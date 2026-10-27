"""Put TCP segments back in order, one byte stream per direction.

Segments are placed by sequence number, not by capture order, so
out-of-order delivery and retransmissions sort themselves out: where two
segments cover the same bytes, the first one captured is kept. Sequence
numbers wrap at 2**32; offsets are measured from the start of each
direction (the SYN when it was captured, otherwise the lowest sequence
number seen, as when the capture began part-way through a connection).

Bytes the capture never saw (a dropped packet, a snapshot length that cut
a segment short) leave a gap. Nothing is guessed across a gap: the stream
is split into Chunks of contiguous bytes, and the gap is reported, so a
reader of the stream knows a message may be missing there.

Each byte keeps the time and frame of the segment that delivered it, so a
message can be timed by when its last byte arrived. A direction is capped
at MAX_STREAM bytes; beyond that it is cut off with a note.
"""

import bisect
from dataclasses import dataclass, field

SYN, FIN, RST = 0x02, 0x01, 0x04
MAX_STREAM = 16 * 1024 * 1024
MOD = 1 << 32


@dataclass
class Chunk:
    """Contiguous bytes of one direction, from offset start."""

    start: int
    data: bytes
    marks: list  # (offset, ts, frame) where each delivering segment's new bytes begin, in order

    def __post_init__(self):
        self._offsets = [m[0] for m in self.marks]

    def when(self, offset):
        """(ts, frame) of the segment that delivered the byte at this stream offset."""
        i = bisect.bisect_right(self._offsets, offset) - 1
        _, ts, frame = self.marks[max(i, 0)]
        return ts, frame

    @property
    def end(self):
        return self.start + len(self.data)


@dataclass
class Direction:
    src: str
    sport: int
    chunks: list = field(default_factory=list)
    gaps: int = 0  # holes between chunks
    missing_bytes: int = 0
    capped: bool = False
    syn: bool = False
    fin: bool = False
    rst: bool = False
    first_ts: float = None
    last_ts: float = None

    @property
    def bytes(self):
        return sum(len(c.data) for c in self.chunks)


@dataclass
class Stream:
    """One TCP connection: client to server, as far as the capture can tell."""

    client: str
    client_port: int
    server: str
    server_port: int
    to_server: Direction
    to_client: Direction
    syn_seen: bool  # the connection's start is in the capture, so client and server are certain
    first_frame: int

    @property
    def first_ts(self):
        return min(t for t in (self.to_server.first_ts, self.to_client.first_ts) if t is not None)

    @property
    def last_ts(self):
        return max(t for t in (self.to_server.last_ts, self.to_client.last_ts) if t is not None)

    @property
    def closed_by(self):
        """"client", "server", "both" or None: who sent FIN or RST first is not tracked, only who did."""
        sides = [name for name, d in (("client", self.to_server), ("server", self.to_client)) if d.fin or d.rst]
        return "both" if len(sides) == 2 else (sides[0] if sides else None)

    @property
    def reset_by(self):
        sides = [name for name, d in (("client", self.to_server), ("server", self.to_client)) if d.rst]
        return "both" if len(sides) == 2 else (sides[0] if sides else None)


def streams(packets, server_ports):
    """Reassemble every TCP connection with a server_ports port on either side, in order of first packet."""
    groups = {}
    for p in packets:
        if p.proto != "tcp" or not (p.sport in server_ports or p.dport in server_ports):
            continue
        key = frozenset(((p.src, p.sport), (p.dst, p.dport)))
        groups.setdefault(key, []).append(p)
    return [_assemble(segments, server_ports) for segments in groups.values()]


def _assemble(segments, server_ports):
    segments = sorted(segments, key=lambda p: (p.ts, p.frame))
    a, b = (segments[0].src, segments[0].sport), (segments[0].dst, segments[0].dport)
    client, server = _roles(segments, a, b, server_ports)
    syn_seen = any(p.tcp_flags & SYN for p in segments)
    up = _direction([p for p in segments if (p.src, p.sport) == client], *client)
    down = _direction([p for p in segments if (p.src, p.sport) == server], *server)
    return Stream(client[0], client[1], server[0], server[1], up, down, syn_seen,
                  min(p.frame for p in segments))


def _roles(segments, a, b, server_ports):
    """(client, server). The side that sent a bare SYN is the client; failing that, the LDAP port is the
    server's; failing that (both are), the lower port."""
    for p in segments:
        if p.tcp_flags & SYN and not p.tcp_flags & 0x10:  # SYN without ACK
            src = (p.src, p.sport)
            return (src, b if src == a else a)
    a_server, b_server = a[1] in server_ports, b[1] in server_ports
    if a_server != b_server:
        return (b, a) if a_server else (a, b)
    return (b, a) if a[1] < b[1] else (a, b)


def _direction(segments, src, sport):
    d = Direction(src, sport)
    if not segments:
        return d
    d.first_ts, d.last_ts = segments[0].ts, segments[-1].ts
    d.syn = any(p.tcp_flags & SYN for p in segments)
    d.fin = any(p.tcp_flags & FIN for p in segments)
    d.rst = any(p.tcp_flags & RST for p in segments)
    syn = next((p for p in segments if p.tcp_flags & SYN), None)
    base = (syn.tcp_seq + 1) % MOD if syn else _lowest(segments)
    pieces = []  # (offset, payload, ts, frame), only segments carrying data
    for p in segments:
        if not p.payload:
            continue
        offset = _relative(p.tcp_seq, base)
        if offset < 0:  # before the start we chose: a retransmission of something earlier, or noise
            continue
        pieces.append((offset, p.payload, p.ts, p.frame))
    pieces.sort(key=lambda x: (x[0], x[2]))
    runs, expected = [], None  # each run: [start, [byte parts], [marks]]
    for offset, payload, ts, frame in pieces:
        end = offset + len(payload)
        if offset >= MAX_STREAM:
            d.capped = True
            break
        if end > MAX_STREAM:
            payload = payload[:MAX_STREAM - offset]
            end = MAX_STREAM
            d.capped = True
        if not runs or offset > expected:
            if runs:
                d.gaps += 1
                d.missing_bytes += offset - expected
            runs.append([offset, [], []])
            expected = offset
        if end <= expected:  # entirely bytes already held: a retransmission
            continue
        runs[-1][1].append(payload[expected - offset:])
        runs[-1][2].append((expected, ts, frame))
        expected = end
    d.chunks = [Chunk(start, b"".join(parts), marks) for start, parts, marks in runs]
    return d


def _relative(seq, base):
    """seq minus base in sequence space, as a signed offset (wrap-around safe)."""
    diff = (seq - base) % MOD
    return diff - MOD if diff >= MOD // 2 else diff


def _lowest(segments):
    """The earliest sequence number among the data-carrying segments, allowing for wrap-around."""
    seqs = [p.tcp_seq for p in segments if p.payload] or [segments[0].tcp_seq]
    first = seqs[0]
    return min(seqs, key=lambda s: _relative(s, first))
