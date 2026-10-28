"""Read a .pcap or .pcapng file into Packets, safely.

A capture handed over in a ticket is untrusted input: it may be cut short
(copied while tcpdump was still writing), damaged, enormous, or crafted. So
the file formats are read here with every length checked before it is used,
rather than by a general-purpose reader:

- the file size and the number of packets are capped (Limits);
- a record or block that claims more bytes than a packet can hold, or more
  than the file has left, ends the read with a note, keeping everything
  before it;
- a packet that cannot be decoded is counted and skipped, never fatal.

Only a file that is not a capture at all raises CaptureError.

pcapng is read in full: every interface keeps its own link type and
timestamp resolution, new sections reset them, and the direction flag on
each packet is kept, because which way a packet went on the capturing host
helps say where a capture was taken.
"""

import io
import os
import pathlib
import struct
from collections import Counter
from dataclasses import dataclass, field

from auth_capture_explainer import layers

MiB = 1024 * 1024
MAX_RECORD = 1 * MiB  # one packet; tcpdump's largest snapshot length is 256 KiB
MAX_BLOCK = 16 * MiB  # one pcapng block, which may also carry long options or embedded keys

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
PCAPNG_BOM = 0x1A2B3C4D

# pcapng block types
BT_IDB, BT_PB, BT_SPB, BT_EPB, BT_DSB = 1, 2, 3, 6, 0x0A
SHB_TYPE = 0x0A0D0D0A
OPT_END, OPT_IF_TSRESOL, OPT_IF_TSOFFSET, OPT_EPB_FLAGS = 0, 9, 14, 2
EPB_DIRECTION = {1: "in", 2: "out"}

# Formats people send by mistake, so the error can say what to do instead.
OTHER_FORMATS = (
    (b"\x1f\x8b", "a gzip-compressed file; decompress it first (gunzip)"),
    (b"PK\x03\x04", "a zip archive; extract the capture from it first"),
    (b"\xa1\xb2\xcd\x34", "a modified (Kuznetzov) pcap; re-save it as pcap or pcapng with Wireshark or editcap"),
    (b"\x34\xcd\xb2\xa1", "a modified (Kuznetzov) pcap; re-save it as pcap or pcapng with Wireshark or editcap"),
    (b"snoop\x00\x00\x00", "a Solaris snoop capture; re-save it as pcapng with Wireshark or editcap"),
    (b"GMBU", "a Microsoft Network Monitor capture; re-save it as pcapng with Wireshark"),
)


class CaptureError(ValueError):
    """The file cannot be read as a capture at all."""


@dataclass
class Limits:
    max_bytes: int = 256 * MiB
    max_packets: int = 1_000_000


@dataclass
class Capture:
    name: str  # the file's name only: reports never show the folder it came from
    format: str  # "pcap" or "pcapng"
    size: int = 0
    frames: int = 0  # packet records read from the file
    packets: list = field(default_factory=list)  # layers.Packet, in file order
    linktypes: list = field(default_factory=list)  # in the order first seen
    ignored: Counter = field(default_factory=Counter)  # reason -> count: frames this tool has no use for
    malformed: Counter = field(default_factory=Counter)  # reason -> count: damaged or cut-short frames
    first_malformed: dict = field(default_factory=dict)  # reason -> first frame number
    notes: list = field(default_factory=list)  # file-level problems and remarks, as sentences
    stopped_early: bool = False
    first_ts: float = None  # of the decoded packets, kept when the packets themselves are let go
    last_ts: float = None

    def skip(self, frame_no, skip):
        if skip.malformed:
            self.malformed[skip.reason] += 1
            self.first_malformed.setdefault(skip.reason, frame_no)
        else:
            self.ignored[skip.reason] += 1


def read_capture(path, limits=None):
    """Read the file at path. Raises CaptureError if it is not a capture or is over the size limit."""
    limits = limits or Limits()
    path = pathlib.Path(path)
    try:
        f = open(path, "rb")
    except OSError as e:
        raise CaptureError(f"cannot open {path.name}: {e.strerror or e}") from e
    with f:
        size = os.fstat(f.fileno()).st_size
        _check_size(path.name, size, limits)
        return _from_file(f, path.name, size, limits)


STREAM_CHUNK = 64 * 1024
INTERRUPTED = ("Reading was interrupted (Ctrl-C) {where}; everything read up to then is analysed, and anything "
               "after it is missing.")


def read_stream(stream, name="standard input", limits=None):
    """Read a capture from a binary stream, such as tcpdump -w - piped in, a chunk at a time. The size limit
    applies as it reads, so an endless stream stops at the limit rather than filling memory.

    Ctrl-C while reading (as when stopping 'tcpdump -w - | auth-capture-explainer -') ends the reading, not the
    program: what arrived is analysed, and the report says the capture stopped early. So does a stream that
    ends part-way through a packet."""
    limits = limits or Limits()
    parts, size, interrupted = [], 0, False
    try:
        while size <= limits.max_bytes:
            chunk = stream.read(min(STREAM_CHUNK, limits.max_bytes + 1 - size))
            if not chunk:
                break
            parts.append(chunk)
            size += len(chunk)
    except KeyboardInterrupt:
        interrupted = True
    _check_size(name, size, limits)
    cap = _from_file(io.BytesIO(b"".join(parts)), name, size, limits)
    if interrupted:
        cap.notes.append(INTERRUPTED.format(where=f"after {size} bytes of {name}"))
    if interrupted:
        cap.stopped_early = True
    return cap


def frames(path):
    """(ts, linktype, frame bytes) for every packet record in a pcap or pcapng file, without decoding them,
    for tools that rewrite captures. Notes about damage are dropped; a file that is not a capture raises
    CaptureError."""
    path = pathlib.Path(path)
    with open(path, "rb") as f:
        head = f.read(4)
        if head in PCAP_MAGIC:
            records = _pcap_records(f, head)
        elif head == PCAPNG_SHB:
            records = _pcapng_records(f)
        else:
            raise CaptureError(f"{path.name} is not a pcap or pcapng capture")
        for item in records:
            if not isinstance(item, str):
                ts, linktype, data, _direction, _cut = item
                yield ts, linktype, data


def _check_size(name, size, limits):
    if size > limits.max_bytes:
        raise CaptureError(f"{name} is over the {limits.max_bytes / MiB:.0f} MiB limit"
                           + (f" ({size / MiB:.0f} MiB)" if size > limits.max_bytes + 1 else ""))


def _from_file(f, name, size, limits):
    head = f.read(4)
    if len(head) < 4:
        raise CaptureError(f"{name} is empty or too short to be a capture")
    if head in PCAP_MAGIC:
        cap, records = Capture(name, "pcap", size), _pcap_records(f, head)
    elif head == PCAPNG_SHB:
        cap, records = Capture(name, "pcapng", size), _pcapng_records(f)
    else:
        raise CaptureError(f"{name} is not a pcap or pcapng capture: {_what_is_it(head + f.read(4))}")
    _read(cap, records, limits)
    if CUT_SHORT in cap.notes:
        cap.stopped_early = True
    return cap


def _what_is_it(head):
    for magic, what in OTHER_FORMATS:
        if head.startswith(magic):
            return f"it looks like {what}"
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head):
        return "it looks like text (perhaps a decoded export); save the capture itself as .pcap or .pcapng"
    return "the file type is not recognised; save it as .pcap or .pcapng (Wireshark: File, Save As)"


def _read(cap, records, limits):
    """Decode every record into cap. Records are (ts, linktype, data, direction, cut) or a note string.
    Ctrl-C part-way through a big file stops the reading, not the program, as for a stream."""
    try:
        _read_records(cap, records, limits)
    except KeyboardInterrupt:
        cap.notes.append(INTERRUPTED.format(where=f"after {cap.frames} packets"))
        cap.stopped_early = True


def _read_records(cap, records, limits):
    for item in records:
        if isinstance(item, str):
            cap.notes.append(item)
            continue
        if cap.frames >= limits.max_packets:
            cap.notes.append(f"Stopped after {limits.max_packets} packets (the limit); the rest of the file "
                             "was not read.")
            cap.stopped_early = True
            return
        cap.frames += 1
        ts, linktype, data, direction, cut = item
        if linktype not in cap.linktypes:
            cap.linktypes.append(linktype)
        result = layers.decode(cap.frames, ts, linktype, data, direction, cut)
        if isinstance(result, layers.Skip):
            cap.skip(cap.frames, result)
        else:
            cap.packets.append(result)
            cap.first_ts = ts if cap.first_ts is None else min(cap.first_ts, ts)
            cap.last_ts = ts if cap.last_ts is None else max(cap.last_ts, ts)


CUT_SHORT = ("The file ends part-way through a packet: the capture was cut short (copied while still being "
             "written, or truncated). Everything before that point was read.")


def _damaged(what):
    return f"The file is damaged at {what}, so reading stopped there. Everything before it was read."


def _pcap_records(f, magic):
    endian, per_second = PCAP_MAGIC[magic]
    header = f.read(20)
    if len(header) < 20:
        yield CUT_SHORT
        return
    major, _minor, _zone, _sigfigs, _snaplen, network = struct.unpack(endian + "HHiIII", header)
    if major != 2:
        yield f"The pcap header says format version {major}, not 2; reading it as version 2 anyway."
    linktype = network & 0x03FFFFFF  # the top bits can carry FCS information
    record = 0
    while True:
        rec = f.read(16)
        if not rec:
            return
        if len(rec) < 16:
            yield CUT_SHORT
            return
        record += 1
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
        if incl > MAX_RECORD:
            yield _damaged(f"packet record {record}, which claims {incl} bytes")
            return
        data = f.read(incl)
        if len(data) < incl:
            yield CUT_SHORT
            return
        yield sec + frac / per_second, linktype, data, None, orig > incl


@dataclass
class _Interface:
    linktype: int
    divisor: int = 1_000_000
    offset: int = 0


def _pcapng_records(f):
    endian = None
    interfaces = []
    last_ts = 0.0
    first = True  # read_capture has already consumed the first block's type
    while True:
        head = PCAPNG_SHB + f.read(4) if first else f.read(8)
        if not head:
            return
        if len(head) < 8:
            yield CUT_SHORT
            return
        if head[:4] == PCAPNG_SHB:
            bom = f.read(4)
            if len(bom) < 4:
                yield CUT_SHORT
                return
            if struct.unpack("<I", bom)[0] == PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == PCAPNG_BOM:
                endian = ">"
            else:
                if first:
                    raise CaptureError("the pcapng section header has an invalid byte-order mark")
                yield _damaged("a section header with an invalid byte-order mark")
                return
            (length,) = struct.unpack(endian + "I", head[4:8])
            prefix, btype = bom, SHB_TYPE
        else:
            btype, length = struct.unpack(endian + "II", head)
            prefix = b""
        first = False
        if length < 12 + len(prefix) or length % 4 or length > MAX_BLOCK:
            yield _damaged(f"a block that claims {length} bytes")
            return
        rest = f.read(length - 8 - len(prefix))
        if len(rest) < length - 8 - len(prefix):
            yield CUT_SHORT
            return
        block = prefix + rest
        if struct.unpack(endian + "I", block[-4:])[0] != length:
            yield _damaged("a block whose two length fields disagree")
            return
        body = block[:-4]

        if btype == SHB_TYPE:
            if len(body) < 12:
                yield _damaged("a section header that is too short")
                return
            (major,) = struct.unpack_from(endian + "H", body, 4)
            if major != 1:
                yield f"A pcapng section says format version {major}, not 1; reading it anyway."
            interfaces = []  # interfaces are numbered per section
        elif btype == BT_IDB:
            if len(body) < 8:
                yield _damaged("an interface description that is too short")
                return
            linktype, _reserved, _snaplen = struct.unpack_from(endian + "HHI", body)
            iface = _Interface(linktype)
            for code, value in _options(body[8:], endian):
                if code == OPT_IF_TSRESOL and len(value) >= 1:
                    v = value[0]
                    iface.divisor = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                elif code == OPT_IF_TSOFFSET and len(value) >= 8:
                    (iface.offset,) = struct.unpack(endian + "q", value[:8])
            interfaces.append(iface)
        elif btype in (BT_EPB, BT_PB):
            if btype == BT_EPB:
                fixed = 20
                if len(body) < fixed:
                    yield _damaged("a packet block that is too short")
                    return
                if_id, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body)
            else:  # the obsolete Packet Block: a 16-bit interface id and a drops count
                fixed = 20
                if len(body) < fixed:
                    yield _damaged("a packet block that is too short")
                    return
                if_id, _drops, hi, lo, caplen, origlen = struct.unpack_from(endian + "HHIIII", body)
            if caplen > len(body) - fixed or caplen > MAX_RECORD:
                yield _damaged(f"a packet block that claims {caplen} bytes of packet data")
                return
            if if_id >= len(interfaces):
                yield _damaged(f"a packet for interface {if_id}, which the file never described")
                return
            iface = interfaces[if_id]
            data = body[fixed:fixed + caplen]
            direction = None
            for code, value in _options(body[fixed + _pad4(caplen):], endian):
                if code == OPT_EPB_FLAGS and len(value) >= 4:
                    direction = EPB_DIRECTION.get(struct.unpack(endian + "I", value[:4])[0] & 0x3)
            last_ts = ((hi << 32) | lo) / iface.divisor + iface.offset
            yield last_ts, iface.linktype, data, direction, origlen > caplen
        elif btype == BT_SPB:
            if len(body) < 4 or not interfaces:
                yield _damaged("a simple packet block with no interface described")
                return
            (origlen,) = struct.unpack_from(endian + "I", body)
            data = body[4:4 + min(origlen, MAX_RECORD)]
            # A simple packet block has no timestamp: give it the previous packet's.
            yield last_ts, interfaces[0].linktype, data, None, origlen > len(data)
        elif btype == BT_DSB:
            yield ("The capture contains a decryption secrets block (for example TLS session keys). "
                   "auth-capture-explainer does not use it and never decrypts traffic.")
        # Other blocks (name resolution, statistics, custom) carry nothing this tool needs.


def _pad4(n):
    return (n + 3) & ~3


def _options(buf, endian):
    """(code, value) pairs from a pcapng option list, stopping at the end marker or at damage."""
    i = 0
    while i + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, i)
        if code == OPT_END:
            return
        value = buf[i + 4:i + 4 + length]
        if len(value) < length:
            return
        yield code, value
        i += 4 + _pad4(length)
