"""Build LDAP messages, TLS records and TCP conversations for tests.

The BER encoder here is written from X.690 independently of
auth_capture_explainer.ber, so the decoder is not tested against itself. TCP
conversations track sequence numbers like a real stack, and can split,
reorder, repeat or drop segments.
"""

import struct
from dataclasses import replace

import dpkt

import pcapbuild as pb
from auth_capture_explainer import layers

# --- BER ------------------------------------------------------------------------------

UNIVERSAL, APPLICATION, CONTEXT = 0x00, 0x40, 0x80
CONSTRUCTED = 0x20


def length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(identifier, content):
    return bytes([identifier]) + length(len(content)) + content


def integer(n, identifier=0x02):
    size = (n if n >= 0 else -n - 1).bit_length() // 8 + 1  # minimal two's complement
    return tlv(identifier, n.to_bytes(size, "big", signed=True))


def enum(n):
    return integer(n, 0x0A)


def octets(value, identifier=0x04):
    return tlv(identifier, value.encode() if isinstance(value, str) else value)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def seq(*parts, identifier=0x30):
    return tlv(identifier, b"".join(parts))


def app(tag, *parts, constructed=True):
    return tlv(APPLICATION | (CONSTRUCTED if constructed else 0) | tag, b"".join(parts))


def ctx(tag, content, constructed=False):
    return tlv(CONTEXT | (CONSTRUCTED if constructed else 0) | tag, content)


def message(ident, op, controls=None):
    return seq(integer(ident), op, *([ctx(0, controls, constructed=True)] if controls else []))


# --- LDAP operations ---------------------------------------------------------------------

def bind_request(ident, dn, password=b"", version=3):
    password = password.encode() if isinstance(password, str) else password
    return message(ident, app(0, integer(version), octets(dn), ctx(0, password)))


def sasl_bind(ident, dn, mechanism, credentials=None):
    sasl = octets(mechanism) + (octets(credentials) if credentials is not None else b"")
    return message(ident, app(0, integer(3), octets(dn), ctx(3, sasl, constructed=True)))


def result(code, matched="", diagnostic="", referrals=None):
    out = enum(code) + octets(matched) + octets(diagnostic)
    if referrals:
        out += ctx(3, b"".join(octets(r) for r in referrals), constructed=True)
    return out


def bind_response(ident, code, matched="", diagnostic="", referrals=None):
    return message(ident, app(1, result(code, matched, diagnostic, referrals)))


def search_request(ident, base, flt, scope=2, attributes=()):
    return message(ident, app(3, octets(base), enum(scope), enum(0), integer(0), integer(0), boolean(False),
                              flt, seq(*(octets(a) for a in attributes))))


def search_entry(ident, dn, attributes=()):
    """attributes: (name, [values])."""
    attrs = seq(*(seq(octets(name), seq(*(octets(v) for v in values), identifier=0x31))
                  for name, values in attributes))
    return message(ident, app(4, octets(dn), attrs))


def search_done(ident, code=0, diagnostic=""):
    return message(ident, app(5, result(code, "", diagnostic)))


def search_reference(ident, *urls):
    return message(ident, app(19, *(octets(u) for u in urls)))


def extended_request(ident, oid, value=None):
    return message(ident, app(23, ctx(0, oid.encode()), *([ctx(1, value)] if value is not None else [])))


def extended_response(ident, code, oid=None, diagnostic=""):
    return message(ident, app(24, result(code, "", diagnostic), *([ctx(10, oid.encode())] if oid else [])))


def unbind(ident):
    return message(ident, tlv(APPLICATION | 2, b""))


def abandon(ident, target):
    return message(ident, integer(target, APPLICATION | 16))


def delete_request(ident, dn):
    return message(ident, octets(dn, APPLICATION | 10))


def modify_response(ident, code, diagnostic=""):
    return message(ident, app(7, result(code, "", diagnostic)))


STARTTLS = "1.3.6.1.4.1.1466.20037"


# --- search filters -------------------------------------------------------------------

def f_eq(attr, value):
    return ctx(3, octets(attr) + octets(value), constructed=True)


def f_and(*fs):
    return ctx(0, b"".join(fs), constructed=True)


def f_or(*fs):
    return ctx(1, b"".join(fs), constructed=True)


def f_not(f):
    return ctx(2, f, constructed=True)


def f_present(attr):
    return ctx(7, attr.encode())


def f_substr(attr, initial=None, anys=(), final=None):
    parts = (ctx(0, initial.encode()) if initial else b"") + b"".join(ctx(1, a.encode()) for a in anys) \
        + (ctx(2, final.encode()) if final else b"")
    return ctx(4, octets(attr) + seq(parts), constructed=True)


def f_cmp(tag, attr, value):
    return ctx(tag, octets(attr) + octets(value), constructed=True)


def f_ext(attr, rule, value, dn=False):
    return ctx(9, (ctx(1, rule.encode()) if rule else b"") + ctx(2, attr.encode()) + ctx(3, value.encode())
               + (ctx(4, b"\xff") if dn else b""), constructed=True)


# --- TLS records ----------------------------------------------------------------------------

def tls_record(ctype, body, version=0x0303):
    return struct.pack("!BHH", ctype, version, len(body)) + body


def _ext(ext, value):
    return struct.pack("!HH", ext, len(value)) + value


def client_hello(sni=None, versions=(0x0304, 0x0303), legacy=0x0303):
    exts = b""
    if sni:
        name = sni.encode()
        exts += _ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    if versions:
        listed = b"".join(struct.pack("!H", v) for v in versions)
        exts += _ext(43, bytes([len(listed)]) + listed)
    body = struct.pack("!H", legacy) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    return tls_record(22, bytes([1]) + len(body).to_bytes(3, "big") + body, 0x0301)


def server_hello(version=0x0303, tls13=False):
    exts = _ext(43, struct.pack("!H", 0x0304)) if tls13 else b""
    body = struct.pack("!H", 0x0303 if tls13 else version) + b"\x22" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
    body += struct.pack("!H", len(exts)) + exts
    return tls_record(22, bytes([2]) + len(body).to_bytes(3, "big") + body)


def alert(level, description):
    return tls_record(21, bytes([level, description]))


def change_cipher_spec():
    return tls_record(20, b"\x01")


def app_data(n=40):
    return tls_record(23, b"\xee" * n)


# --- TCP conversations ------------------------------------------------------------------------

class Conversation:
    """A TCP connection between a client and an LDAP server, producing layers.Packets."""

    def __init__(self, client=pb.CLIENT, cport=40000, server=pb.SERVER, sport=389, isn=(1000, 5000)):
        self.client, self.cport, self.server, self.sport = client, cport, server, sport
        self.seq = {True: isn[0], False: isn[1]}  # True: the client's direction
        self.packets = []
        self.ips = []  # (ts, raw IP bytes), for writing the conversation out as a capture file

    def _packet(self, ts, from_client, payload=b"", flags=dpkt.tcp.TH_ACK, seq=None):
        src, sport, dst, dport = ((self.client, self.cport, self.server, self.sport) if from_client
                                  else (self.server, self.sport, self.client, self.cport))
        seq = self.seq[from_client] if seq is None else seq
        ip = pb.tcp(src, dst, sport, dport, payload, seq=seq % (1 << 32), ack=self.seq[not from_client] % (1 << 32),
                    flags=flags)
        p = layers.decode(0, ts, layers.LINKTYPE_RAW, ip)
        assert isinstance(p, layers.Packet), p
        self.packets.append(p)
        self.ips.append((ts, ip))
        return p

    def handshake(self, ts):
        self._packet(ts, True, flags=dpkt.tcp.TH_SYN, seq=self.seq[True])
        self.seq[True] += 1
        self._packet(ts + 0.0001, False, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=self.seq[False])
        self.seq[False] += 1
        self._packet(ts + 0.0002, True)
        return self

    def send(self, ts, from_client, data, split=None):
        """Send data, in segments of at most split bytes. Returns the segment packets."""
        sizes = [len(data)] if not split else [min(split, len(data) - i) for i in range(0, len(data), split)]
        sent, pos = [], 0
        for i, n in enumerate(sizes):
            sent.append(self._packet(ts + i * 0.0001, from_client, data[pos:pos + n],
                                     flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH))
            self.seq[from_client] += n
            pos += n
        return sent

    def client_says(self, ts, data, split=None):
        return self.send(ts, True, data, split)

    def server_says(self, ts, data, split=None):
        return self.send(ts, False, data, split)

    def skip(self, from_client, n):
        """Advance the sequence number as if n bytes were sent but not captured."""
        self.seq[from_client] += n

    def close(self, ts, from_client=True, reset=False):
        flags = dpkt.tcp.TH_RST if reset else dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK
        self._packet(ts, from_client, flags=flags)
        if not reset:
            self.seq[from_client] += 1
            self._packet(ts + 0.0001, not from_client, flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
        return self

    def numbered(self, start=1):
        """The packets with frame numbers in order, as a capture would number them."""
        return [replace(p, frame=start + i) for i, p in enumerate(self.packets)]
