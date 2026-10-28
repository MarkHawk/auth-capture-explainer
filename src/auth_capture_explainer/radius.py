"""Find RADIUS messages in a capture and decode them strictly.

RADIUS is recognised by port: 1812 and 1813, the legacy 1645 and 1646 that
older NASes still use, and any port the user adds. A UDP payload on one of
those ports is decoded as RADIUS; whether it is a request or a reply comes
from its code, not from which side of the port pair it is on (some NASes
send from source port 1812 too).

Decoding never raises. A payload that cannot be RADIUS is a Malformed with
the reason; a message that is cut short or has a broken attribute keeps
whatever decoded cleanly and lists the problem, so a capture with a short
snapshot length still shows who asked whom and with which ID.
"""

import struct
from dataclasses import dataclass, field

from auth_capture_explainer.radius_dict import (
    CODES,
    REQUESTS,
    VENDOR_SPECIFIC,
    Attribute,
    code_name,
)

HEADER = 20
MAX_LENGTH = 4096  # RFC 2865 section 3; RFC 7930 larger packets are not in use on these ports
AUTH, ACCT = "authentication", "accounting"


@dataclass(frozen=True)
class Ports:
    """Which UDP ports carry RADIUS, and how to describe each."""

    auth: frozenset = frozenset({1812})
    acct: frozenset = frozenset({1813})
    legacy_auth: frozenset = frozenset({1645})
    legacy_acct: frozenset = frozenset({1646})
    extra: frozenset = frozenset()  # given by the user; their role comes from the messages seen

    @property
    def all(self):
        return self.auth | self.acct | self.legacy_auth | self.legacy_acct | self.extra

    def label(self, port):
        if port in self.legacy_auth:
            return f"{port} (legacy {AUTH} port)"
        if port in self.legacy_acct:
            return f"{port} (legacy {ACCT} port)"
        if port in self.extra:
            return f"{port} (non-standard port)"
        return str(port)

    def is_legacy(self, port):
        return port in self.legacy_auth or port in self.legacy_acct

    def with_extra(self, ports):
        return Ports(self.auth, self.acct, self.legacy_auth, self.legacy_acct, frozenset(self.extra | set(ports)))


DEFAULT_PORTS = Ports()


@dataclass
class Message:
    packet: object  # the layers.Packet it came in
    code: int
    id: int
    length: int  # from the header
    authenticator: bytes
    attributes: list = field(default_factory=list)
    raw: bytes = b""  # the RADIUS bytes as captured, up to the header's length
    problems: list = field(default_factory=list)  # sentences; empty for a clean message

    @property
    def name(self):
        return code_name(self.code)

    @property
    def is_request(self):
        return self.code in REQUESTS

    @property
    def complete(self):
        return len(self.raw) == self.length and not self.problems

    def get(self, attr_type):
        """The first top-level attribute of this type, or None."""
        for a in self.attributes:
            if a.type == attr_type and a.vendor is None:
                return a
        return None

    def all(self, attr_type):
        return [a for a in self.attributes if a.type == attr_type and a.vendor is None]

    def has(self, attr_type):
        return self.get(attr_type) is not None

    def position(self, attr_type):
        """Where the first top-level attribute of this type comes (0 for first), or None if absent.
        Read from the bytes, so a Vendor-Specific attribute counts once however many it holds."""
        i, n = HEADER, 0
        while i + 2 <= len(self.raw):
            if self.raw[i] == attr_type:
                return n
            if self.raw[i + 1] < 2:
                return None
            i += self.raw[i + 1]
            n += 1
        return None


@dataclass(frozen=True)
class Malformed:
    packet: object
    reason: str


def find(packets, ports=DEFAULT_PORTS):
    """(messages, malformed) for every UDP packet to or from a RADIUS port, in capture order."""
    messages, malformed = [], []
    wanted = ports.all
    for p in packets:
        if p.proto != "udp" or not (p.sport in wanted or p.dport in wanted):
            continue
        result = decode(p)
        (messages if isinstance(result, Message) else malformed).append(result)
    return messages, malformed


def decode(packet):
    """A Message, or Malformed when the payload cannot be RADIUS."""
    data = packet.payload
    if len(data) < 4:
        return Malformed(packet, f"{len(data)} bytes, too short for a RADIUS header")
    code, ident, length = struct.unpack_from("!BBH", data)
    if code not in CODES:
        return Malformed(packet, f"code {code} is not a RADIUS packet type")
    if not HEADER <= length <= MAX_LENGTH:
        return Malformed(packet, f"length field {length} is outside the allowed {HEADER} to {MAX_LENGTH}")
    msg = Message(packet, code, ident, length, data[4:HEADER], raw=data[:length])
    if len(data) < length:
        cause = "the capture's snapshot length cut it short" if packet.truncated else "the datagram is shorter"
        msg.problems.append(f"only {len(data)} of {length} bytes were captured: {cause}")
    if len(data) < HEADER:
        return msg
    msg.attributes, problem = _attributes(data[HEADER:length])
    if problem and not (len(data) < length):  # a cut-off tail is already explained above
        msg.problems.append(problem)
    return msg


def _attributes(body):
    """(attributes, problem). Stops at the first attribute that does not fit."""
    attrs, i = [], 0
    while i < len(body):
        if i + 2 > len(body):
            return attrs, "an attribute header runs past the end of the message"
        attr_type, attr_len = body[i], body[i + 1]
        if attr_len < 2:
            return attrs, f"attribute {attr_type} has an invalid length {attr_len}"
        if i + attr_len > len(body):
            return attrs, f"attribute {attr_type} runs past the end of the message"
        value = body[i + 2:i + attr_len]
        if attr_type == VENDOR_SPECIFIC and len(value) >= 4:
            attrs += _vendor_attributes(value)
        else:
            attrs.append(Attribute(attr_type, value))
        i += attr_len
    return attrs, None


def _vendor_attributes(value):
    """Sub-attributes of a Vendor-Specific attribute in the RFC 2865 suggested format. A vendor
    that does not follow it is kept as one attribute, shown by length."""
    (vendor,) = struct.unpack_from("!I", value)
    subs, i, body = [], 0, value[4:]
    while i < len(body):
        if i + 2 > len(body) or body[i + 1] < 2 or i + body[i + 1] > len(body):
            return [Attribute(VENDOR_SPECIFIC, value, vendor, None)]
        subs.append(Attribute(VENDOR_SPECIFIC, body[i + 2:i + body[i + 1]], vendor, body[i]))
        i += body[i + 1]
    return subs or [Attribute(VENDOR_SPECIFIC, value, vendor, None)]


def encode(code, ident, authenticator, attributes):
    """RADIUS bytes for a message. attributes: (type, value) pairs or Attributes (vendor ones re-wrapped)."""
    body = b""
    for a in attributes:
        if isinstance(a, Attribute) and a.vendor is not None and a.vendor_type is not None:
            sub = bytes([a.vendor_type, len(a.value) + 2]) + a.value
            value = struct.pack("!I", a.vendor) + sub
            body += bytes([VENDOR_SPECIFIC, len(value) + 2]) + value
            continue
        attr_type, value = (a.type, a.value) if isinstance(a, Attribute) else a  # a whole VSA keeps its bytes
        if len(value) > 253:
            raise ValueError(f"attribute {attr_type} value is {len(value)} bytes; the limit is 253")
        body += bytes([attr_type, len(value) + 2]) + value
    length = HEADER + len(body)
    if length > MAX_LENGTH:
        raise ValueError(f"message is {length} bytes; the limit is {MAX_LENGTH}")
    if len(authenticator) != 16:
        raise ValueError("the authenticator must be 16 bytes")
    return struct.pack("!BBH", code, ident, length) + authenticator + body
