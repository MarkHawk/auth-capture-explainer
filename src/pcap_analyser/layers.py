"""Turn one captured frame into a Packet: addresses, ports and payload.

The link-layer headers (Ethernet with VLAN tags, Linux cooked captures,
loopback, raw IP) are a few fixed fields, so they are read here directly.
IP onwards goes to dpkt, but its results are not taken on trust: dpkt keeps
whatever bytes are there, so lengths are checked against the headers' own
length fields, and IP fragments are refused rather than read as if they
were whole datagrams.

dpkt decodes upper layers eagerly and, on damaged input, can fail with
almost any exception (fuzzing found AttributeError inside its IPsec
handling), so each call into it catches Exception and reports the frame as
malformed. Only the dpkt call is wrapped: a bug in this module still
surfaces in the tests.

A frame that is not wanted (ARP, another protocol) is a Skip with
malformed=False. A frame that is damaged or cut short is a Skip with
malformed=True, so the report can say how many were dropped and why. Nothing
in here raises on bad input.
"""

import ipaddress
import struct
from dataclasses import dataclass

import dpkt

# Link types (https://www.tcpdump.org/linktypes.html).
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALIASES = (12, 14)  # DLT_RAW on some BSDs, before the LINKTYPE values were fixed
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    LINKTYPE_NULL: "BSD loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "raw IP",
    12: "raw IP",
    14: "raw IP",
    LINKTYPE_LOOP: "OpenBSD loopback",
    LINKTYPE_LINUX_SLL: "Linux cooked",
    LINKTYPE_IPV4: "raw IPv4",
    LINKTYPE_IPV6: "raw IPv6",
    LINKTYPE_LINUX_SLL2: "Linux cooked v2",
}

ETH_IPV4, ETH_IPV6 = 0x0800, 0x86DD
VLAN_TAGS = (0x8100, 0x88A8, 0x9100)
MAX_VLAN_TAGS = 4
# BSD loopback address families for IPv6 differ by OS: NetBSD/OpenBSD, FreeBSD, macOS.
NULL_IPV4, NULL_IPV6 = (2,), (24, 28, 30)

# Linux cooked capture packet types: which way the packet went on the capturing host.
SLL_DIRECTION = {0: "in", 1: "in", 2: "in", 4: "out"}  # host, broadcast, multicast, outgoing

# ICMP destination unreachable codes that matter for "why no reply".
ICMP4_UNREACH = {0: "network unreachable", 1: "host unreachable", 3: "port unreachable",
                 9: "administratively prohibited", 10: "administratively prohibited",
                 13: "administratively prohibited"}
ICMP6_UNREACH = {0: "no route", 1: "administratively prohibited", 3: "address unreachable",
                 4: "port unreachable", 5: "administratively prohibited", 6: "administratively prohibited"}


@dataclass(frozen=True)
class IcmpError:
    """An ICMP destination unreachable, and the packet it complains about."""

    reason: str  # e.g. "port unreachable", "administratively prohibited"
    proto: str  # of the original packet: "udp" or "tcp"
    src: str  # the original packet's source, so the sender of the request
    dst: str
    sport: int
    dport: int


@dataclass(frozen=True)
class Packet:
    frame: int  # 1-based frame number, as Wireshark shows it
    ts: float  # seconds since the epoch
    direction: str  # "in" or "out" on the capturing host, or None when the capture does not say
    ip_version: int
    src: str
    dst: str
    ttl: int  # IPv4 TTL or IPv6 hop limit
    proto: str  # "udp", "tcp" or "icmp"
    sport: int = 0
    dport: int = 0
    payload: bytes = b""
    truncated: bool = False  # the payload is shorter than its headers say (cut by the snapshot length)
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 0
    icmp: IcmpError = None


@dataclass(frozen=True)
class Skip:
    reason: str
    malformed: bool  # True: damaged or cut short. False: simply not something this tool reads.


def decode(frame_no, ts, linktype, data, direction=None, cut=False):
    """A Packet, or a Skip saying why not. cut: the capture kept fewer bytes than were on the wire."""
    if linktype == LINKTYPE_ETHERNET:
        ethertype, rest = _ethernet(data)
    elif linktype == LINKTYPE_LINUX_SLL:
        ethertype, rest, direction = _sll(data, direction)
    elif linktype == LINKTYPE_LINUX_SLL2:
        ethertype, rest, direction = _sll2(data, direction)
    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        ethertype, rest = _loopback(data, linktype)
    elif linktype in (LINKTYPE_RAW, *LINKTYPE_RAW_ALIASES, LINKTYPE_IPV4, LINKTYPE_IPV6):
        ethertype, rest = _raw(data)
    else:
        return Skip(f"link type {linktype} is not supported", False)
    if isinstance(ethertype, Skip):
        return ethertype
    if ethertype == ETH_IPV4:
        return _ipv4(frame_no, ts, direction, rest, cut)
    if ethertype == ETH_IPV6:
        return _ipv6(frame_no, ts, direction, rest, cut)
    return Skip("not IP", False)


def _ethernet(data):
    if len(data) < 14:
        return Skip("Ethernet header cut short", True), b""
    (ethertype,) = struct.unpack_from("!H", data, 12)
    offset = 14
    for _ in range(MAX_VLAN_TAGS):
        if ethertype not in VLAN_TAGS:
            break
        if len(data) < offset + 4:
            return Skip("VLAN tag cut short", True), b""
        (ethertype,) = struct.unpack_from("!H", data, offset + 2)
        offset += 4
    return ethertype, data[offset:]


def _sll(data, direction):
    if len(data) < 16:
        return Skip("Linux cooked header cut short", True), b"", direction
    pkttype, _, _, ethertype = struct.unpack_from("!HHH8xH", data)
    return ethertype, data[16:], SLL_DIRECTION.get(pkttype, direction)


def _sll2(data, direction):
    if len(data) < 20:
        return Skip("Linux cooked v2 header cut short", True), b"", direction
    ethertype, _, _, _, pkttype = struct.unpack_from("!HHIHB", data)
    return ethertype, data[20:], SLL_DIRECTION.get(pkttype, direction)


def _loopback(data, linktype):
    if len(data) < 4:
        return Skip("loopback header cut short", True), b""
    if linktype == LINKTYPE_LOOP:
        families = {struct.unpack_from("!I", data)[0]}
    else:  # LINKTYPE_NULL is in the capturing host's byte order, which the file does not record
        families = {struct.unpack_from("<I", data)[0], struct.unpack_from(">I", data)[0]}
    if families & set(NULL_IPV4):
        return ETH_IPV4, data[4:]
    if families & set(NULL_IPV6):
        return ETH_IPV6, data[4:]
    return Skip("not IP", False), b""


def _raw(data):
    version = data[0] >> 4 if data else 0
    if version == 4:
        return ETH_IPV4, data
    if version == 6:
        return ETH_IPV6, data
    return Skip("raw packet that is neither IPv4 nor IPv6", True), b""


def _addr(raw):
    return str(ipaddress.ip_address(raw))


def _ipv4(frame_no, ts, direction, data, cut):
    if len(data) < 20 or data[0] >> 4 != 4:
        return Skip("IPv4 header cut short", True)
    ihl = (data[0] & 0x0F) * 4
    (total,) = struct.unpack_from("!H", data, 2)
    if ihl < 20 or total < ihl:
        return Skip("IPv4 header lengths are invalid", True)
    if len(data) < ihl:
        return Skip("IPv4 header cut short", True)
    (flags_offset,) = struct.unpack_from("!H", data, 6)
    if flags_offset & 0x3FFF:  # more-fragments flag or a non-zero offset
        return Skip("IP fragment (fragments are not reassembled)", False)
    cut = cut or len(data) < total
    try:
        ip = dpkt.ip.IP(data[:total])  # no further: short frames are padded to the Ethernet minimum
    except Exception:  # dpkt on damaged input: see the module docstring
        return Skip("IPv4 header could not be read", True)
    common = dict(frame=frame_no, ts=ts, direction=direction, ip_version=4,
                  src=_addr(ip.src), dst=_addr(ip.dst), ttl=ip.ttl)
    return _transport(ip.p, ip.data, data[ihl:total], common, cut)


def _ipv6(frame_no, ts, direction, data, cut):
    if len(data) < 40 or data[0] >> 4 != 6:
        return Skip("IPv6 header cut short", True)
    (plen,) = struct.unpack_from("!H", data, 4)
    cut = cut or (plen and len(data) < 40 + plen)
    if plen:  # 0 means a jumbogram, whose length is in an extension header
        data = data[:40 + plen]
    try:
        ip = dpkt.ip6.IP6(data)
    except Exception:  # dpkt on damaged input: see the module docstring
        return Skip("IPv6 headers could not be read", True)
    if not hasattr(ip, "p"):  # dpkt stops at headers it cannot walk past, such as IPsec's
        if ip.nxt in (dpkt.ip.IP_PROTO_ESP, dpkt.ip.IP_PROTO_AH):
            return Skip(f"IP protocol {ip.nxt}", False)
        return Skip("IPv6 extension headers could not be read", True)
    if dpkt.ip.IP_PROTO_FRAGMENT in ip.extension_hdrs and ip.extension_hdrs[dpkt.ip.IP_PROTO_FRAGMENT]:
        return Skip("IP fragment (fragments are not reassembled)", False)
    common = dict(frame=frame_no, ts=ts, direction=direction, ip_version=6,
                  src=_addr(ip.src), dst=_addr(ip.dst), ttl=ip.hlim)
    offset = _ipv6_upper_offset(data)
    raw = data[offset:] if offset is not None else None
    return _transport(ip.p, ip.data, raw, common, cut)


IPV6_OPTION_HEADERS = (0, 43, 60, 135, 139, 140)  # hop-by-hop, routing, destination, mobility, HIP, shim6
MAX_IPV6_HEADERS = 16


def _ipv6_upper_offset(data):
    """Where the upper-layer header starts, walking the extension headers; None if they run off the end."""
    nxt, offset = data[6], 40
    for _ in range(MAX_IPV6_HEADERS):
        if nxt not in (*IPV6_OPTION_HEADERS, dpkt.ip.IP_PROTO_FRAGMENT, dpkt.ip.IP_PROTO_AH):
            return offset
        if len(data) < offset + 2:
            return None
        if nxt == dpkt.ip.IP_PROTO_FRAGMENT:
            length = 8
        elif nxt == dpkt.ip.IP_PROTO_AH:
            length = (data[offset + 1] + 2) * 4
        else:
            length = (data[offset + 1] + 1) * 8
        nxt, offset = data[offset], offset + length
    return None


def _not_decoded(name, raw, header_len):
    """Why dpkt could not decode a transport header: too few bytes, or nonsense in them."""
    if raw is not None and len(raw) >= header_len:
        return Skip(f"{name} header is invalid", True)
    return Skip(f"{name} header cut short", True)


def _transport(proto, layer, raw, common, cut):
    """proto is the IP protocol number; layer is dpkt's decode of it (bytes when it gave up);
    raw is the transport bytes when known."""
    if proto == dpkt.ip.IP_PROTO_UDP:
        if not isinstance(layer, dpkt.udp.UDP):
            return _not_decoded("UDP", raw, 8)
        if layer.ulen < 8:
            return Skip("UDP length field is invalid", True)
        payload = bytes(layer.data)
        want = layer.ulen - 8  # anything beyond it is link-layer padding
        return Packet(**common, proto="udp", sport=layer.sport, dport=layer.dport,
                      payload=payload[:want], truncated=len(payload) < want)
    if proto == dpkt.ip.IP_PROTO_TCP:
        if not isinstance(layer, dpkt.tcp.TCP) or layer.off * 4 < 20:
            return _not_decoded("TCP", raw, 20)
        return Packet(**common, proto="tcp", sport=layer.sport, dport=layer.dport, payload=bytes(layer.data),
                      truncated=bool(cut), tcp_seq=layer.seq, tcp_ack=layer.ack, tcp_flags=layer.flags)
    if proto in (dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6):
        # The original bytes, not dpkt's: re-serialising a damaged decode can itself fail.
        icmp = _icmp_error(raw or b"", v6=proto == dpkt.ip.IP_PROTO_ICMP6)
        if icmp is None:
            return Skip("ICMP other than destination unreachable", False)
        return Packet(**common, proto="icmp", icmp=icmp, truncated=bool(cut))
    return Skip(f"IP protocol {proto}", False)


def _icmp_error(body, v6):
    """An IcmpError for a destination unreachable that quotes a UDP or TCP packet, else None."""
    if len(body) < 8:
        return None
    icmp_type, code = body[0], body[1]
    quoted = body[8:]  # type, code, checksum, then 4 unused bytes
    if v6:
        if icmp_type != 1 or len(quoted) < 44:
            return None
        reason = ICMP6_UNREACH.get(code, f"unreachable (code {code})")
        proto, src, dst, ports = quoted[6], quoted[8:24], quoted[24:40], quoted[40:44]
    else:
        if icmp_type != 3 or len(quoted) < 20 or quoted[0] >> 4 != 4:
            return None
        ihl = (quoted[0] & 0x0F) * 4
        if ihl < 20 or len(quoted) < ihl + 4:
            return None
        reason = ICMP4_UNREACH.get(code, f"unreachable (code {code})")
        proto, src, dst, ports = quoted[9], quoted[12:16], quoted[16:20], quoted[ihl:ihl + 4]
    if proto not in (dpkt.ip.IP_PROTO_UDP, dpkt.ip.IP_PROTO_TCP):
        return None
    sport, dport = struct.unpack("!HH", ports)
    return IcmpError(reason, "udp" if proto == dpkt.ip.IP_PROTO_UDP else "tcp",
                     _addr(src), _addr(dst), sport, dport)
