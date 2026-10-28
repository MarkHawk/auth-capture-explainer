"""Build small synthetic captures for tests.

Packets are assembled with dpkt; the .pcap and .pcapng files are written
here with struct, independently of auth_capture_explainer.capture, so a mistake in the
reader cannot be mirrored by the writer. Addresses come from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32).
"""

import ipaddress
import struct

import dpkt

CLIENT, SERVER = "192.0.2.10", "192.0.2.2"
CLIENT6, SERVER6 = "2001:db8::10", "2001:db8::2"


def _raw(addr):
    return ipaddress.ip_address(addr).packed


# --- IP packets -------------------------------------------------------------

def udp(src, dst, sport, dport, payload, ttl=64):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = len(u)
    return _ip(src, dst, dpkt.ip.IP_PROTO_UDP, u, ttl)


def tcp(src, dst, sport, dport, payload=b"", seq=0, ack=0, flags=dpkt.tcp.TH_ACK, ttl=64):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=payload)
    return _ip(src, dst, dpkt.ip.IP_PROTO_TCP, t, ttl)


def _ip(src, dst, proto, upper, ttl):
    if ipaddress.ip_address(src).version == 6:
        ip6 = dpkt.ip6.IP6(src=_raw(src), dst=_raw(dst), nxt=proto, hlim=ttl, data=upper)
        ip6.plen = len(bytes(upper))
        return bytes(ip6)
    ip = dpkt.ip.IP(src=_raw(src), dst=_raw(dst), p=proto, ttl=ttl, data=upper)
    ip.len = len(ip)
    return bytes(dpkt.ip.IP(bytes(ip)))  # round trip, so the checksum is filled in


def ipv6_with_hop_by_hop(src, dst, sport, dport, payload):
    """An IPv6 UDP packet behind a hop-by-hop options header."""
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = len(u)
    hbh = bytes([dpkt.ip.IP_PROTO_UDP, 0]) + b"\x01\x04\x00\x00\x00\x00"  # PadN to 8 bytes
    body = hbh + bytes(u)
    header = struct.pack("!IHBB", 6 << 28, len(body), 0, 64) + _raw(src) + _raw(dst)
    return header + body


def ipv6_fragment(src, dst, payload):
    frag = struct.pack("!BBHI", dpkt.ip.IP_PROTO_UDP, 0, 1, 0x1234)  # offset 0, more fragments
    body = frag + payload
    header = struct.pack("!IHBB", 6 << 28, len(body), 44, 64) + _raw(src) + _raw(dst)
    return header + body


def ipv4_fragment(src, dst, payload, more=True, offset=0):
    ip = bytearray(udp(src, dst, 40000, 1812, payload))
    struct.pack_into("!H", ip, 6, (0x2000 if more else 0) | offset)
    return bytes(ip)


def icmp_unreachable(original, code=3, sender=SERVER):
    """An ICMPv4 destination unreachable quoting the first 28 bytes of original (IPv4/UDP)."""
    quoted = original[:28]
    body = struct.pack("!BBHI", 3, code, 0, 0) + quoted
    dst = str(ipaddress.ip_address(original[12:16]))
    return _ip_proto(sender, dst, dpkt.ip.IP_PROTO_ICMP, body)


def icmp6_unreachable(original, code=4, sender=SERVER6):
    quoted = original[:48]
    body = struct.pack("!BBHI", 1, code, 0, 0) + quoted
    dst = str(ipaddress.ip_address(original[8:24]))
    return _ip_proto(sender, dst, dpkt.ip.IP_PROTO_ICMP6, body)


def icmp_echo(src=CLIENT, dst=SERVER):
    return _ip_proto(src, dst, dpkt.ip.IP_PROTO_ICMP, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping")


def _ip_proto(src, dst, proto, body, ttl=64):
    if ipaddress.ip_address(src).version == 6:
        return struct.pack("!IHBB", 6 << 28, len(body), proto, ttl) + _raw(src) + _raw(dst) + body
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(body), 0, 0, ttl, proto, 0) + _raw(src) + _raw(dst)
    return header + body


def other_ip_proto(proto=47, src=CLIENT, dst=SERVER):
    return _ip_proto(src, dst, proto, b"\x00" * 8)


# --- link layers --------------------------------------------------------------

MAC_A, MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def ether(ip, vlans=(), pad=True):
    ethertype = 0x86DD if ip[0] >> 4 == 6 else 0x0800
    tags = b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in vlans)
    frame = MAC_B + MAC_A + tags + struct.pack("!H", ethertype) + ip
    return frame + b"\x00" * (60 - len(frame)) if pad and len(frame) < 60 else frame


def arp():
    return MAC_B + MAC_A + struct.pack("!H", 0x0806) + b"\x00" * 28


def sll(ip, pkttype=0):
    ethertype = 0x86DD if ip[0] >> 4 == 6 else 0x0800
    return struct.pack("!HHH8sH", pkttype, 1, 6, MAC_A + b"\0\0", ethertype) + ip


def sll2(ip, pkttype=0):
    ethertype = 0x86DD if ip[0] >> 4 == 6 else 0x0800
    return struct.pack("!HHIHBB8s", ethertype, 0, 2, 1, pkttype, 6, MAC_A + b"\0\0") + ip


def null(ip, family=None, order="<"):
    family = family if family is not None else (30 if ip[0] >> 4 == 6 else 2)
    return struct.pack(order + "I", family) + ip


def loop(ip):
    return struct.pack("!I", 24 if ip[0] >> 4 == 6 else 2) + ip


# --- files --------------------------------------------------------------------

def pcap(records, linktype=1, endian="<", nano=False, snaplen=262144):
    """records: (ts, frame) or (ts, frame, orig_len)."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    per_second = 1_000_000_000 if nano else 1_000_000
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for rec in records:
        ts, frame = rec[0], rec[1]
        orig = rec[2] if len(rec) > 2 else len(frame)
        sec = int(ts)
        frac = round((ts - sec) * per_second)
        out += struct.pack(endian + "IIII", sec, frac, len(frame), orig) + frame
    return out


def _option(endian, code, value):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def _block(endian, btype, body):
    length = 12 + len(body)
    return struct.pack(endian + "II", btype, length) + body + struct.pack(endian + "I", length)


def shb(endian="<"):
    return _block(endian, 0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))


def idb(linktype, endian="<", tsresol=None, tsoffset=None, name=None):
    opts = b""
    if tsresol is not None:
        opts += _option(endian, 9, bytes([tsresol]))
    if tsoffset is not None:
        opts += _option(endian, 14, struct.pack(endian + "q", tsoffset))
    if name is not None:
        opts += _option(endian, 2, name.encode())
    if opts:
        opts += _option(endian, 0, b"")
    return _block(endian, 1, struct.pack(endian + "HHI", linktype, 0, 262144) + opts)


def epb(if_id, ts_units, frame, endian="<", orig_len=None, flags=None):
    """ts_units: the timestamp in the interface's resolution (microseconds by default)."""
    body = struct.pack(endian + "IIIII", if_id, ts_units >> 32, ts_units & 0xFFFFFFFF, len(frame),
                       orig_len if orig_len is not None else len(frame))
    body += frame + b"\x00" * (-len(frame) % 4)
    if flags is not None:
        body += _option(endian, 2, struct.pack(endian + "I", flags)) + _option(endian, 0, b"")
    return _block(endian, 6, body)


def spb(frame, endian="<"):
    return _block(endian, 3, struct.pack(endian + "I", len(frame)) + frame + b"\x00" * (-len(frame) % 4))


def obsolete_pb(if_id, ts_units, frame, endian="<"):
    body = struct.pack(endian + "HHIIII", if_id, 0, ts_units >> 32, ts_units & 0xFFFFFFFF, len(frame), len(frame))
    return _block(endian, 2, body + frame + b"\x00" * (-len(frame) % 4))


def dsb(endian="<"):
    secrets = b"CLIENT_RANDOM 00 00\n"
    return _block(endian, 0x0A, struct.pack(endian + "II", 0x544C534B, len(secrets)) + secrets
                  + b"\x00" * (-len(secrets) % 4))


def nrb(endian="<"):
    return _block(endian, 4, struct.pack(endian + "HH", 0, 0))


def pcapng(*blocks, endian="<"):
    """A whole file: a section header, then the given blocks (already built)."""
    return shb(endian) + b"".join(blocks)


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


# --- RADIUS ---------------------------------------------------------------------

AUTH = bytes(range(16))  # a fixed Request Authenticator; tests that need it to vary pass their own


def radius(code, ident, attrs=(), authenticator=AUTH):
    """RADIUS bytes. attrs: (type, value) pairs, value as bytes or str."""
    body = b""
    for attr_type, value in attrs:
        value = value.encode() if isinstance(value, str) else value
        body += bytes([attr_type, len(value) + 2]) + value
    return struct.pack("!BBH", code, ident, 20 + len(body)) + authenticator + body


def vsa(vendor, vendor_type, value):
    """A Vendor-Specific attribute (type 26) holding one sub-attribute."""
    return 26, struct.pack("!I", vendor) + bytes([vendor_type, len(value) + 2]) + value


def int_attr(attr_type, n):
    return attr_type, struct.pack("!I", n)


def capture_file(tmp_path, name, *sources, linktype=101):
    """Write the raw IP packets of traces or conversations (anything with .ips) to a pcap, in time order."""
    timed = sorted((ts, ip) for source in sources for ts, ip in source.ips)
    return write(tmp_path, name, pcap(timed, linktype=linktype))
