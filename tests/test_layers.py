"""Frames to Packets: every supported link layer, IPv4 and IPv6, and the ways
a frame can be damaged, cut short or simply not relevant."""

import struct

import pytest

import pcapbuild as pb
from pcap_analyser import layers
from pcap_analyser.layers import Packet, Skip

RADIUS = b"\x01\x07\x00\x14" + b"A" * 16  # a bare Access-Request header


def decode(frame, linktype=layers.LINKTYPE_ETHERNET, **kw):
    return layers.decode(1, 100.0, linktype, frame, **kw)


def test_ethernet_ipv4_udp():
    p = decode(pb.ether(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)))
    assert isinstance(p, Packet)
    assert (p.ip_version, p.src, p.dst, p.proto, p.sport, p.dport) == (4, pb.CLIENT, pb.SERVER, "udp", 40000, 1812)
    assert p.payload == RADIUS and not p.truncated and p.direction is None and p.ttl == 64


def test_ethernet_padding_is_not_payload():
    """Frames under 60 bytes are padded; the padding must not join a UDP or TCP payload."""
    u = decode(pb.ether(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, b"ab")))
    t = decode(pb.ether(pb.tcp(pb.CLIENT, pb.SERVER, 40000, 389, b"ab")))
    assert u.payload == b"ab" and t.payload == b"ab"


@pytest.mark.parametrize("vlans", [[(0x8100, 10)], [(0x88A8, 100), (0x8100, 10)]], ids=["802.1Q", "QinQ"])
def test_vlan_tags(vlans):
    p = decode(pb.ether(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS), vlans=vlans))
    assert p.payload == RADIUS


def test_ipv6_udp_and_tcp():
    u = decode(pb.ether(pb.udp(pb.CLIENT6, pb.SERVER6, 40000, 1812, RADIUS)))
    t = decode(pb.ether(pb.tcp(pb.CLIENT6, pb.SERVER6, 40000, 389, b"\x30\x00", seq=5, ack=9)))
    assert (u.ip_version, u.src, u.dst, u.payload) == (6, pb.CLIENT6, pb.SERVER6, RADIUS)
    assert (t.proto, t.payload, t.tcp_seq, t.tcp_ack) == ("tcp", b"\x30\x00", 5, 9)


def test_ipv6_extension_header_is_walked():
    p = decode(pb.ether(pb.ipv6_with_hop_by_hop(pb.CLIENT6, pb.SERVER6, 40000, 1812, RADIUS)))
    assert (p.proto, p.dport, p.payload) == ("udp", 1812, RADIUS)


@pytest.mark.parametrize("frame", [
    pb.ipv4_fragment(pb.CLIENT, pb.SERVER, RADIUS, more=True),
    pb.ipv4_fragment(pb.CLIENT, pb.SERVER, RADIUS, more=False, offset=185),
    pb.ipv6_fragment(pb.CLIENT6, pb.SERVER6, RADIUS),
], ids=["v4-first", "v4-last", "v6"])
def test_fragments_are_skipped_not_misread(frame):
    assert decode(frame, layers.LINKTYPE_RAW) == Skip("IP fragment (fragments are not reassembled)", False)


@pytest.mark.parametrize("pkttype,direction", [(0, "in"), (4, "out"), (3, None)])
def test_linux_cooked_direction(pkttype, direction):
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    assert decode(pb.sll(ip, pkttype), layers.LINKTYPE_LINUX_SLL).direction == direction
    assert decode(pb.sll2(ip, pkttype), layers.LINKTYPE_LINUX_SLL2).direction == direction


def test_direction_from_the_file_is_kept_when_the_link_layer_has_none():
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    assert decode(pb.ether(ip), direction="out").direction == "out"


@pytest.mark.parametrize("order", ["<", ">"])
@pytest.mark.parametrize("version", [4, 6])
def test_bsd_loopback_in_either_byte_order(order, version):
    ip = pb.udp(pb.CLIENT if version == 4 else pb.CLIENT6, pb.SERVER if version == 4 else pb.SERVER6,
                40000, 1812, RADIUS)
    assert decode(pb.null(ip, order=order), layers.LINKTYPE_NULL).ip_version == version
    assert decode(pb.loop(ip), layers.LINKTYPE_LOOP).ip_version == version


@pytest.mark.parametrize("linktype", [layers.LINKTYPE_RAW, 12, 14, layers.LINKTYPE_IPV4, layers.LINKTYPE_IPV6])
def test_raw_ip(linktype):
    ip = pb.udp(pb.CLIENT6, pb.SERVER6, 1, 1812, RADIUS) if linktype == layers.LINKTYPE_IPV6 else \
        pb.udp(pb.CLIENT, pb.SERVER, 1, 1812, RADIUS)
    assert decode(ip, linktype).payload == RADIUS


def test_snapshot_length_cut_marks_udp_truncated():
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    p = decode(pb.ether(ip, pad=False)[:14 + 28 + 6], cut=True)
    assert p.truncated and p.payload == RADIUS[:6]


def test_snapshot_length_cut_marks_tcp_truncated():
    ip = pb.tcp(pb.CLIENT, pb.SERVER, 40000, 389, b"x" * 40)
    p = decode(pb.ether(ip)[:14 + 40 + 10], cut=True)
    assert p.truncated and p.payload == b"x" * 10


@pytest.mark.parametrize("frame,reason", [
    (pb.arp(), "not IP"),
    (pb.ether(pb.other_ip_proto(47)), "IP protocol 47"),
    (pb.ether(pb.icmp_echo()), "ICMP other than destination unreachable"),
])
def test_irrelevant_frames_are_ignored_not_malformed(frame, reason):
    assert decode(frame) == Skip(reason, False)


def test_unsupported_link_type():
    assert decode(b"\x00" * 40, 147) == Skip("link type 147 is not supported", False)


def test_icmp_port_unreachable_names_the_original_request():
    request = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    p = decode(pb.ether(pb.icmp_unreachable(request, code=3)))
    assert (p.proto, p.src, p.dst) == ("icmp", pb.SERVER, pb.CLIENT)
    assert p.icmp == layers.IcmpError("port unreachable", "udp", pb.CLIENT, pb.SERVER, 40000, 1812)


def test_icmp_admin_prohibited():
    request = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    assert decode(pb.ether(pb.icmp_unreachable(request, code=13))).icmp.reason == "administratively prohibited"


def test_icmpv6_port_unreachable():
    request = pb.udp(pb.CLIENT6, pb.SERVER6, 40000, 1812, RADIUS)
    p = decode(pb.ether(pb.icmp6_unreachable(request, code=4)))
    assert p.icmp == layers.IcmpError("port unreachable", "udp", pb.CLIENT6, pb.SERVER6, 40000, 1812)


def _corrupt(ip, offset, value, fmt="!B"):
    b = bytearray(ip)
    struct.pack_into(fmt, b, offset, value)
    return bytes(b)


UDP4 = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
TCP4 = pb.tcp(pb.CLIENT, pb.SERVER, 40000, 389, b"x")


@pytest.mark.parametrize("frame,reason", [
    (b"\x00" * 10, "Ethernet header cut short"),
    (pb.ether(UDP4)[:14] + UDP4[:12], "IPv4 header cut short"),
    (pb.ether(_corrupt(UDP4, 0, 0x44)), "IPv4 header lengths are invalid"),  # IHL 4: 16 bytes
    (pb.ether(_corrupt(UDP4, 2, 10, "!H")), "IPv4 header lengths are invalid"),  # total < IHL
    (pb.ether(UDP4[:24], pad=False), "UDP header cut short"),
    (pb.ether(_corrupt(UDP4, 24, 4, "!H")), "UDP length field is invalid"),
    (pb.ether(_corrupt(TCP4, 32, 0x40)), "TCP header is invalid"),
    (pb.ether(pb.udp(pb.CLIENT6, pb.SERVER6, 1, 2, b""))[:14 + 30], "IPv6 header cut short"),
    (pb.ether(UDP4, vlans=[(0x8100, 1)])[:16], "VLAN tag cut short"),
    (b"\x00" * 10, "Linux cooked header cut short"),
], ids=["eth", "ip4-short", "ihl", "total", "udp-short", "ulen", "tcp-off", "ip6-short", "vlan", "sll"])
def test_damaged_frames_are_malformed(frame, reason):
    linktype = layers.LINKTYPE_LINUX_SLL if reason.startswith("Linux") else layers.LINKTYPE_ETHERNET
    assert decode(frame, linktype) == Skip(reason, True)


def test_raw_garbage_is_malformed():
    assert decode(b"\x10\x00", layers.LINKTYPE_RAW) == Skip("raw packet that is neither IPv4 nor IPv6", True)
