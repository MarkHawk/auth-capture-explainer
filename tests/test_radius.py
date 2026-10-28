"""Finding and decoding RADIUS messages: ports, codes, attributes, vendor
attributes, and messages that are cut short or malformed."""

import pytest

import pcapbuild as pb
from auth_capture_explainer import layers, radius
from auth_capture_explainer.radius import Malformed, Message, Ports
from auth_capture_explainer.radius_dict import Attribute


def packet(payload, sport=40000, dport=1812, src=pb.CLIENT, dst=pb.SERVER, cut=False, frame=1, ts=1.0):
    p = layers.decode(frame, ts, layers.LINKTYPE_RAW, pb.udp(src, dst, sport, dport, payload))
    if cut:  # as if the snapshot length stopped it at 30 bytes
        frame_bytes = pb.udp(src, dst, sport, dport, payload)[:28 + 30]
        p = layers.decode(frame, ts, layers.LINKTYPE_RAW, frame_bytes, cut=True)
    return p


REQUEST = pb.radius(1, 7, [(1, "dave"), (2, b"\xaa" * 16), (32, "nas"), (80, b"\x00" * 16)])


def test_access_request():
    m = radius.decode(packet(REQUEST))
    assert isinstance(m, Message) and m.complete
    assert (m.code, m.name, m.id, m.length, m.is_request) == (1, "Access-Request", 7, len(REQUEST), True)
    assert m.authenticator == pb.AUTH and m.raw == REQUEST
    assert [(a.name, a.display()) for a in m.attributes] == [
        ("User-Name", "dave"), ("User-Password", "(hidden, 16 bytes)"), ("NAS-Identifier", "nas"),
        ("Message-Authenticator", "(present, value hidden)")]
    assert m.get(1).value == b"dave" and m.has(80) and not m.has(18)


def test_reply_with_two_reply_messages():
    m = radius.decode(packet(pb.radius(3, 7, [(18, "Password expired"), (18, "Call the help desk")]), 1812, 40000))
    assert not m.is_request and m.name == "Access-Reject"
    assert [a.value for a in m.all(18)] == [b"Password expired", b"Call the help desk"]


def test_vendor_specific_sub_attributes():
    m = radius.decode(packet(pb.radius(3, 1, [pb.vsa(311, 16, b"k" * 34), pb.vsa(311, 2, b"E=691 R=0 V=3"),
                                              pb.vsa(9, 1, b"vendor text"), pb.vsa(9, 2, b"other")])))
    assert [(a.name, a.display()) for a in m.attributes] == [
        ("MS-MPPE-Send-Key", "(hidden, 34 bytes)"), ("MS-CHAP-Error", "E=691 R=0 V=3"),
        ("VSA vendor 9, type 1", "vendor text"), ("VSA vendor 9, type 2", "(5 bytes)")]


def test_vendor_specific_in_a_non_standard_layout_is_kept_whole():
    odd = (26, (12356).to_bytes(4, "big") + b"\x01\x00\x05abc")  # sub-attribute length 0
    m = radius.decode(packet(pb.radius(2, 1, [odd])))
    assert len(m.attributes) == 1 and m.attributes[0].vendor == 12356 and m.attributes[0].vendor_type is None
    assert m.attributes[0].display() == "(10 bytes)" and m.complete


def test_padding_after_the_length_field_is_ignored():
    m = radius.decode(packet(REQUEST + b"\x00" * 7))
    assert m.raw == REQUEST and m.complete and len(m.attributes) == 4


def test_cut_by_the_snapshot_length_keeps_what_was_captured():
    m = radius.decode(packet(REQUEST, cut=True))
    assert isinstance(m, Message) and (m.code, m.id) == (1, 7) and not m.complete
    assert m.problems == [f"only 30 of {len(REQUEST)} bytes were captured: the capture's snapshot length cut it short"]
    assert [a.name for a in m.attributes] == ["User-Name"]  # the whole attributes before the cut


def test_header_only_cut():
    m = radius.decode(packet(REQUEST[:12]))
    assert isinstance(m, Message) and m.attributes == [] and "only 12 of" in m.problems[0]


@pytest.mark.parametrize("payload,reason", [
    (b"\x01\x02", "2 bytes, too short for a RADIUS header"),
    (b"\x63\x01\x00\x14" + b"\x00" * 16, "code 99 is not a RADIUS packet type"),
    (b"\x01\x01\x00\x10" + b"\x00" * 16, "length field 16 is outside the allowed 20 to 4096"),
    (b"\x01\x01\x10\x01" + b"\x00" * 16, "length field 4097 is outside the allowed 20 to 4096"),
])
def test_not_radius(payload, reason):
    m = radius.decode(packet(payload))
    assert isinstance(m, Malformed) and m.reason == reason


@pytest.mark.parametrize("attrs,problem,kept", [
    (b"\x01\x00dave", "attribute 1 has an invalid length 0", []),
    (b"\x01\x01", "attribute 1 has an invalid length 1", []),
    (b"\x01\x20dave", "attribute 1 runs past the end of the message", []),
    (b"\x01\x06dave\x20", "an attribute header runs past the end of the message", ["User-Name"]),
])
def test_broken_attributes_keep_the_ones_before(attrs, problem, kept):
    body = b"\x20\x05abc" + attrs  # a good NAS-Identifier first
    payload = bytes([1, 1]) + (20 + len(body)).to_bytes(2, "big") + pb.AUTH + body
    m = radius.decode(packet(payload))
    assert m.problems == [problem] and [a.name for a in m.attributes] == ["NAS-Identifier", *kept]
    assert not m.complete


def test_find_uses_the_radius_ports_only():
    packets = [
        packet(REQUEST, dport=1812), packet(REQUEST, dport=1813), packet(REQUEST, dport=1645),
        packet(REQUEST, dport=1646), packet(REQUEST, dport=11812), packet(REQUEST, dport=53),
        packet(b"\x01\x02", dport=1812),
    ]
    messages, malformed = radius.find(packets)
    assert [m.packet.dport for m in messages] == [1812, 1813, 1645, 1646]
    assert [m.reason for m in malformed] == ["2 bytes, too short for a RADIUS header"]
    messages, _ = radius.find(packets, radius.DEFAULT_PORTS.with_extra({11812}))
    assert 11812 in [m.packet.dport for m in messages]


def test_find_recognises_a_client_sending_from_1812():
    messages, _ = radius.find([packet(REQUEST, sport=1812, dport=1812)])
    assert messages[0].is_request


def test_find_skips_tcp_and_icmp():
    tcp = layers.decode(1, 1.0, layers.LINKTYPE_RAW, pb.tcp(pb.CLIENT, pb.SERVER, 1, 1812, REQUEST))
    assert radius.find([tcp]) == ([], [])


def test_port_labels():
    ports = radius.DEFAULT_PORTS.with_extra({11812})
    assert ports.label(1812) == "1812" and ports.label(1813) == "1813"
    assert ports.label(1645) == "1645 (legacy authentication port)"
    assert ports.label(1646) == "1646 (legacy accounting port)"
    assert ports.label(11812) == "11812 (non-standard port)"
    assert ports.is_legacy(1645) and not ports.is_legacy(1812)
    assert ports.all == {1812, 1813, 1645, 1646, 11812}
    assert Ports().extra == frozenset() and radius.DEFAULT_PORTS.all == {1812, 1813, 1645, 1646}


def test_encode_round_trips():
    attrs = [Attribute(1, b"dave"), Attribute(80, b"\x00" * 16), Attribute(26, b"k" * 34, 311, 16),
             Attribute(26, (12356).to_bytes(4, "big") + b"\x01\x00\x05abc", 12356, None)]
    data = radius.encode(1, 9, pb.AUTH, attrs)
    m = radius.decode(packet(data))
    assert m.attributes == attrs and m.raw == data and m.complete
    assert radius.encode(1, 7, pb.AUTH, [(1, b"dave"), (2, b"\xaa" * 16), (32, b"nas"), (80, b"\x00" * 16)]) == REQUEST


@pytest.mark.parametrize("args,error", [
    ((1, 1, b"short", []), "authenticator must be 16 bytes"),
    ((1, 1, pb.AUTH, [(1, b"x" * 254)]), "limit is 253"),
    ((1, 1, pb.AUTH, [(1, b"x" * 253)] * 17), "limit is 4096"),
])
def test_encode_refuses_what_radius_cannot_carry(args, error):
    with pytest.raises(ValueError, match=error):
        radius.encode(*args)
