"""Damaged input never crashes the reader.

Mixed captures (every link layer, IPv4 and IPv6, UDP, TCP and ICMP) are cut
at every byte and mutated many times with a fixed seed, so a failure always
reproduces. The only exception allowed out is CaptureError, for a file that
is not a capture at all; everything else must come back as a Capture.
"""

import random

import pytest

import ldap_build as lb
import pcapbuild as pb
from ldap_build import Conversation
from radius_trace import Trace
from auth_capture_explainer import ber, layers, ldap, ldap_checks, ldap_exchange, radius_checks, radius_exchange, render, servers
from auth_capture_explainer.analyse import Options, analyse
from auth_capture_explainer.capture import Capture, CaptureError, read_capture
from auth_capture_explainer.causes import likely_causes
from auth_capture_explainer.radius_dict import ATTRIBUTES
from auth_capture_explainer.secret import Secret

SEED = 20261027
RADIUS = b"\x01\x07\x00\x14" + b"A" * 16


def ips():
    request = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    return [
        request,
        pb.udp(pb.CLIENT6, pb.SERVER6, 40000, 1812, RADIUS),
        pb.tcp(pb.CLIENT, pb.SERVER, 40000, 389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
        pb.tcp(pb.CLIENT6, pb.SERVER6, 40000, 389, b"\x30\x05\x02\x01\x02\x42\x00"),
        pb.icmp_unreachable(request),
        pb.icmp6_unreachable(pb.udp(pb.CLIENT6, pb.SERVER6, 40000, 1812, RADIUS)),
        pb.ipv6_with_hop_by_hop(pb.CLIENT6, pb.SERVER6, 1, 1812, RADIUS),
        pb.ipv4_fragment(pb.CLIENT, pb.SERVER, RADIUS),
    ]


def mixed_pcap():
    return pb.pcap([(i + 0.5, pb.ether(ip, vlans=[(0x8100, 5)] if i % 2 else ())) for i, ip in enumerate(ips())])


def mixed_pcapng():
    links = [(layers.LINKTYPE_ETHERNET, pb.ether), (layers.LINKTYPE_LINUX_SLL2, pb.sll2),
             (layers.LINKTYPE_RAW, lambda ip: ip), (layers.LINKTYPE_NULL, pb.null)]
    blocks = [pb.idb(lt, tsresol=9 if i else None) for i, (lt, _) in enumerate(links)]
    for i, ip in enumerate(ips()):
        if_id = i % len(links)
        blocks.append(pb.epb(if_id, i * 1000, links[if_id][1](ip), flags=1 + i % 2))
    blocks += [pb.spb(pb.ether(ips()[0])), pb.dsb(), pb.nrb()]
    return pb.pcapng(*blocks)


def read_or_refuse(path):
    try:
        cap = read_capture(path)
    except CaptureError:
        return None
    assert isinstance(cap, Capture)
    return cap


@pytest.mark.parametrize("build", [mixed_pcap, mixed_pcapng])
def test_the_samples_read_cleanly(tmp_path, build):
    cap = read_capture(pb.write(tmp_path, "a", build()))
    assert not cap.malformed and len(cap.packets) >= 7


@pytest.mark.parametrize("build", [mixed_pcap, mixed_pcapng])
def test_cut_at_every_byte(tmp_path, build):
    data = build()
    path = tmp_path / "cut"
    for end in range(len(data)):
        path.write_bytes(data[:end])
        read_or_refuse(path)


@pytest.mark.parametrize("build", [mixed_pcap, mixed_pcapng])
def test_random_mutations(tmp_path, build):
    rng = random.Random(SEED)
    data = build()
    path = tmp_path / "mutated"
    for _ in range(1500):
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(len(b))
            choice = rng.random()
            if choice < 0.5:
                b[i] ^= 1 << rng.randrange(8)
            elif choice < 0.8:
                b[i] = rng.choice((0x00, 0xFF, 0x7F, 0x80))
            else:
                del b[i:i + rng.randint(1, 16)]
                if not b:
                    break
        path.write_bytes(bytes(b))
        read_or_refuse(path)


@pytest.mark.parametrize("linktype", sorted(layers.LINKTYPE_NAMES))
def test_random_frames_never_raise(linktype):
    rng = random.Random(SEED + linktype)
    templates = [pb.ether(ip) for ip in ips()] + ips()
    for _ in range(2000):
        if rng.random() < 0.3:
            frame = bytes(rng.randrange(256) for _ in range(rng.randrange(80)))
        else:
            b = bytearray(rng.choice(templates))
            for _ in range(rng.randint(1, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            frame = bytes(b[:rng.randrange(len(b) + 1)])
        result = layers.decode(1, 0.0, linktype, frame)
        assert isinstance(result, (layers.Packet, layers.Skip))


def radius_templates():
    attrs = [(t, b"\x00\x00\x00\x01") for t in ATTRIBUTES if t != 26]
    return [
        pb.radius(1, 1, attrs[:40]),
        pb.radius(1, 2, attrs[40:] + [pb.vsa(311, 16, b"k" * 34), pb.vsa(311, 2, b"E=691")]),
        pb.radius(3, 1, [(18, "denied"), (79, b"\x04\x07\x00\x04"), (97, b"\x00\x40" + b"\x20" * 8)]),
        pb.radius(4, 9, [(40, b"\x00\x00\x00\x01"), (44, "s"), (55, b"\xff\xff\xff\xff"), (64, b"\x01\x00\x00\x0d")]),
    ]


def test_random_radius_never_raises():
    """Mutated RADIUS through decoding, pairing, summaries and every attribute's display."""
    rng = random.Random(SEED)
    templates = radius_templates()
    packets = []
    for n in range(3000):
        b = bytearray(rng.choice(templates))
        for _ in range(rng.randint(1, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        payload = bytes(b[:rng.randrange(len(b) + 1)])
        port = rng.choice((1812, 1813))
        if rng.random() < 0.5:  # towards the server
            ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, port, payload)
        else:
            ip = pb.udp(pb.SERVER, pb.CLIENT, port, 40000, payload)
        packets.append(layers.decode(n + 1, n * 0.01, layers.LINKTYPE_RAW, ip))
    result = radius_exchange.analyse(packets, capture_end=100.0)
    for e in result.exchanges:
        for m in (*e.attempts, *([e.reply] if e.reply else [])):
            for a in m.attributes:
                assert isinstance(a.display(), str)
        e.outcome, e.response_time, e.user_name, e.reply_messages
    for c in result.conversations():
        c.outcomes, c.response_times, c.reject_times


def test_random_radius_through_checks_and_causes_never_raises():
    """The same mutated traffic, with and without a secret, all the way to likely causes."""
    rng = random.Random(SEED + 1)
    templates = radius_templates()
    packets = []
    for n in range(2000):
        b = bytearray(rng.choice(templates))
        for _ in range(rng.randint(0, 4)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        payload = bytes(b[:rng.randrange(len(b) + 1)])
        if rng.random() < 0.5:
            ip = pb.udp(pb.CLIENT, pb.SERVER, 40000 + rng.randrange(2), 1812, payload)
        else:
            ip = pb.udp(pb.SERVER, pb.CLIENT, 1812, 40000 + rng.randrange(2), payload)
        packets.append(layers.decode(n + 1, n * 0.5, layers.LINKTYPE_RAW, ip, rng.choice(("in", "out", None))))
    result = radius_exchange.analyse(packets, capture_end=1100.0)
    for secret in (None, Secret(b"fuzz-secret", "test")):
        likely_causes(radius_checks.check(result, secret))


def ldap_conversation_bytes():
    up = (lb.bind_request(1, "cn=svc,ou=services,dc=example", "x" * 20)
          + lb.search_request(2, "ou=people,dc=example", lb.f_and(lb.f_eq("uid", "dave"), lb.f_present("cn")))
          + lb.extended_request(3, lb.STARTTLS) + lb.client_hello("ldap.example") + lb.app_data())
    down = (lb.bind_response(1, 49, "", "data 52e") + lb.search_entry(2, "uid=dave,dc=example", [("cn", ["D"])])
            + lb.search_done(2) + lb.extended_response(3, 0, lb.STARTTLS) + lb.server_hello(tls13=True)
            + lb.alert(2, 48))
    return up, down


def test_random_ldap_streams_never_raise():
    """Mutated LDAP conversations through TCP reassembly, decoding, pairing and the TLS reader."""
    rng = random.Random(SEED + 2)
    up, down = ldap_conversation_bytes()
    for _ in range(300):
        c = Conversation(sport=rng.choice((389, 636))).handshake(1.0)
        for data, from_client in ((up, True), (down, False)):
            b = bytearray(data)
            for _ in range(rng.randint(0, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            c.send(1.1, from_client, bytes(b[:rng.randrange(len(b) + 1)]), split=rng.randint(1, 60))
        packets = c.numbered()
        rng.shuffle(packets)
        if rng.random() < 0.3:
            packets = packets[: rng.randrange(len(packets) + 1)]
        result = ldap_exchange.analyse(packets)
        for conn in result.connections:
            for op in conn.operations:
                op.response_time, op.first_response_time, op.entries, op.references
        findings = ldap_checks.check(result, capture_end=10.0)
        likely_causes(findings + servers.check(servers.summaries(ldap_result=result)))


def test_random_bytes_through_ber_and_ldap_never_raise_anything_but_ber_errors():
    rng = random.Random(SEED + 3)
    up, down = ldap_conversation_bytes()
    for _ in range(5000):
        b = bytearray(rng.choice((up, down)))
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        data = bytes(b[rng.randrange(len(b)):])
        try:
            ldap.decode(ber.read(data))
        except ber.BerError:
            pass


def test_whole_pipeline_on_mutated_files_never_raises(tmp_path):
    """RADIUS and LDAP together, mutated at the file level, through analysis and both renderers."""
    t = Trace()
    for i in range(3):
        t.request(1.0 + 2 * i, 16, secret=b"s", password=b"pw")
    t.request(2.0, 1)
    t.reply(2.5, 1, code=3, attrs=[(18, "no")])
    c = Conversation().handshake(1.0)
    up, down = ldap_conversation_bytes()
    c.client_says(1.1, up, split=50)
    c.server_says(1.2, down, split=50)
    data = pb.pcap(sorted(t.ips + c.ips), linktype=101)
    rng = random.Random(SEED + 4)
    path = tmp_path / "m.pcap"
    for i in range(150):
        b = bytearray(data)
        for _ in range(rng.randint(1, 20)):
            b[rng.randrange(24, len(b))] = rng.randrange(256)
        path.write_bytes(bytes(b))
        cap = read_or_refuse(path)
        if cap is None:
            continue
        report = analyse(cap, Options(secret=Secret(b"s", "test") if i % 2 else None))
        render.render_text(report)
        render.render_json(report)
