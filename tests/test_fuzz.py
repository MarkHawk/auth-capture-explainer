"""Damaged input never crashes the reader.

Mixed captures (every link layer, IPv4 and IPv6, UDP, TCP and ICMP) are cut
at every byte and mutated many times with a fixed seed, so a failure always
reproduces. The only exception allowed out is CaptureError, for a file that
is not a capture at all; everything else must come back as a Capture.
"""

import random

import pytest

import pcapbuild as pb
from pcap_analyser import layers
from pcap_analyser.capture import Capture, CaptureError, read_capture

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
