"""TCP reassembly: order, retransmission, overlap, gaps, wrap-around, roles,
closing, and the size cap."""

from dataclasses import replace

import pcapbuild as pb
from ldap_build import Conversation
from auth_capture_explainer import tcpstream

PORTS = {389}


def one(packets):
    (stream,) = tcpstream.streams(packets, PORTS)
    return stream


def joined(direction):
    return b"".join(c.data for c in direction.chunks)


def test_in_order_both_directions():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, b"hello server")
    c.server_says(1.2, b"hello client")
    s = one(c.packets)
    assert (s.client, s.client_port, s.server, s.server_port, s.syn_seen) == (pb.CLIENT, 40000, pb.SERVER, 389, True)
    assert joined(s.to_server) == b"hello server" and joined(s.to_client) == b"hello client"
    assert s.to_server.gaps == s.to_client.gaps == 0


def test_out_of_order_segments_are_put_back():
    c = Conversation().handshake(1.0)
    segments = c.client_says(1.1, b"abcdefghij", split=3)
    c.packets = c.packets[:3] + list(reversed(segments))
    assert joined(one(c.packets).to_server) == b"abcdefghij"


def test_retransmissions_and_overlaps_keep_the_first_copy():
    c = Conversation().handshake(1.0)
    first = c.client_says(1.1, b"abcdef")[0]
    c.packets.append(replace(first, ts=1.5, payload=b"abcdef"))  # a whole retransmission
    c.packets.append(replace(first, ts=1.6, tcp_seq=first.tcp_seq + 3, payload=b"DEFghi"))  # overlap, new tail
    stream = one(c.packets)
    assert joined(stream.to_server) == b"abcdefghi" and stream.to_server.gaps == 0


def test_a_gap_splits_the_stream_and_is_counted():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, b"before")
    c.skip(True, 7)
    c.client_says(1.2, b"after")
    d = one(c.packets).to_server
    assert [(ch.start, ch.data) for ch in d.chunks] == [(0, b"before"), (13, b"after")]
    assert (d.gaps, d.missing_bytes) == (1, 7)


def test_sequence_numbers_wrap():
    c = Conversation(isn=((1 << 32) - 4, 5000)).handshake(1.0)
    c.client_says(1.1, b"abcdefgh", split=3)
    assert joined(one(c.packets).to_server) == b"abcdefgh"


def test_capture_joined_part_way_uses_the_ldap_port_for_roles():
    c = Conversation()
    c.server_says(1.0, b"late reply")  # no handshake: the server speaks first in the capture
    c.client_says(1.1, b"next request")
    s = one(c.packets)
    assert (s.server, s.server_port, s.syn_seen) == (pb.SERVER, 389, False)
    assert joined(s.to_client) == b"late reply" and joined(s.to_server) == b"next request"


def test_the_syn_decides_roles_when_both_ports_are_ldap_ports():
    c = Conversation(cport=636, sport=389).handshake(1.0)
    c.client_says(1.1, b"x")
    s = tcpstream.streams(c.packets, {389, 636})[0]
    assert (s.client_port, s.server_port) == (636, 389)


def test_when_gives_the_delivering_segment():
    c = Conversation().handshake(1.0)
    c.client_says(2.0, b"abc")
    c.client_says(3.0, b"def")
    chunk = one(c.numbered()).to_server.chunks[0]
    assert [chunk.when(i)[0] for i in range(6)] == [2.0, 2.0, 2.0, 3.0, 3.0, 3.0]
    assert chunk.when(4)[1] == 5  # frame numbers as the capture numbers them


def test_closing():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, b"x")
    c.close(1.2, from_client=True)
    assert one(c.packets).closed_by == "both" and one(c.packets).reset_by is None
    r = Conversation().handshake(1.0)
    r.close(1.1, from_client=False, reset=True)
    assert one(r.packets).closed_by == "server" and one(r.packets).reset_by == "server"


def test_a_handshake_alone_has_no_chunks():
    s = one(Conversation().handshake(1.0).packets)
    assert s.to_server.chunks == [] and s.to_client.chunks == []


def test_other_ports_are_ignored():
    c = Conversation(sport=80).handshake(1.0)
    assert tcpstream.streams(c.packets, PORTS) == []


def test_ipv6():
    c = Conversation(client=pb.CLIENT6, server=pb.SERVER6).handshake(1.0)
    c.client_says(1.1, b"v6")
    assert joined(one(c.packets).to_server) == b"v6"


def test_the_size_cap(monkeypatch):
    monkeypatch.setattr(tcpstream, "MAX_STREAM", 10)
    c = Conversation().handshake(1.0)
    c.client_says(1.1, b"0123456789abcdef", split=4)
    d = one(c.packets).to_server
    assert joined(d) == b"0123456789" and d.capped
