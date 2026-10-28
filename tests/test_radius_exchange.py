"""Pairing requests with replies: retransmissions, out-of-order and duplicate
replies, retries under a new ID, replies from elsewhere, ICMP errors, and
the per-conversation summaries."""

import struct

import pytest

import pcapbuild as pb
from auth_capture_explainer import layers, radius
from auth_capture_explainer import radius_exchange as rx

OTHER_CLIENT, OTHER_SERVER = "198.51.100.20", "198.51.100.2"


class Trace:
    """Builds a list of Packets as a capture would hold them."""

    def __init__(self):
        self.packets = []

    def _add(self, ip, ts):
        p = layers.decode(len(self.packets) + 1, ts, layers.LINKTYPE_RAW, ip)
        assert isinstance(p, layers.Packet)
        self.packets.append(p)
        return p

    def request(self, ts, ident, user="dave", code=1, client=pb.CLIENT, cport=40000, server=pb.SERVER,
                sport=1812, auth=pb.AUTH, extra=()):
        attrs = ([(1, user)] if user else []) + list(extra)
        return self._add(pb.udp(client, server, cport, sport, pb.radius(code, ident, attrs, auth)), ts)

    def reply(self, ts, ident, code=2, client=pb.CLIENT, cport=40000, server=pb.SERVER, sport=1812, attrs=()):
        return self._add(pb.udp(server, client, sport, cport, pb.radius(code, ident, attrs)), ts)

    def raw(self, ts, ip):
        return self._add(ip, ts)

    def analyse(self, ports=radius.DEFAULT_PORTS, capture_end=None):
        end = capture_end if capture_end is not None else max(p.ts for p in self.packets) + 60
        return rx.analyse(self.packets, ports, end)


def only(result):
    assert len(result.exchanges) == 1
    return result.exchanges[0]


def test_accept():
    t = Trace()
    t.request(10.0, 1)
    t.reply(10.004, 1)
    e = only(t.analyse())
    assert (e.name, e.outcome, e.answered, e.retransmissions) == ("Access-Request", "Access-Accept", True, 0)
    assert e.response_time == pytest.approx(0.004) and e.user_name == "dave"
    assert (e.client, e.client_port, e.server, e.server_port, e.id) == (pb.CLIENT, 40000, pb.SERVER, 1812, 1)


def test_reject_with_reply_messages_is_timed_separately():
    t = Trace()
    t.request(10.0, 1)
    t.reply(11.0, 1, code=3, attrs=[(18, "Password has expired"), (18, "Call the help desk")])
    t.request(20.0, 2)
    t.reply(20.01, 2)
    r = t.analyse()
    assert r.exchanges[0].outcome == "Access-Reject"
    assert r.exchanges[0].reply_messages == ["Password has expired", "Call the help desk"]
    (conv,) = r.conversations()
    assert conv.response_times.count == 1 and conv.response_times.max == pytest.approx(0.01)
    assert conv.reject_times.count == 1 and conv.reject_times.max == pytest.approx(1.0)


def test_challenge():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1, code=11, attrs=[(24, b"\x01" * 8)])
    assert only(t.analyse()).outcome == "Access-Challenge"


def test_out_of_order_replies_pair_by_id():
    t = Trace()
    t.request(1.0, 1, user="dave")
    t.request(1.1, 2, user="erin")
    t.reply(1.2, 2, code=3)
    t.reply(1.5, 1, code=2)
    first, second = t.analyse().exchanges
    assert (first.user_name, first.outcome) == ("dave", "Access-Accept")
    assert (second.user_name, second.outcome) == ("erin", "Access-Reject")
    assert first.response_time == pytest.approx(0.5)


def test_packets_are_paired_in_time_order_not_file_order():
    t = Trace()
    t.reply(2.0, 1)  # listed first, as when two interfaces are merged
    t.request(1.0, 1)
    r = t.analyse()
    assert only(r).outcome == "Access-Accept" and r.orphan_replies == []


def test_retransmissions_with_no_reply():
    t = Trace()
    for ts in (1.0, 3.0, 5.0):
        t.request(ts, 16)
    e = only(t.analyse(capture_end=6.0))
    assert (e.retransmissions, e.span, e.reused_id_of) == (2, 4.0, None)
    # The capture stopped a second after the last attempt, but the first two had gone unanswered.
    assert e.outcome == rx.NO_REPLY and e.response_time is None


def test_a_lone_request_with_no_resends_anywhere_uses_the_default_window():
    t = Trace()
    t.request(1.0, 1)
    e = only(t.analyse(capture_end=2.0))
    assert (e.outcome, e.reply_window, e.reply_window_source) == \
        (rx.CAPTURE_ENDED, rx.DEFAULT_REPLY_WINDOW, rx.WINDOW_DEFAULT)
    assert only(t.analyse(capture_end=1.0 + rx.DEFAULT_REPLY_WINDOW + 1)).outcome == rx.NO_REPLY


def test_the_default_window_is_configurable():
    t = Trace()
    t.request(1.0, 1)
    e = only(rx.analyse(t.packets, capture_end=2.0, default_reply_window=0.5))
    assert (e.outcome, e.reply_window) == (rx.NO_REPLY, 0.5)


def test_the_window_is_the_interval_this_client_resends_at():
    t = Trace()
    for ts in (1.0, 4.0, 7.0):  # this client waits 3 s between attempts
        t.request(ts, 1)
    t.request(10.0, 1, client=OTHER_CLIENT, user="other")
    t.request(11.0, 1, client=OTHER_CLIENT, user="other")  # another client that waits 1 s
    t.request(30.0, 2, user="erin")

    def erin(capture_end):
        return next(e for e in t.analyse(capture_end=capture_end).exchanges if e.user_name == "erin")

    assert (erin(32.5).reply_window, erin(32.5).reply_window_source) == (3.0, rx.WINDOW_FROM_CLIENT)
    assert erin(32.5).outcome == rx.CAPTURE_ENDED  # 2.5 s after: not yet due from this client
    assert erin(33.5).outcome == rx.NO_REPLY  # 3.5 s after: due, and unanswered


def test_the_window_falls_back_to_the_capture_wide_interval():
    t = Trace()
    for ts in (1.0, 3.0):
        t.request(ts, 1)  # this client resends after 2 s
    t.request(10.0, 1, client=OTHER_CLIENT)  # this one never resends
    other = t.analyse(capture_end=11.5).exchanges[1]
    assert (other.reply_window, other.reply_window_source, other.outcome) == \
        (2.0, rx.WINDOW_FROM_CAPTURE, rx.CAPTURE_ENDED)
    assert t.analyse(capture_end=12.5).exchanges[1].outcome == rx.NO_REPLY


def test_a_retry_under_a_new_id_counts_towards_the_resend_interval():
    t = Trace()
    t.request(1.0, 1, cport=40000)
    t.request(5.0, 2, cport=40001)
    t.request(20.0, 3, cport=40002, user="erin")
    erin = t.analyse(capture_end=23.0).exchanges[2]
    assert (erin.reply_window, erin.outcome) == (4.0, rx.CAPTURE_ENDED)


def test_retransmission_then_reply_times_from_the_latest_attempt():
    t = Trace()
    t.request(1.0, 5)
    t.request(3.0, 5)
    t.reply(3.25, 5)
    e = only(t.analyse())
    assert e.retransmissions == 1
    assert e.response_time == pytest.approx(0.25) and e.total_time == pytest.approx(2.25)


def test_a_reply_to_each_resend_is_kept_as_a_duplicate():
    t = Trace()
    t.request(1.0, 5)
    t.request(3.0, 5)
    t.reply(3.1, 5)
    t.reply(3.2, 5)
    e = only(t.analyse())
    assert len(e.extra_replies) == 1 and e.reply.packet.ts == 3.1


def accounting_start(delay):
    return [(41, struct.pack("!I", delay)), (44, "sess-1"), (40, struct.pack("!I", 1))]


def test_same_id_with_a_new_authenticator_is_a_new_request():
    """An accounting resend with an updated Acct-Delay-Time has a new authenticator: a new request."""
    t = Trace()
    t.request(1.0, 9, user=None, code=4, sport=1813, auth=b"\x01" * 16, extra=accounting_start(0))
    t.request(4.0, 9, user=None, code=4, sport=1813, auth=b"\x02" * 16, extra=accounting_start(3))
    first, second = t.analyse().exchanges
    assert first.retransmissions == second.retransmissions == 0
    assert second.reused_id_of is first and second.retry_of is first  # same Acct-Session-Id


def test_id_reuse_while_a_request_is_pending():
    """Same client, port and ID, different Request Authenticator, before any reply: two requests.
    The one reply goes to the newer, and the newer is marked as having reused the ID."""
    t = Trace()
    t.request(1.0, 7, user="dave", auth=b"\x0a" * 16)
    t.request(1.5, 7, user="erin", auth=b"\x0b" * 16)
    t.reply(1.6, 7)
    first, second = t.analyse().exchanges
    assert (first.user_name, first.outcome, first.retransmissions) == ("dave", rx.NO_REPLY, 0)
    assert (second.user_name, second.outcome, second.reused_id_of) == ("erin", "Access-Accept", first)
    assert second.retry_of is None  # a different user: not a retry


def test_same_authenticator_is_a_retransmission():
    t = Trace()
    t.request(1.0, 7, auth=b"\x0a" * 16)
    t.request(3.0, 7, auth=b"\x0a" * 16)
    e = only(t.analyse())
    assert e.retransmissions == 1 and e.reused_id_of is None


def test_an_id_reused_after_a_reply_is_a_new_exchange():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.1, 1)
    t.request(2.0, 1, auth=b"\x09" * 16)
    t.reply(2.1, 1, code=3)
    first, second = t.analyse().exchanges
    assert [first.outcome, second.outcome] == ["Access-Accept", "Access-Reject"]
    assert second.reused_id_of is None  # the first had been answered: an ordinary reuse


def test_an_id_reused_long_after_is_a_new_exchange():
    t = Trace()
    t.request(1.0, 1)
    t.request(1.0 + rx.RETRANSMIT_WINDOW + 1, 1)
    first, second = t.analyse().exchanges
    assert first.retransmissions == second.retransmissions == 0
    assert second.retry_of is first  # same user, unanswered, within the retry window


def test_a_retry_under_a_new_id_is_linked():
    t = Trace()
    t.request(1.0, 1, cport=40000)
    t.request(7.0, 2, cport=40001)  # a new socket and ID, as many NASes do
    t.request(8.0, 3, cport=40002, user="erin")
    t.reply(8.1, 3, cport=40002)
    first, second, third = t.analyse().exchanges
    assert second.retry_of is first and third.retry_of is None


def test_a_new_login_after_a_reply_is_not_a_retry():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.1, 1, code=3)
    t.request(5.0, 2)
    assert t.analyse().exchanges[1].retry_of is None


def test_retries_are_per_server():
    t = Trace()
    t.request(1.0, 1)
    t.request(7.0, 2, server=OTHER_SERVER)  # failover to the next server is not a retry of the first
    assert t.analyse().exchanges[1].retry_of is None


def test_reply_from_another_address_is_paired_and_flagged():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.1, 1, server=OTHER_SERVER)
    e = only(t.analyse())
    assert e.answered and e.reply_from_elsewhere


def test_reply_with_no_request_in_the_capture():
    t = Trace()
    t.reply(1.0, 1)
    r = t.analyse()
    assert r.exchanges == [] and len(r.orphan_replies) == 1


def test_reply_of_the_wrong_kind_does_not_pair():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.1, 1, code=5)  # Accounting-Response cannot answer an Access-Request
    r = t.analyse()
    assert not r.exchanges[0].answered and len(r.orphan_replies) == 1


@pytest.mark.parametrize("sport,reply_code", [(1812, 2), (1813, 5)])
def test_status_server(sport, reply_code):
    t = Trace()
    t.request(1.0, 1, user=None, code=12, sport=sport)
    t.reply(1.001, 1, code=reply_code, sport=sport)
    e = only(t.analyse())
    assert e.name == "Status-Server" and e.answered


def test_icmp_port_unreachable_for_a_request():
    t = Trace()
    req = t.request(1.0, 1)
    t.raw(1.0005, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, req.payload), code=3))
    e = only(t.analyse())
    ((icmp, about),) = e.icmp
    assert about == "request" and icmp.icmp.reason == "port unreachable"


def test_icmp_about_a_reply_means_the_client_stopped_listening():
    t = Trace()
    t.request(1.0, 1)
    rep = t.reply(9.0, 1)
    t.raw(9.001, pb.icmp_unreachable(pb.udp(pb.SERVER, pb.CLIENT, 1812, 40000, rep.payload), code=3,
                                     sender=pb.CLIENT))
    e = only(t.analyse())
    assert [about for _, about in e.icmp] == ["reply"]


def test_icmp_matching_no_exchange_is_kept_as_stray():
    t = Trace()
    t.raw(1.0, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, pb.radius(1, 1)), code=13))
    t.raw(2.0, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 53, b"dns query")))
    r = t.analyse()
    assert len(r.stray_icmp) == 1 and r.stray_icmp[0].icmp.reason == "administratively prohibited"


def test_legacy_and_extra_ports():
    t = Trace()
    t.request(1.0, 1, sport=1645)
    t.reply(1.1, 1, sport=1645)
    t.request(2.0, 2, sport=11812)
    t.reply(2.1, 2, sport=11812)
    assert [e.server_port for e in t.analyse().exchanges] == [1645]
    with_extra = t.analyse(radius.DEFAULT_PORTS.with_extra({11812}))
    assert [e.server_port for e in with_extra.exchanges] == [1645, 11812]


def test_ipv6():
    t = Trace()
    t.request(1.0, 1, client=pb.CLIENT6, server=pb.SERVER6)
    t.reply(1.02, 1, client=pb.CLIENT6, server=pb.SERVER6)
    e = only(t.analyse())
    assert (e.client, e.server, e.answered) == (pb.CLIENT6, pb.SERVER6, True)


def test_a_cut_short_request_still_pairs():
    t = Trace()
    full = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, pb.radius(1, 4, [(1, "dave"), (32, "nas")]))
    t.packets.append(layers.decode(1, 1.0, layers.LINKTYPE_RAW, full[:28 + 22], cut=True))
    t.reply(1.1, 4)
    e = only(t.analyse())
    assert e.answered and not e.request.complete


def test_malformed_payloads_on_radius_ports_are_reported():
    t = Trace()
    t.raw(1.0, pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, b"GET / HTTP/1.1\r\n"))
    r = t.analyse()
    assert r.exchanges == [] and r.malformed[0].reason == "code 71 is not a RADIUS packet type"


def test_conversations_and_servers():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.010, 1)
    t.request(2.0, 2)
    t.reply(2.030, 2)
    for ts in (3.0, 5.0, 7.0):
        t.request(ts, 3, user="erin")
    t.request(4.0, 1, client=OTHER_CLIENT)
    t.reply(4.020, 1, client=OTHER_CLIENT)
    r = t.analyse()
    convs = {c.client: c for c in r.conversations()}
    nas = convs[pb.CLIENT]
    assert (nas.requests, nas.answered, nas.retransmissions) == (3, 2, 2)
    assert nas.outcomes == {"Access-Accept": 2, rx.NO_REPLY: 1}
    assert nas.response_times.count == 2 and nas.response_times.p50 == pytest.approx(0.010)
    (server,) = r.servers()
    assert (server.client, server.server, server.server_port, server.requests, server.answered) == \
        (None, pb.SERVER, 1812, 4, 3)
    assert server.response_times.max == pytest.approx(0.030)
