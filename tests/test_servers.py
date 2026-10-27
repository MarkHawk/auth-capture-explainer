"""Per-server summaries across clients, and the slow-server finding."""

import ldap_build as lb
from ldap_build import Conversation
from radius_trace import OTHER_CLIENT, Trace

from pcap_analyser import ldap_exchange, servers
from pcap_analyser.findings import Status


def test_radius_server_summary_leaves_rejects_out_and_counts_no_reply():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1)
    t.request(2.0, 2, client=OTHER_CLIENT)
    t.reply(3.0, 2, client=OTHER_CLIENT, code=3)
    for ts in (4.0, 6.0, 8.0):
        t.request(ts, 3, user="erin")
    (s,) = servers.summaries(t.analyse())
    assert (s.protocol, s.server, s.label, s.clients, s.requests, s.unanswered) == (
        "radius", "192.0.2.2:1812", "192.0.2.2:1812", 2, 3, 1)
    assert s.times.count == 1 and abs(s.times.max - 0.01) < 1e-9 and not s.slow


def test_ldap_server_summary_and_a_server_slow_for_everyone():
    convs = []
    for i, client in enumerate(("192.0.2.10", "198.51.100.20")):
        c = Conversation(client=client, cport=40000 + i).handshake(1.0)
        c.client_says(1.1, lb.bind_request(1, "cn=a", "x"))
        c.server_says(3.1, lb.bind_response(1, 0))
        c.client_says(3.2, lb.unbind(2))
        convs.append(c)
    result = ldap_exchange.analyse(convs[0].numbered() + convs[1].numbered(start=100))
    (s,) = servers.summaries(ldap_result=result)
    assert (s.protocol, s.label, s.clients, s.requests, s.unanswered, s.slow) == (
        "ldap", "192.0.2.2:389", 2, 2, 0, True)  # unbinds expect nothing and are not counted
    (f,) = servers.check([s])
    assert f.status == Status.WARN and f.summary.startswith("192.0.2.2:389 (LDAP) is slow for all its 2 clients")


def test_a_slow_server_with_one_client_is_left_to_the_pair_finding():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, "cn=a", "x"))
    c.server_says(3.1, lb.bind_response(1, 0))
    (s,) = servers.summaries(ldap_result=ldap_exchange.analyse(c.numbered()))
    assert s.slow and servers.check([s]) == []
