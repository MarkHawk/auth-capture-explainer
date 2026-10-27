"""Local cross-check against the raw captures from the session 1 spike.

scratch/spike/ is gitignored and exists only on the machine that ran the
spike, so these tests are skipped everywhere else, CI included. The RADIUS
spike captures are keyed with the lab's real shared secret, so nothing here
compares or prints authenticators, User-Password or Message-Authenticator
values: the assertions are about structure only (codes, IDs, counts,
timings), and anything secret-derived is reduced to a boolean before it
reaches an assert, so a failure message cannot show it.

These go once the sanitised lab captures exist (session 7).
"""

import pytest

from conftest import ROOT
from pcap_analyser import radius_exchange as rx
from pcap_analyser.capture import read_capture

SPIKE = ROOT / "scratch" / "spike"

pytestmark = pytest.mark.skipif(not SPIKE.is_dir(), reason="no local spike captures (scratch/spike)")


def analyse(name):
    cap = read_capture(SPIKE / name)
    assert not cap.malformed and not cap.notes
    return rx.analyse(cap.packets, capture_end=cap.last_ts)


def by_name(result, name):
    return [e for e in result.exchanges if e.name == name]


def test_reject_capture():
    r = analyse("radius-reject-spike.pcap")
    assert not r.malformed and not r.orphan_replies and not r.stray_icmp
    (login,) = by_name(r, "Access-Request")
    assert (login.outcome, login.retransmissions, login.user_name) == ("Access-Reject", 0, "dave")
    assert login.request.complete and login.reply.complete
    # FreeRADIUS's deliberate reject delay: one second, which must not count as a slow reply.
    assert 0.9 < login.response_time < 1.2
    assert [a.name for a in login.request.attributes] == [
        "Message-Authenticator", "User-Name", "User-Password", "NAS-Identifier"]
    shown = " ".join(a.display() for a in login.request.attributes + login.reply.attributes)
    assert "(hidden, " in shown and "(present, value hidden)" in shown
    health = by_name(r, "Status-Server")
    assert health and all(e.outcome == "Access-Accept" and e.client == "127.0.0.1" for e in health)
    nas = next(c for c in r.servers() if c.server != "127.0.0.1")
    assert nas.response_times.count == 0 and nas.reject_times.count == 1


def test_secret_mismatch_capture():
    r = analyse("radius-05-spike.pcap")
    (login,) = by_name(r, "Access-Request")
    assert (login.outcome, login.retransmissions, login.reused_id_of) == (rx.NO_REPLY, 2, None)
    assert 1.9 < login.reply_window < 2.1 and login.reply_window_source == rx.WINDOW_FROM_CLIENT
    assert 3.5 < login.span < 4.5  # radclient: three attempts two seconds apart
    identical = all(a.raw == login.request.raw for a in login.attempts)
    assert identical
    assert all(a.packet.direction == "in" for a in login.attempts)  # captured on the server
    assert all(e.answered for e in by_name(r, "Status-Server"))


def test_real_nas_packets_verify_with_the_public_break_value():
    """During the 05 break the NAS signs with "not-the-radius-secret", a value published in
    identity-lab's scenario script, so checking with it reveals nothing about the lab's real secret."""
    from pcap_analyser import radius_auth

    r = analyse("radius-05-spike.pcap")
    (login,) = by_name(r, "Access-Request")
    right = [(c.method, c.ok) for c in radius_auth.check_request(login.request, b"not-the-radius-secret")]
    wrong = [(c.method, c.ok) for c in radius_auth.check_request(login.request, b"some-other-value")]
    assert right == [("Message-Authenticator", True), ("User-Password", True)]
    assert wrong == [("Message-Authenticator", False), ("User-Password", False)]


def test_likely_causes_on_real_traffic():
    from pcap_analyser import radius_checks
    from pcap_analyser.causes import likely_causes

    (broken,) = likely_causes(radius_checks.check(analyse("radius-05-spike.pcap")))
    assert (broken.pattern, broken.confirmed, broken.runbook) == (
        "radius-secret-mismatch", False, "05-radius-shared-secret-mismatch")
    assert "Against a firewall: the requests were seen arriving at the server." in broken.evidence
    (rejected,) = likely_causes(radius_checks.check(analyse("radius-reject-spike.pcap")))
    assert rejected.pattern == "radius-user-rejected"


def test_ldap_through_the_relay():
    """The LDAP spike: three connections through the capture relay to the lab's directory."""
    from pcap_analyser import ldap_exchange

    cap = read_capture(SPIKE / "ldap-spike.pcap")
    conns = ldap_exchange.analyse(cap.packets).connections
    assert [c.kind for c in conns] == ["ldap"] * 3
    assert all(c.stream.syn_seen and not c.problems and not c.gaps for c in conns)
    binds = [c.operations[0] for c in conns]
    assert [(b.request.dn, b.result.result_code) for b in binds] == [
        ("cn=keycloak-svc,ou=services,dc=idlab,dc=example", 49),  # identity-lab 04's wrong bind value
        ("", 0),  # anonymous, before the base search
        ("cn=nobody,ou=services,dc=idlab,dc=example", 49),  # OpenLDAP answers 49 for a missing DN too
    ]
    assert binds[0].request.password_length == len("not-the-bind-password")
    search = conns[1].operations[1]
    assert (search.request.scope, search.request.filter, search.entries, search.result.result_code) == (
        "base", "(objectclass=*)", 1, 0)
    assert all(c.operations[-1].name == "UnbindRequest" for c in conns)


def test_ldap_likely_cause_on_real_traffic():
    from pcap_analyser import ldap_checks, ldap_exchange
    from pcap_analyser.causes import likely_causes

    cap = read_capture(SPIKE / "ldap-spike.pcap")
    (cause,) = likely_causes(ldap_checks.check(ldap_exchange.analyse(cap.packets), capture_end=cap.last_ts))
    assert (cause.pattern, cause.runbook, cause.confirmed) == (
        "ldap-service-bind-failed", "04-ldap-bind-failure", False)  # the role rests on the DN's wording here
    assert "cn=keycloak-svc,ou=services,dc=idlab,dc=example" in cause.summary
