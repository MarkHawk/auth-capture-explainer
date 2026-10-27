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
