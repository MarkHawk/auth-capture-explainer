"""RADIUS findings and their likely causes, scenario by scenario.

Each test builds the traffic a real failure produces (a NAS resending into
silence, an ICMP error, a reject, a secret that verifies on one side only),
runs the checks and the causes, and looks at what a reader would be told.
"""

import pcapbuild as pb
import pytest
from radius_trace import LOOPBACK, OTHER_CLIENT, SERVER_SECRET, Trace, auth_for

from pcap_analyser import radius, runbooks
from pcap_analyser import radius_checks as rc
from pcap_analyser.causes import likely_causes
from pcap_analyser.findings import Status
from pcap_analyser.secret import Secret

WRONG_SECRET = b"sample-wrong-secret"
SERVER = f"{pb.SERVER}:1812"


def run(trace, secret=None, captured_on=None, **kw):
    findings = rc.check(trace.analyse(**kw), Secret(secret, "test") if secret else None, captured_on)
    return findings, likely_causes(findings)


def finding(findings, check_id, server=SERVER):
    matches = [f for f in findings if f.check_id == check_id and f.details.get("server", server) == server]
    assert len(matches) == 1, (check_id, [f.check_id for f in findings])
    return matches[0]


def has(findings, check_id, server=SERVER):
    return any(f.check_id == check_id and f.details.get("server", server) == server for f in findings)


def only_cause(causes):
    assert len(causes) == 1, [c.pattern for c in causes]
    return causes[0]


def nas_resends_into_silence(t, direction="in", secret=WRONG_SECRET, user="dave", ident=16, start=1.0):
    """A current NAS (it signs with Message-Authenticator) sending one login three times. secret=None
    makes an old NAS that does not sign."""
    for i in range(3):
        t.request(start + 2 * i, ident, user=user, direction=direction, secret=secret, password=b"pw" if secret else None)


# --- nothing to say, and the good path ---------------------------------------------

def test_no_radius_no_findings():
    t = Trace()
    t.raw(1.0, pb.udp(pb.CLIENT, pb.SERVER, 1, 53, b"dns"))
    assert run(t) == ([], [])


def test_a_clean_login():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"pw")
    t.reply(1.004, 1, secret=SERVER_SECRET)
    findings, causes = run(t)
    assert finding(findings, "radius.answering").status == Status.PASS
    assert finding(findings, "radius.message_authenticator").status == Status.PASS
    rt = finding(findings, "radius.response_time")
    assert rt.status == Status.PASS and rt.summary == f"{SERVER}: 1 replies, p50 4 ms, p95 4 ms, slowest 4 ms."
    skip = [f for f in findings if f.check_id == "radius.secret"]
    assert len(skip) == 1 and skip[0].status == Status.SKIP and "--secret-file" in skip[0].summary
    assert not has(findings, "radius.unanswered") and causes == []


def test_a_clean_login_with_the_right_secret():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"pw")
    t.reply(1.004, 1, secret=SERVER_SECRET)
    findings, causes = run(t, SERVER_SECRET)
    sec = finding(findings, "radius.secret")
    assert sec.status == Status.PASS and sec.details["server_match"] is True
    assert sec.summary.startswith("The secret you gave matches this server: Response Authenticator verifies on "
                                  "its Access-Accept and Message-Authenticator verifies on its Access-Accept.")
    assert "It matches the client 192.0.2.10 (NAS-Identifier \"nas\")" in sec.summary
    assert causes == []


# --- 05: the NAS resends into silence ---------------------------------------------------

def test_secret_mismatch_seen_on_the_server():
    """The identity-lab 05 shape: three identical requests arriving at the server, no reply, while the
    server's own loopback health checks are answered."""
    t = Trace()
    t.health_check(0.5, 9)
    nas_resends_into_silence(t, direction="in")
    t.health_check(5.5, 10)
    findings, causes = run(t, capture_end=6.0)
    un = finding(findings, "radius.unanswered")
    assert un.status == Status.FAIL
    assert un.summary == ('192.0.2.10 (NAS-Identifier "nas") sent an Access-Request for "dave" to 192.0.2.2:1812, '
                          "then resent it twice over 4.0 s (ID 16, same authenticator). None of the 3 attempts got "
                          "a reply. No ICMP error came back.")
    point = finding(findings, "radius.capture_point")
    assert point.details["where"] == "server" and point.details["loopback_answering"]
    assert "a firewall in between is ruled out" in point.summary
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed, cause.runbook) == (
        "radius-secret-mismatch", False, runbooks.RADIUS_SECRET_MISMATCH)
    assert cause.server == SERVER
    assert cause.summary.startswith("The server receives 192.0.2.10's requests and stays silent, while it answers "
                                    "others, which is how a RADIUS server treats requests it cannot authenticate")
    assert "unknown client" in cause.summary
    assert cause.evidence[0] == ("For a secret mismatch: the request was resent twice and never answered; no ICMP "
                                 "error came back; this host answers RADIUS on its loopback address meanwhile.")
    assert cause.evidence[1] == "Against a firewall: the requests were seen arriving at the server."
    assert "Shared secret is incorrect" in cause.first_step


def test_secret_mismatch_confirmed_with_the_servers_secret():
    """With the server's secret: the loopback replies verify, the NAS's requests do not."""
    t = Trace()
    t.health_check(0.5, 9, secret=SERVER_SECRET)
    nas_resends_into_silence(t, direction="in", secret=WRONG_SECRET)
    findings, causes = run(t, SERVER_SECRET, capture_end=6.0)
    sec = finding(findings, "radius.secret")
    assert sec.status == Status.FAIL and sec.details["client_match"] == {pb.CLIENT: False}
    # The three attempts are identical, so the request is checked once.
    assert sec.summary.endswith("It does not match the client 192.0.2.10 (NAS-Identifier \"nas\"): "
                                "Message-Authenticator fails on its Access-Request, and its User-Password decodes to "
                                "unprintable bytes.")
    local = finding(findings, "radius.secret", f"{LOOPBACK}:1812")
    assert local.status == Status.PASS and local.details["server_match"] is True
    cause = only_cause(causes)
    assert (cause.pattern, cause.label) == ("radius-secret-mismatch", "shared secret mismatch")
    assert "drops them without replying" in cause.summary
    assert any("verifies with the secret you gave, so it is most likely this server's secret" in e
               for e in cause.evidence)


def test_given_the_nas_secret_the_servers_loopback_traffic_disagrees():
    t = Trace()
    t.health_check(0.5, 9, secret=SERVER_SECRET)
    nas_resends_into_silence(t, direction="in", secret=WRONG_SECRET)
    findings, causes = run(t, WRONG_SECRET, capture_end=6.0)
    cause = only_cause(causes)
    assert (cause.pattern, cause.label) == ("radius-secret-mismatch", "shared secret mismatch, most likely")
    assert "The secret you gave looks like the NAS's" in cause.summary


def test_secret_ruled_out_points_at_the_client_list():
    t = Trace()
    nas_resends_into_silence(t, direction="in", secret=SERVER_SECRET)
    findings, causes = run(t, SERVER_SECRET, capture_end=6.0)
    cause = only_cause(causes)
    assert cause.pattern == "radius-unanswered-secret-ok"
    assert "unknown client" in cause.first_step


def test_seen_from_the_nas_with_a_silent_server_cannot_tell():
    t = Trace()
    nas_resends_into_silence(t, direction="out")
    findings, causes = run(t, capture_end=6.0)
    assert finding(findings, "radius.capture_point").details["where"] == "client"
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("radius-no-reply", False)
    assert "Seen from the client" in cause.summary and "a firewall or routing" in cause.summary
    assert cause.evidence[-1] == "To tell them apart: capture on the RADIUS server itself, or check its log."


def test_no_direction_but_the_server_answers_another_nas():
    t = Trace()
    t.request(0.5, 1, client=OTHER_CLIENT, user="erin")
    t.reply(0.51, 1, client=OTHER_CLIENT)
    nas_resends_into_silence(t, direction=None)
    findings, causes = run(t, capture_end=6.0)
    assert finding(findings, "radius.capture_point").details["where"] is None
    cause = only_cause(causes)
    assert cause.pattern == "radius-secret-mismatch"
    assert cause.summary.startswith("The server answers other clients but not 192.0.2.10")
    assert "198.51.100.20" in cause.evidence[0]
    assert cause.evidence[1].startswith("Against a firewall, partly")


def test_no_direction_and_nothing_answered():
    t = Trace()
    nas_resends_into_silence(t, direction=None)
    findings, causes = run(t, capture_end=6.0)
    assert "--captured-on" in finding(findings, "radius.capture_point").summary
    cause = only_cause(causes)
    assert cause.pattern == "radius-no-reply" and "where this capture was taken" in cause.summary


def test_the_user_can_say_where_the_capture_was_taken():
    t = Trace()
    nas_resends_into_silence(t, direction=None)
    findings, causes = run(t, captured_on="server", capture_end=6.0)
    assert finding(findings, "radius.capture_point").summary == "You said the capture was taken on the server."
    assert only_cause(causes).pattern == "radius-secret-mismatch"


def test_a_capture_on_a_router_sees_each_request_twice():
    t = Trace()
    for ts in (1.0, 3.0):
        t.request(ts, 5, direction="in")
        t.request(ts + 0.0001, 5, direction="out")
    findings, _ = run(t, capture_end=4.0)
    assert finding(findings, "radius.capture_point").details["where"] == "path"


# --- other reasons for no reply ------------------------------------------------------------

def test_port_unreachable():
    t = Trace()
    req = t.request(1.0, 1)
    t.raw(1.001, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, req.payload), code=3))
    findings, causes = run(t)
    icmp = finding(findings, "radius.icmp")
    assert icmp.status == Status.FAIL
    assert icmp.summary == ("Requests to 192.0.2.2:1812 drew ICMP port unreachable once, from the server itself: "
                            "nothing is listening on that UDP port there.")
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("radius-port-closed", True)
    assert "1645" in cause.summary


def test_a_firewall_refuses():
    t = Trace()
    req = t.request(1.0, 1)
    t.raw(1.001, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, req.payload), code=13,
                                     sender="198.51.100.1"))
    findings, causes = run(t)
    assert "(not the server: a router or firewall on the way)" in finding(findings, "radius.icmp").summary
    cause = only_cause(causes)
    assert cause.pattern == "radius-firewall" and "198.51.100.1" in cause.summary
    assert cause.first_step.startswith("Allow UDP 1812 from the NAS")


def test_host_unreachable():
    t = Trace()
    req = t.request(1.0, 1)
    t.raw(1.001, pb.icmp_unreachable(pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, req.payload), code=1,
                                     sender="198.51.100.1"))
    assert only_cause(run(t)[1]).pattern == "radius-unreachable"


def test_replies_from_the_wrong_address():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1, src="192.0.2.3")
    findings, causes = run(t)
    assert finding(findings, "radius.reply_from_elsewhere").status == Status.WARN
    cause = only_cause(causes)
    assert cause.pattern == "radius-reply-wrong-address" and "192.0.2.3:1812" in cause.summary


def test_an_old_nas_without_message_authenticator():
    t = Trace()
    nas_resends_into_silence(t, direction="in", secret=None)
    findings, causes = run(t, capture_end=6.0)
    ma = finding(findings, "radius.message_authenticator")
    assert ma.status == Status.WARN and "CVE-2024-3596" in ma.summary
    cause = only_cause(causes)
    assert cause.pattern == "radius-no-message-authenticator"


def test_signed_requests_into_silence_are_not_blamed_on_message_authenticator():
    t = Trace()
    nas_resends_into_silence(t, direction="in", secret=WRONG_SECRET)
    findings, causes = run(t, capture_end=6.0)
    assert finding(findings, "radius.message_authenticator").status == Status.PASS
    assert only_cause(causes).pattern == "radius-secret-mismatch"


# --- rejects ---------------------------------------------------------------------------

def test_a_reject_without_the_secret():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"wrong")
    t.reply(2.0, 1, code=3, attrs=[(18, "Password incorrect")], secret=SERVER_SECRET)
    findings, causes = run(t)
    rej = finding(findings, "radius.rejects")
    assert rej.summary == '192.0.2.2:1812 rejected 1 Access-Request for "dave". Reply-Message: "Password incorrect".'
    rt = finding(findings, "radius.response_time")
    assert rt.status == Status.INFO and "after 1.0 s" in rt.summary and "delay rejects on purpose" in rt.summary
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed, cause.runbook) == ("radius-user-rejected", False, None)
    assert cause.summary == ('The server rejected the login for "dave" with "Password incorrect". A reject is '
                             "usually about the user's password or account.")
    assert cause.evidence[-1].startswith("Not checked: the secret")


def test_a_reject_that_verifies_is_genuine():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"wrong")
    t.reply(2.0, 1, code=3, secret=SERVER_SECRET)
    cause = only_cause(run(t, SERVER_SECRET)[1])
    assert cause.pattern == "radius-user-rejected" and cause.confirmed
    assert "genuine answer from the server" in cause.summary


def test_everyone_rejected_through_one_nas_raises_the_secret():
    t = Trace()
    for i, user in enumerate(("dave", "erin", "frank")):
        t.request(1.0 + i, i, user=user)
        t.reply(2.0 + i, i, code=3)
    cause = only_cause(run(t)[1])
    assert cause.pattern == "radius-user-rejected" and cause.runbook == runbooks.RADIUS_SECRET_MISMATCH
    assert "every login through 192.0.2.10 is rejected" in cause.summary


def test_a_legacy_server_with_a_different_secret_rejects_everyone():
    """Runbook 05, step 3: the NAS uses the secret given; the server's rejects are made with another."""
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"right")
    t.reply(2.0, 1, code=3, secret=WRONG_SECRET)
    findings, causes = run(t, SERVER_SECRET)
    sec = finding(findings, "radius.secret")
    assert sec.details["server_match"] is False and sec.details["reject_fails"]
    assert sec.summary.startswith("The secret you gave does not match this server")
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("radius-secret-mismatch", True)
    assert "Its Access-Rejects are not about the users' passwords" in cause.summary


def test_a_secret_that_matches_neither_side():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"pw")
    t.reply(1.01, 1, secret=SERVER_SECRET)
    cause = only_cause(run(t, WRONG_SECRET)[1])
    assert (cause.pattern, cause.label) == ("radius-secret-unknown", "the secret given matches neither side")


# --- timing and other remarks ---------------------------------------------------------------

def test_a_slow_server():
    t = Trace()
    for i in range(4):
        t.request(10.0 * i, i, user=f"u{i}")
        t.reply(10.0 * i + 1.5, i)
    findings, causes = run(t)
    rt = finding(findings, "radius.response_time")
    assert rt.status == Status.WARN and "That is slow" in rt.summary
    cause = only_cause(causes)
    assert cause.pattern == "radius-slow" and "p95 1.5 s" in cause.summary


def test_replies_after_a_resend_are_late():
    t = Trace()
    t.request(1.0, 1)
    t.request(3.0, 1)
    t.reply(3.2, 1)
    rt = finding(run(t)[0], "radius.response_time")
    assert rt.status == Status.WARN and "came only after the client had resent" in rt.summary


def test_a_request_just_before_the_end_is_not_unanswered():
    t = Trace()
    t.request(1.0, 1)
    findings, causes = run(t, capture_end=2.0)
    late = finding(findings, "radius.capture_ended")
    assert late.status == Status.INFO and "the default, as nothing in the capture was resent" in late.summary
    assert not has(findings, "radius.unanswered") and causes == []


def test_reused_ids_and_legacy_ports_are_remarked_on():
    t = Trace()
    t.request(1.0, 7, sport=1645, auth=auth_for(1))
    t.request(1.5, 7, sport=1645, auth=auth_for(2), user="erin")
    t.reply(1.6, 7, sport=1645)
    findings, _ = run(t)
    server = f"{pb.SERVER}:1645"
    assert finding(findings, "radius.reused_ids", server).status == Status.WARN
    assert finding(findings, "radius.legacy_port", server).status == Status.INFO
    assert finding(findings, "radius.answering", server).summary.startswith(
        "192.0.2.2:1645 (legacy authentication port) answered 1 of 2 requests")


def test_challenges_malformed_and_orphans():
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1, code=11)
    t.reply(2.0, 99)
    t.raw(3.0, pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, b"\x01\x02"))
    findings, _ = run(t)
    assert finding(findings, "radius.challenges").status == Status.INFO
    assert finding(findings, "radius.malformed").summary.startswith(
        "1 packet on RADIUS ports could not be read as RADIUS (first at frame 4")
    assert finding(findings, "radius.orphan_replies").status == Status.INFO


def test_whitespace_in_the_secret_is_mentioned_without_the_value():
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET)
    t.reply(1.01, 1, secret=SERVER_SECRET)
    findings, _ = run(t, b" spaced ")
    notes = [f.summary for f in findings if f.check_id == "radius.secret_shape"]
    assert len(notes) == 2 and all("spaced" not in n for n in notes)


def test_two_servers_two_causes_and_loopback_only_when_alone():
    t = Trace()
    t.health_check(0.5, 1)
    nas_resends_into_silence(t, direction=None)
    t.request(1.0, 1, server="198.51.100.2", user="erin")
    t.reply(2.0, 1, server="198.51.100.2", code=3)
    causes = run(t, capture_end=6.0)[1]
    assert [c.server for c in causes] == [SERVER, "198.51.100.2:1812"]
    alone = Trace()
    alone.health_check(0.5, 1)
    alone.request(1.0, 2, user=None, code=12, client=LOOPBACK, server=LOOPBACK, nas=None)
    alone.request(3.0, 2, user=None, code=12, client=LOOPBACK, server=LOOPBACK, nas=None)
    assert [c.server for c in run(alone, capture_end=4.0)[1]] == [f"{LOOPBACK}:1812"]


@pytest.mark.parametrize("scenario", ["mismatch", "reject", "neither"])
def test_no_report_text_contains_the_secret(scenario):
    canary = b"canary-secret-value"
    t = Trace()
    t.health_check(0.5, 1, secret=canary)
    t.request(1.0, 2, secret=canary if scenario != "mismatch" else WRONG_SECRET, password=b"pw", direction="in")
    if scenario == "reject":
        t.reply(2.0, 2, code=3, secret=canary)
    findings, causes = run(t, canary if scenario != "neither" else WRONG_SECRET, capture_end=10.0)
    text = " ".join([f.summary for f in findings] + [repr(f.details) for f in findings]
                    + [c.summary + " ".join(c.evidence) + c.first_step for c in causes])
    assert "canary" not in text and WRONG_SECRET.decode() not in text


def test_ports_given_by_the_user_are_checked_and_labelled():
    t = Trace()
    t.request(1.0, 1, sport=11812)
    t.reply(1.01, 1, sport=11812)
    findings = rc.check(t.analyse(radius.DEFAULT_PORTS.with_extra({11812})))
    assert finding(findings, "radius.answering", f"{pb.SERVER}:11812").summary.startswith(
        "192.0.2.2:11812 (non-standard port) answered")
