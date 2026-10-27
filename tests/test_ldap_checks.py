"""LDAP findings and their likely causes, scenario by scenario.

Each test builds the traffic a real failure produces (a service account
that cannot bind, one user's wrong password, signing enforcement, a TLS
handshake that stops short) and looks at what a reader would be told.
"""

import ldap_build as lb
import pcapbuild as pb
import pytest
from ldap_build import Conversation
from pcap_analyser import ldap_checks as lc
from pcap_analyser import ldap_exchange as lx
from pcap_analyser import runbooks
from pcap_analyser.causes import likely_causes
from pcap_analyser.findings import Status

SVC = "cn=keycloak-svc,ou=services,dc=idlab,dc=example"
APP = "cn=portal,ou=apps,dc=example"
DAVE = "uid=dave,ou=people,dc=idlab,dc=example"
PLAIN = "cn=thing,dc=example"  # a DN that says nothing about its role
AD = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {}, v4563"
PASSWORD = "canary-password"


def run(*conversations, **kw):
    packets = []
    for i, c in enumerate(conversations):
        packets += c.numbered(start=1 + 1000 * i)
    end = max(p.ts for p in packets)
    findings = lc.check(lx.analyse(packets, kw.pop("ports", lx.DEFAULT_PORTS)), capture_end=end + 60, **kw)
    return findings, likely_causes(findings)


def finding(findings, check_id):
    matches = [f for f in findings if f.check_id == check_id]
    assert len(matches) == 1, (check_id, [f.check_id for f in findings])
    return matches[0]


def ids(findings):
    return [f.check_id for f in findings]


def only_cause(causes):
    assert len(causes) == 1, [c.pattern for c in causes]
    return causes[0]


def bind(c, ts, ident, dn, code, diagnostic="", password=PASSWORD):
    c.client_says(ts, lb.bind_request(ident, dn, password))
    c.server_says(ts + 0.005, lb.bind_response(ident, code, diagnostic=diagnostic))


def search(c, ts, ident, base, flt, entries=(), code=0, diagnostic="", matched=""):
    c.client_says(ts, lb.search_request(ident, base, flt))
    for i, dn in enumerate(entries):
        c.server_says(ts + 0.001 * (i + 1), lb.search_entry(ident, dn, [("cn", ["x"])]))
    c.server_says(ts + 0.01, lb.message(ident, lb.app(5, lb.result(code, matched, diagnostic))))


# --- binds and their roles ----------------------------------------------------------------------

def test_identity_lab_04_the_service_account_cannot_bind():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 49)
    c.client_says(1.2, lb.unbind(2))
    findings, causes = run(c)
    f = finding(findings, "ldap.bind_failed")
    assert f.summary == (f"192.0.2.10 tried a bind as {SVC} on 192.0.2.2:389: resultCode 49 invalidCredentials "
                         "(wrong password, or a DN that does not exist or cannot bind). The directory gave no "
                         "diagnosticMessage. This is a service account, probably: its name suggests one "
                         "(\"services\"), though nothing in the capture shows how it was used.")
    assert (f.details["role"], f.details["role_certain"]) == ("service", False)
    cause = only_cause(causes)
    assert (cause.pattern, cause.runbook, cause.confirmed) == ("ldap-service-bind-failed", runbooks.LDAP_BIND_FAILURE,
                                                               False)
    assert "every directory login fails, whatever password the user types" in cause.summary
    assert any("OpenLDAP answers 49 for both" in e for e in cause.evidence)
    assert cause.client == "192.0.2.10" and cause.server == "192.0.2.2:389"


def test_naming_it_settles_the_role():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, PLAIN, 49)
    findings, causes = run(c, service_dns=["CN=Thing, DC=Example"])
    assert finding(findings, "ldap.bind_failed").details["role_reason"] == "you named it as a service account"
    assert only_cause(causes).confirmed


def test_behaviour_on_another_connection_makes_it_a_service_account():
    """The same DN bound and searched earlier (before its password was rotated)."""
    ok = Conversation(cport=40001).handshake(1.0)
    bind(ok, 1.1, 1, PLAIN, 0)
    search(ok, 1.2, 2, "dc=example", lb.f_eq("uid", "dave"), [DAVE])
    bad = Conversation(cport=40002).handshake(5.0)
    bind(bad, 5.1, 1, PLAIN, 49)
    findings, causes = run(ok, bad)
    f = finding(findings, "ldap.bind_failed")
    assert (f.details["role"], f.details["role_certain"]) == ("service", True)
    assert "followed by searches on the same connection" in f.details["role_reason"]
    assert only_cause(causes).pattern == "ldap-service-bind-failed" and only_cause(causes).confirmed


def test_one_users_wrong_password_on_active_directory():
    """The service account works and finds the user; the user's own bind fails with data 52e."""
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, APP, 0)
    search(c, 1.2, 2, "dc=example", lb.f_eq("sAMAccountName", "dave"), [DAVE])
    bind(c, 1.3, 3, DAVE, 49, AD.format("52e"))
    findings, causes = run(c)
    f = finding(findings, "ldap.bind_failed")
    assert "Active Directory reason: data 52e, invalid credentials: the password is wrong (the account exists)." \
        in f.summary
    assert (f.details["role"], f.details["role_certain"], f.details["ad_data"]) == ("user", True, "52e")
    assert finding(findings, "ldap.binds").status == Status.PASS
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("ldap-user-bind-failed", True)
    assert "not an outage" in cause.summary and "the password stored in the application" in cause.summary
    assert "earlier search returned this DN" in cause.evidence[0]


def test_a_locked_out_service_account():
    c = Conversation().handshake(1.0)
    for i in range(3):
        bind(c, 1.1 + i, i + 1, SVC, 49, AD.format("775"))
    findings, causes = run(c, service_dns=[SVC])
    assert "3 attempts, all with this result." in finding(findings, "ldap.bind_failed").summary
    cause = only_cause(causes)
    assert "locked out, often by the application itself" in cause.summary
    assert cause.first_step.startswith("Fix the password stored in the application first, then unlock")


def test_an_unknown_role_asks_for_service_dn():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, PLAIN, 49)
    cause = only_cause(run(c)[1])
    assert cause.pattern == "ldap-bind-failed" and "--service-dn" in cause.first_step


def test_service_bind_then_user_search_then_bind_as_the_returned_dn():
    """The usual login: the service account binds and searches, the search returns the user, the application
    binds as that DN. Bind-then-search makes the first a service account even though a search also returns its
    own entry (here, a group lookup that lists it); appearing in results makes the second a user."""
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, PLAIN, 0)
    search(c, 1.2, 2, "dc=example", lb.f_eq("uid", "dave"), [DAVE])
    search(c, 1.3, 3, "dc=example", lb.f_eq("member", PLAIN), [PLAIN])
    bind(c, 1.4, 4, DAVE, 49)
    result = lx.analyse(c.numbered())
    service, user = lc.bind_role(PLAIN, result), lc.bind_role(DAVE, result)
    assert (service.role, service.certain) == ("service", True)
    assert "followed by searches on the same connection" in service.reason
    assert (user.role, user.certain) == ("user", True) and "an earlier search returned this DN" in user.reason
    assert only_cause(run(c)[1]).pattern == "ldap-user-bind-failed"


def test_bind_then_search_wins_over_appearing_in_search_results():
    """A DN that a search returns, but that also binds and then searches, is a service account."""
    finder = Conversation(cport=40001).handshake(1.0)
    bind(finder, 1.1, 1, APP, 0)
    search(finder, 1.2, 2, "dc=example", lb.f_present("objectClass"), [PLAIN])
    worker = Conversation(cport=40002).handshake(2.0)
    bind(worker, 2.1, 1, PLAIN, 0)
    search(worker, 2.2, 2, "dc=example", lb.f_eq("uid", "erin"))
    result = lx.analyse(finder.numbered() + worker.numbered(start=100))
    assert lc.bind_role(PLAIN, result).role == "service"


def test_upn_and_down_level_names_are_read_for_hints():
    from pcap_analyser.ldap_exchange import Result
    empty = Result(lx.DEFAULT_PORTS)
    assert lc.bind_role("svc-portal@corp.example", empty).role == "service"
    assert lc.bind_role("CORP\\svc_portal", empty).role == "service"
    assert lc.bind_role("CN=Dave Dawson,OU=Users,DC=corp,DC=example", empty).role == "user"
    assert lc.bind_role("dave@corp.example", empty).role is None


# --- change 4: unauthenticated binds and signing enforcement ---------------------------------------

def test_an_accepted_unauthenticated_bind():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, DAVE, 0, password="")
    findings, causes = run(c)
    f = finding(findings, "ldap.unauthenticated_bind")
    assert f.status == Status.FAIL and "RFC 4513, section 5.1.2" in f.summary and "the directory accepted it" in f.summary
    assert "ldap.binds" not in ids(findings)  # not counted as a good bind
    assert only_cause(causes).pattern == "ldap-unauthenticated-bind"


def test_an_unauthenticated_bind_outranks_and_explains_what_follows_it():
    """An empty-password bind accepted, then a search refused for lack of rights: the bind is the cause."""
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, DAVE, 0, password="")
    search(c, 1.2, 2, "ou=people,dc=example", lb.f_eq("uid", "dave"), code=50)
    search(c, 1.3, 3, "ou=people,dc=example", lb.f_eq("uid", "erin"))
    findings, causes = run(c)
    assert finding(findings, "ldap.unauthenticated_bind").details["followed_by"] == [
        "a SearchRequest that failed with 50 insufficientAccessRights", "a search for (uid=erin) that found nothing"]
    assert "ldap.search_failed" in ids(findings) and "ldap.search_empty" in ids(findings)
    cause = only_cause(causes)
    assert cause.pattern == "ldap-unauthenticated-bind"
    assert ("followed on the same connection by a SearchRequest that failed with 50 insufficientAccessRights, and "
            "a search for (uid=erin) that found nothing: an unauthenticated bind carries only anonymous rights"
            ) in cause.summary


def test_a_refused_unauthenticated_bind_is_flagged_but_not_a_bind_failure():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, DAVE, 53, "unauthenticated bind (DN with no password) disallowed", password="")
    findings, causes = run(c)
    f = finding(findings, "ldap.unauthenticated_bind")
    assert f.status == Status.WARN and "refused it (53 unwillingToPerform), as it should" in f.summary
    assert "ldap.bind_failed" not in ids(findings) and causes == []


def test_an_anonymous_bind_is_not_unauthenticated():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, "", 0, password="")
    assert "ldap.unauthenticated_bind" not in ids(run(c)[0])


def test_result_8_on_a_simple_bind_is_signing_enforcement():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 8, "00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on "
                            "integrity checking if SSL\\TLS are not already active on the connection, data 0, v4563")
    findings, causes = run(c)
    assert finding(findings, "ldap.bind_failed").details["signing_required"]
    cause = only_cause(causes)
    assert (cause.pattern, cause.label, cause.confirmed) == (
        "ldap-signing-required", "LDAP signing or channel binding enforcement", False)
    assert "LDAP signing enforcement" in cause.summary and "channel binding" in cause.summary
    assert "00002028 says binds must be signed" in cause.evidence[0]
    assert "2887 and 2889" in cause.evidence[1]


def test_result_8_without_an_active_directory_message():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 8)
    assert only_cause(run(c)[1]).pattern == "ldap-signing-required"


def test_channel_binding_rejected():
    c = Conversation(sport=636).handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, SVC, "x"))
    c.server_says(1.2, lb.bind_response(1, 49, diagnostic="80090346: LdapErr: DSID-0C09058A, comment: "
                                                         "AcceptSecurityContext error, data 80090346, v4563"))
    cause = only_cause(run(c, service_dns=[SVC])[1])
    assert cause.pattern == "ldap-channel-binding" and "TLS-inspecting proxy" in cause.summary


def test_confidentiality_required():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 13, "confidentiality required")
    assert only_cause(run(c)[1]).pattern == "ldap-tls-required"


# --- searches and other results --------------------------------------------------------------

def test_a_base_dn_that_does_not_exist():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, APP, 0)
    search(c, 1.2, 2, "ou=staff,dc=example", lb.f_eq("uid", "dave"), code=32, matched="dc=example")
    findings, causes = run(c)
    f = finding(findings, "ldap.search_failed")
    assert "32 noSuchObject (the DN does not exist)" in f.summary and "closest existing entry is dc=example" in f.summary
    cause = only_cause(causes)
    assert cause.pattern == "ldap-dn-not-found" and "the search base ou=staff,dc=example" in cause.summary


def test_insufficient_access():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, APP, 0)
    search(c, 1.2, 2, "dc=example", lb.f_eq("uid", "dave"), code=50)
    assert only_cause(run(c)[1]).pattern == "ldap-insufficient-access"


def test_a_search_without_a_bind_on_active_directory():
    c = Conversation().handshake(1.0)
    search(c, 1.1, 1, "dc=corp,dc=example", lb.f_eq("sAMAccountName", "dave"), code=1,
           diagnostic="000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful "
                      "bind must be completed on the connection., data 0, v4563")
    findings, causes = run(c)
    assert "a successful bind is needed before this operation" in finding(findings, "ldap.search_failed").summary
    assert only_cause(causes).pattern == "ldap-bind-needed"


def test_a_user_lookup_that_finds_nothing():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, APP, 0)
    search(c, 1.2, 2, "ou=people,dc=example", lb.f_eq("uid", "nobody"))
    findings, causes = run(c)
    f = finding(findings, "ldap.search_empty")
    assert f.status == Status.WARN and "(uid=nobody) under ou=people,dc=example" in f.summary
    assert only_cause(causes).pattern == "ldap-user-not-found"


def test_an_empty_search_that_is_not_a_user_lookup_is_only_noted():
    c = Conversation().handshake(1.0)
    search(c, 1.1, 1, "dc=example", lb.f_present("memberOf"))
    findings, causes = run(c)
    assert finding(findings, "ldap.search_empty").status == Status.INFO and causes == []


def test_size_limit_and_referrals():
    c = Conversation().handshake(1.0)
    search(c, 1.1, 1, "dc=example", lb.f_eq("cn", "smith"), [DAVE], code=4)
    search(c, 1.2, 2, "dc=example", lb.f_present("cn"), code=10)
    findings, _ = run(c)
    assert finding(findings, "ldap.search_limited").status == Status.WARN
    assert finding(findings, "ldap.referrals").status == Status.INFO


def test_other_operations_that_fail():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.delete_request(1, DAVE))
    c.server_says(1.2, lb.message(1, lb.app(11, lb.result(50, "", "no write access"))))
    f = finding(run(c)[0], "ldap.operation_failed")
    assert f.summary == 'DelRequest from 192.0.2.10 failed: 50 insufficientAccessRights. Diagnostic message: "no write access".'


# --- connections that cannot be read --------------------------------------------------------------

def test_ldaps_with_a_plaintext_unknown_ca_alert():
    c = Conversation(sport=636).handshake(1.0)
    c.client_says(1.1, lb.client_hello("dc1.corp.example", versions=()))
    c.server_says(1.2, lb.server_hello(0x0303))
    c.client_says(1.3, lb.alert(2, 48))
    findings, causes = run(c)
    f = finding(findings, "ldap.tls")
    assert f.status == Status.FAIL and "636 (LDAPS)" in f.summary and "fatal unknown_ca alert" in f.summary
    assert f.next_step == lc.READABLE_CAPTURE and "does not decrypt" in f.next_step
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("ldap-tls-failed", True)
    assert "-servername dc1.corp.example" in cause.first_step


def test_ldaps_tls13_stopping_after_server_hello_is_a_likely_trust_problem():
    c = Conversation(sport=636).handshake(1.0)
    c.client_says(1.1, lb.client_hello("dc1.corp.example"))
    c.server_says(1.2, lb.server_hello(tls13=True) + lb.change_cipher_spec() + lb.app_data(900))
    c.client_says(1.3, lb.change_cipher_spec() + lb.app_data(19))
    c.close(1.4)
    findings, causes = run(c)
    f = finding(findings, "ldap.tls")
    assert f.status == Status.WARN and "does not rule a trust problem out" in f.summary
    cause = only_cause(causes)
    assert (cause.pattern, cause.confirmed) == ("ldap-tls-failed", False)
    assert "not ruled out" in cause.summary and "size of an alert" in cause.evidence[0]


def test_a_working_ldaps_connection_is_noted_with_no_cause():
    c = Conversation(sport=636).handshake(1.0)
    c.client_says(1.1, lb.client_hello("dc1.corp.example"))
    c.server_says(1.2, lb.server_hello(tls13=True) + lb.app_data(900))
    c.client_says(1.3, lb.app_data(53) + lb.app_data(200))
    c.server_says(1.4, lb.app_data(80))
    findings, causes = run(c)
    f = finding(findings, "ldap.tls")
    assert f.status == Status.INFO and "makes no claim about it" in f.summary and causes == []
    assert "The TLS handshake completed" in f.summary and f.next_step == lc.READABLE_CAPTURE


def test_starttls_refused():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.extended_request(1, lb.STARTTLS))
    c.server_says(1.2, lb.extended_response(1, 52, diagnostic="TLS not configured"))
    findings, causes = run(c)
    assert "password in clear" in finding(findings, "ldap.starttls_refused").summary
    assert "ldap.operation_failed" not in ids(findings)
    assert only_cause(causes).pattern == "ldap-starttls-refused"


def test_sasl_signed_or_sealed():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.sasl_bind(1, "", "GSS-SPNEGO", b"token"))
    c.server_says(1.2, lb.bind_response(1, 0))
    c.client_says(1.3, (60).to_bytes(4, "big") + b"\x05\x04" + b"\xa5" * 58)
    findings, causes = run(c)
    f = finding(findings, "ldap.sasl_layer")
    assert "After a GSS-SPNEGO bind" in f.summary and f.next_step == lc.READABLE_CAPTURE
    assert "ldap.damaged" not in ids(findings) and causes == []


def test_connections_reset_before_any_data():
    c = Conversation().handshake(1.0)
    c.close(1.1, from_client=False, reset=True)
    findings, causes = run(c)
    assert finding(findings, "ldap.refused").status == Status.FAIL
    assert only_cause(causes).pattern == "ldap-connection-refused"


def test_no_response_then_a_reset():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.search_request(1, "dc=example", lb.f_present("cn")))
    c.close(30.0, from_client=False, reset=True)
    findings, causes = run(c)
    f = finding(findings, "ldap.unanswered")
    assert f.summary == ("1 request from 192.0.2.10 to 192.0.2.2:389 got no response: a SearchRequest, then the "
                         "server reset the connection 28.9 s later.")
    cause = only_cause(causes)
    assert cause.pattern == "ldap-no-response" and "until the directory closed the connection" in cause.summary


@pytest.mark.parametrize("capture_end,waited", [(1.6, "500 ms"), (31.1, "30.0 s")])
def test_still_pending_when_the_capture_ended_reports_the_real_wait(capture_end, waited):
    """No fixed grace period: half a second or half a minute, the report says how long it waited."""
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.search_request(1, "dc=example", lb.f_present("cn")))
    findings = lc.check(lx.analyse(c.numbered()), capture_end=capture_end)
    assert [f.check_id for f in findings] == ["ldap.pending"]
    assert findings[0].status == Status.WARN
    assert findings[0].summary == (f"1 request from 192.0.2.10 to 192.0.2.2:389 (SearchRequest) had no response "
                                   f"after {waited}; the capture ended while it was still pending, so a response "
                                   "may have come later, or not at all.")
    assert likely_causes(findings) == []


def test_the_client_abandoning_a_request_is_no_response():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.search_request(5, "dc=example", lb.f_present("cn")))
    c.client_says(11.1, lb.abandon(6, 5))
    f = finding(run(c)[0], "ldap.unanswered")
    assert f.summary.endswith("got no response: a SearchRequest, which the client abandoned 10.0 s later.")
    assert f.details["ended_by"] == ["client"]


def test_the_client_unbinding_or_closing_while_waiting_is_no_response():
    unbound = Conversation().handshake(1.0)
    unbound.client_says(1.1, lb.bind_request(1, APP, "x"))
    unbound.client_says(4.1, lb.unbind(2))
    assert finding(run(unbound)[0], "ldap.unanswered").summary.endswith(
        "a BindRequest, then the client unbound 3.0 s later.")
    closed = Conversation().handshake(1.0)
    closed.client_says(1.1, lb.bind_request(1, APP, "x"))
    closed.close(6.1, from_client=True, reset=True)
    findings, causes = run(closed)
    assert finding(findings, "ldap.unanswered").summary.endswith(
        "a BindRequest, then the client reset the connection 5.0 s later.")
    assert "until the client gave up" in only_cause(causes).summary


def test_notice_of_disconnection_and_slow_responses():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, APP, "x"))
    c.server_says(3.1, lb.bind_response(1, 0))
    c.server_says(4.0, lb.extended_response(0, 52, "1.3.6.1.4.1.1466.20036", "server shutting down"))
    findings, causes = run(c)
    assert finding(findings, "ldap.notice").status == Status.WARN
    assert finding(findings, "ldap.response_time").status == Status.WARN
    assert only_cause(causes).pattern == "ldap-slow"


def test_damage_is_reported():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, b"\x30\x80junk" + lb.unbind(2))
    assert finding(run(c)[0], "ldap.damaged").status == Status.WARN


def test_each_client_gets_its_own_cause():
    a = Conversation(cport=40001).handshake(1.0)
    bind(a, 1.1, 1, SVC, 49)
    b = Conversation(client="198.51.100.20", cport=40002).handshake(1.0)
    bind(b, 1.1, 1, SVC, 8)
    causes = run(a, b)[1]
    assert [(c.client, c.pattern) for c in causes] == [
        ("192.0.2.10", "ldap-service-bind-failed"), ("198.51.100.20", "ldap-signing-required")]


def test_radius_and_ldap_causes_side_by_side():
    from radius_trace import Trace
    from pcap_analyser import radius_checks, radius_exchange

    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 49)
    t = Trace()
    t.request(1.0, 1)
    t.reply(2.0, 1, code=3)
    ldap_findings = lc.check(lx.analyse(c.numbered()))
    radius_findings = radius_checks.check(radius_exchange.analyse(t.packets, capture_end=10.0))
    causes = likely_causes(ldap_findings + radius_findings)
    assert [c.pattern for c in causes] == ["ldap-service-bind-failed", "radius-user-rejected"]


def test_no_finding_or_cause_contains_a_bind_password():
    c = Conversation().handshake(1.0)
    bind(c, 1.1, 1, SVC, 49, password=PASSWORD)
    bind(c, 1.2, 2, DAVE, 0, password=PASSWORD)
    findings, causes = run(c)
    text = " ".join([f.summary + repr(f.details) for f in findings]
                    + [c.summary + " ".join(c.evidence) + c.first_step for c in causes])
    assert PASSWORD not in text and "canary" not in text


def test_ipv6_and_ports_given_by_the_user():
    c = Conversation(client=pb.CLIENT6, server=pb.SERVER6, sport=1389).handshake(1.0)
    bind(c, 1.1, 1, SVC, 49)
    findings, causes = run(c, ports=lx.DEFAULT_PORTS.with_extra({1389}))
    assert finding(findings, "ldap.bind_failed").details["server_label"] == "[2001:db8::2]:1389 (non-standard port)"
