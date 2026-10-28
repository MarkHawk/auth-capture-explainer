"""Decoding LDAP messages: every operation the tool reads, search filters
as text, passwords never kept, and reading a stream that is split, damaged
or switches to TLS."""

import pytest

import ldap_build as lb
from auth_capture_explainer import ber, ldap, tcpstream
from auth_capture_explainer.ber import BerError

PASSWORD = "canary-bind-password"


def decode(data):
    return ldap.decode(ber.read(data))


def test_simple_bind_keeps_the_length_never_the_password():
    m = decode(lb.bind_request(1, "cn=svc,ou=services,dc=example", PASSWORD))
    assert (m.id, m.name, m.version, m.dn, m.auth, m.password_length) == (
        1, "BindRequest", 3, "cn=svc,ou=services,dc=example", "simple", len(PASSWORD))
    assert PASSWORD not in repr(m) and "canary" not in str(vars(m))


def test_anonymous_and_unauthenticated_binds():
    assert (decode(lb.bind_request(1, "")).dn, decode(lb.bind_request(1, "")).password_length) == ("", 0)
    unauth = decode(lb.bind_request(1, "uid=dave,ou=people,dc=example", ""))
    assert unauth.dn and unauth.password_length == 0


def test_sasl_bind():
    m = decode(lb.sasl_bind(2, "", "GSSAPI", b"\x60\x82token"))
    assert (m.auth, m.mechanism, m.password_length) == ("sasl", "GSSAPI", None)
    assert decode(lb.sasl_bind(2, "", "EXTERNAL")).mechanism == "EXTERNAL"


def test_bind_response():
    m = decode(lb.bind_response(1, 49, "", "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext "
                                           "error, data 52e, v4563"))
    assert (m.name, m.result_code, m.matched_dn) == ("BindResponse", 49, "")
    assert m.diagnostic.endswith("data 52e, v4563")
    r = decode(lb.bind_response(1, 10, "dc=example", "", referrals=["ldap://other.example/"]))
    assert (r.result_code, r.matched_dn, r.referrals) == (10, "dc=example", ["ldap://other.example/"])


@pytest.mark.parametrize("flt,text", [
    (lb.f_eq("uid", "dave"), "(uid=dave)"),
    (lb.f_and(lb.f_eq("objectClass", "person"), lb.f_eq("uid", "dave")), "(&(objectClass=person)(uid=dave))"),
    (lb.f_or(lb.f_eq("uid", "a"), lb.f_eq("mail", "a@x")), "(|(uid=a)(mail=a@x))"),
    (lb.f_not(lb.f_present("disabled")), "(!(disabled=*))"),
    (lb.f_substr("cn", "Da", ["v"], "e"), "(cn=Da*v*e)"),
    (lb.f_substr("cn", final="son"), "(cn=*son)"),
    (lb.f_cmp(5, "uidNumber", "1000"), "(uidNumber>=1000)"),
    (lb.f_cmp(6, "uidNumber", "2000"), "(uidNumber<=2000)"),
    (lb.f_cmp(8, "cn", "dave"), "(cn~=dave)"),
    (lb.f_ext("userAccountControl", "1.2.840.113556.1.4.803", "2"),
     "(userAccountControl:1.2.840.113556.1.4.803:=2)"),
    (lb.f_ext("ou", None, "people", dn=True), "(ou:dn:=people)"),
    (lb.f_eq("cn", "Smith, John (admin)*"), "(cn=Smith, John \\28admin\\29\\2a)"),
    (lb.f_eq("cn", "Zoë"), "(cn=Zo\\c3\\ab)"),
], ids=lambda x: x if isinstance(x, str) else None)
def test_search_filters_render_as_rfc_4515_text(flt, text):
    m = decode(lb.search_request(2, "ou=people,dc=example", flt, scope=1, attributes=["cn", "mail"]))
    assert (m.name, m.base, m.scope, m.filter, m.attributes) == (
        "SearchRequest", "ou=people,dc=example", "one", text, ["cn", "mail"])


def test_a_long_filter_is_shortened():
    m = decode(lb.search_request(2, "", lb.f_or(*(lb.f_eq("uid", f"user{i}") for i in range(40)))))
    assert len(m.filter) == ldap.MAX_FILTER + 3 and m.filter.endswith("...")


def test_an_unreadable_filter_does_not_lose_the_search():
    m = decode(lb.search_request(2, "dc=example", lb.ctx(15, b"x")))
    assert m.filter == "(unreadable filter)" and m.base == "dc=example"


def test_search_entry_keeps_attribute_names_not_values():
    m = decode(lb.search_entry(2, "uid=dave,ou=people,dc=example",
                               [("mail", ["dave@idlab.example"]), ("cn", ["Dave Dawson"])]))
    assert (m.name, m.dn, m.attributes) == ("SearchResultEntry", "uid=dave,ou=people,dc=example", ["mail", "cn"])
    assert "Dawson" not in str(vars(m)) and "idlab.example" not in str(vars(m))


def test_search_done_and_reference():
    assert decode(lb.search_done(2, 32)).result_code == 32
    assert decode(lb.search_reference(2, "ldap://a/", "ldap://b/")).referrals == ["ldap://a/", "ldap://b/"]


def test_starttls_and_other_extended_operations():
    req = decode(lb.extended_request(3, lb.STARTTLS))
    assert req.is_starttls and req.extended_name == "StartTLS" and req.is_request
    resp = decode(lb.extended_response(3, 0, lb.STARTTLS))
    assert resp.is_starttls and resp.result_code == 0
    whoami = decode(lb.extended_request(4, "1.3.6.1.4.1.4203.1.11.3"))
    assert whoami.extended_name == "Who am I?" and not whoami.is_starttls
    other = decode(lb.extended_request(5, "1.2.3.4"))
    assert other.extended_name == "1.2.3.4"


def test_unbind_abandon_delete_and_other_results():
    assert decode(lb.unbind(9)).name == "UnbindRequest"
    assert decode(lb.abandon(10, 7)).abandon_id == 7
    assert decode(lb.delete_request(11, "uid=x,dc=example")).dn == "uid=x,dc=example"
    m = decode(lb.modify_response(12, 50, "insufficient access"))
    assert (m.name, m.result_code, m.diagnostic) == ("ModifyResponse", 50, "insufficient access")


def test_controls_are_listed_by_oid():
    control = lb.seq(lb.octets("1.2.840.113556.1.4.319"), lb.boolean(True))
    m = decode(lb.message(2, lb.app(3, lb.octets(""), lb.enum(2), lb.enum(0), lb.integer(0), lb.integer(0),
                                    lb.boolean(False), lb.f_present("cn"), lb.seq()), controls=control))
    assert m.controls == ["1.2.840.113556.1.4.319"]


def test_dns_with_control_characters_are_escaped():
    m = decode(lb.bind_request(1, "cn=evil\x1b[2J,dc=example", "x"))
    assert "\x1b" not in m.dn and "\\x1b" in m.dn


@pytest.mark.parametrize("data,message", [
    (lb.octets("x"), "an LDAPMessage"),
    (lb.seq(lb.integer(1)), "needs a message ID and an operation"),
    (lb.seq(lb.integer(-1), lb.app(2, constructed=False)), "out of range"),
    (lb.seq(lb.integer(1), lb.app(30)), "unknown LDAP operation"),
    (lb.seq(lb.integer(1), lb.app(0, lb.integer(3))), "needs a version, a name and authentication"),
    (lb.seq(lb.integer(1), lb.app(0, lb.integer(3), lb.octets("x"), lb.ctx(9, b""))), "unknown bind"),
    (lb.seq(lb.integer(1), lb.app(1, lb.enum(0))), "needs a result code"),
])
def test_not_ldap(data, message):
    with pytest.raises(BerError, match=message):
        decode(data)


# --- reading a direction --------------------------------------------------------------

def chunk(data, start=0, ts=1.0):
    return tcpstream.Chunk(start, data, [(start, ts, 1)])


def test_several_messages_in_one_chunk():
    data = lb.bind_request(1, "cn=a", "x") + lb.search_request(2, "", lb.f_present("objectClass")) + lb.unbind(3)
    parsed = ldap.parse_direction([chunk(data)])
    assert [m.name for m in parsed.messages] == ["BindRequest", "SearchRequest", "UnbindRequest"]
    assert [m.offset for m in parsed.messages][1] == len(lb.bind_request(1, "cn=a", "x"))
    assert parsed.problems == [] and parsed.unfinished == 0


def test_messages_are_timed_by_their_last_byte():
    first, second = lb.bind_request(1, "cn=a", "x"), lb.unbind(2)
    data = first + second
    c = tcpstream.Chunk(0, data, [(0, 1.0, 1), (len(first) - 1, 2.0, 2), (len(first) + 1, 3.0, 3)])
    parsed = ldap.parse_direction([c])
    assert [(m.ts, m.frame) for m in parsed.messages] == [(2.0, 2), (3.0, 3)]


def test_an_unfinished_message_at_the_end():
    data = lb.bind_request(1, "cn=a", "x")
    parsed = ldap.parse_direction([chunk(data + data[:5])])
    assert len(parsed.messages) == 1 and parsed.unfinished == 5


def test_garbage_is_reported_and_skipped():
    good = lb.bind_request(1, "cn=a", "x")
    parsed = ldap.parse_direction([chunk(b"\x04\x80\x00garbage!" + good)])
    assert [m.name for m in parsed.messages] == ["BindRequest"]
    assert parsed.problems[0].offset == 0 and "indefinite length" in parsed.problems[0].reason


def test_a_message_that_is_not_ldap_is_reported_and_skipped():
    parsed = ldap.parse_direction([chunk(lb.seq(lb.integer(1), lb.app(30)) + lb.unbind(2))])
    assert [m.name for m in parsed.messages] == ["UnbindRequest"] and len(parsed.problems) == 1


def test_each_chunk_after_a_gap_is_read_on_its_own():
    a, b = lb.bind_request(1, "cn=a", "x"), lb.unbind(2)
    parsed = ldap.parse_direction([chunk(a), chunk(b, start=len(a) + 50)])
    assert [m.offset for m in parsed.messages] == [0, len(a) + 50]


def test_tls_after_starttls_ends_the_clear_text():
    data = lb.extended_request(1, lb.STARTTLS) + lb.client_hello("ldap.example")
    parsed = ldap.parse_direction([chunk(data)])
    assert [m.name for m in parsed.messages] == ["ExtendedRequest"]
    assert parsed.tls_from == len(lb.extended_request(1, lb.STARTTLS)) and parsed.problems == []


def test_tls_from_the_first_byte():
    parsed = ldap.parse_direction([chunk(lb.client_hello("ldap.example"))])
    assert parsed.messages == [] and parsed.tls_from == 0


def test_a_tls_lookalike_mid_stream_without_starttls_is_not_tls():
    parsed = ldap.parse_direction([chunk(lb.unbind(1) + b"\x16\x03\x01\x00\x05hello")])
    assert parsed.tls_from is None and len(parsed.problems) == 1
