"""LDAP connections: their kind (clear, TLS, StartTLS, empty, unreadable)
and their requests paired with responses."""

import ldap_build as lb
import pcapbuild as pb
from ldap_build import Conversation
from pcap_analyser import ldap_exchange as lx

SVC = "cn=svc,ou=services,dc=example"


def only(conversation, ports=lx.DEFAULT_PORTS):
    result = lx.analyse(conversation.numbered(), ports)
    assert len(result.connections) == 1
    return result.connections[0]


def test_a_failed_service_bind():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, SVC, "wrong"))
    c.server_says(1.112, lb.bind_response(1, 49))
    c.client_says(1.2, lb.unbind(2))
    c.close(1.3)
    conn = only(c)
    assert (conn.kind, conn.port_label, conn.encrypted, conn.problems) == ("ldap", "389", False, [])
    bind, unbind = conn.operations
    assert (bind.name, bind.request.dn, bind.result.result_code, bind.answered) == ("BindRequest", SVC, 49, True)
    assert abs(bind.response_time - 0.012) < 1e-9
    assert (unbind.name, unbind.expects_response, unbind.answered) == ("UnbindRequest", False, False)


def test_a_search_collects_entries_and_references():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.search_request(2, "ou=people,dc=example", lb.f_eq("uid", "dave")))
    c.server_says(1.15, lb.search_entry(2, "uid=dave,ou=people,dc=example", [("cn", ["Dave"])]))
    c.server_says(1.16, lb.search_reference(2, "ldap://other/"))
    c.server_says(1.2, lb.search_done(2))
    (search,) = only(c).operations
    assert (search.entries, search.references, search.result.result_code) == (1, 1, 0)
    assert abs(search.first_response_time - 0.05) < 1e-9 and abs(search.response_time - 0.1) < 1e-9


def test_responses_pair_by_message_id_whatever_their_order():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, SVC, "x"))
    c.client_says(1.11, lb.search_request(2, "dc=example", lb.f_present("cn")))
    c.server_says(1.2, lb.search_done(2, 0))
    c.server_says(1.3, lb.bind_response(1, 0))
    bind, search = only(c).operations
    assert (bind.result.op, search.result.op) == (1, 5)


def test_a_message_split_across_segments_and_two_in_one():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, SVC, "x" * 40), split=7)
    c.server_says(1.2, lb.bind_response(1, 0) + lb.bind_response(9, 0))
    conn = only(c)
    assert conn.operations[0].answered and len(conn.orphan_responses) == 1


def test_unanswered_requests_and_abandon():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.search_request(5, "dc=example", lb.f_present("cn")))
    c.client_says(2.1, lb.abandon(6, 5))
    search, abandon = only(c).operations
    assert not search.answered and search.abandoned and not abandon.expects_response


def test_notice_of_disconnection():
    c = Conversation().handshake(1.0)
    c.server_says(1.1, lb.extended_response(0, 52, "1.3.6.1.4.1.1466.20036", "server shutting down"))
    conn = only(c)
    assert len(conn.notices) == 1 and conn.notices[0].result_code == 52


def test_a_client_sending_a_response_is_a_problem():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_response(1, 0))
    assert "the client sent a BindResponse" in only(c).problems[0].reason


def test_ldaps_is_tls_from_the_first_byte():
    c = Conversation(sport=636).handshake(1.0)
    c.client_says(1.1, lb.client_hello("ldap.example"))
    c.server_says(1.2, lb.server_hello(tls13=True) + lb.change_cipher_spec() + lb.app_data(900))
    c.client_says(1.3, lb.change_cipher_spec() + lb.app_data(53) + lb.app_data(120))  # Finished, then LDAP
    conn = only(c)
    assert (conn.kind, conn.encrypted, conn.port_label, conn.operations) == ("tls", True, "636 (LDAPS)", [])
    assert conn.tls.server_name == "ldap.example" and conn.tls.server_version == "TLS 1.3" and conn.tls.completed
    assert conn.tls_frame == 4  # the ClientHello, after the three handshake packets


def test_tls_is_told_from_the_bytes_on_any_ldap_port():
    c = Conversation(sport=389).handshake(1.0)
    c.client_says(1.1, lb.client_hello())
    assert only(c).kind == "tls"


def test_starttls_then_tls():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.extended_request(1, lb.STARTTLS))
    c.server_says(1.2, lb.extended_response(1, 0, lb.STARTTLS))
    c.client_says(1.3, lb.client_hello("ldap.example"))
    c.server_says(1.4, lb.server_hello(0x0303))
    c.client_says(1.5, lb.alert(2, 48))
    conn = only(c)
    assert conn.kind == "starttls" and conn.encrypted
    (starttls,) = conn.operations
    assert starttls.request.is_starttls and starttls.result.result_code == 0
    assert conn.tls.server_name == "ldap.example" and conn.tls.alerts[0].description == "unknown_ca"
    assert conn.problems == []


def test_starttls_refused_stays_clear():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.extended_request(1, lb.STARTTLS))
    c.server_says(1.2, lb.extended_response(1, 2, diagnostic="unsupported extended operation"))
    c.client_says(1.3, lb.bind_request(2, SVC, "x"))
    c.server_says(1.4, lb.bind_response(2, 13, diagnostic="confidentiality required"))
    conn = only(c)
    assert conn.kind == "ldap" and [op.result.result_code for op in conn.operations] == [2, 13]


def test_an_empty_connection():
    c = Conversation().handshake(1.0)
    c.close(1.1, from_client=False, reset=True)
    assert only(c).kind == "empty"


def test_bytes_that_are_neither_ldap_nor_tls():
    c = Conversation()
    c.client_says(1.0, b"\x00\x01garbage that is not ldap at all")
    conn = only(c)
    assert conn.kind == "unreadable" and conn.problems


def test_a_capture_joined_part_way_still_pairs_what_it_saw():
    c = Conversation()  # no handshake
    c.client_says(1.0, lb.search_request(7, "dc=example", lb.f_present("cn")))
    c.server_says(1.1, lb.search_done(7))
    conn = only(c)
    assert conn.kind == "ldap" and conn.operations[0].answered and not conn.stream.syn_seen


def test_gaps_are_counted():
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, SVC, "x"))
    c.skip(True, 30)
    c.client_says(1.3, lb.unbind(3))
    conn = only(c)
    assert conn.gaps == 1 and [op.name for op in conn.operations] == ["BindRequest", "UnbindRequest"]


def test_ports():
    ports = lx.DEFAULT_PORTS.with_extra({1636})
    assert ports.all == {389, 636, 3268, 3269, 1636}
    assert [ports.label(p) for p in (389, 636, 3268, 3269, 1636)] == [
        "389", "636 (LDAPS)", "3268 (Global Catalog)", "3269 (Global Catalog over TLS)", "1636 (non-standard port)"]
    c = Conversation(sport=1636).handshake(1.0)
    c.client_says(1.1, lb.client_hello())
    assert lx.analyse(c.numbered()).connections == []
    assert lx.analyse(c.numbered(), ports).connections[0].kind == "tls"


def test_several_connections_in_time_order_and_ipv6():
    a = Conversation(cport=40001).handshake(2.0)
    a.client_says(2.1, lb.unbind(1))
    b = Conversation(client=pb.CLIENT6, server=pb.SERVER6, cport=40002).handshake(1.0)
    b.client_says(1.1, lb.unbind(1))
    result = lx.analyse(a.numbered() + b.numbered(start=100))
    assert [c.client for c in result.connections] == [pb.CLIENT6, pb.CLIENT]
