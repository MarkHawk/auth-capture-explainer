"""What a TLS handshake shows in clear: versions, server name, plaintext alerts."""

import random

import ldap_build as lb
from pcap_analyser import tls


def test_client_hello_versions_and_server_name():
    info = tls.inspect(lb.client_hello("ldap.example", versions=(0x0A0A, 0x0304, 0x0303)), b"")
    assert info.client_hello and info.server_name == "ldap.example"
    assert info.client_versions == ["TLS 1.3", "TLS 1.2"]  # the GREASE value 0x0a0a is dropped


def test_client_hello_without_supported_versions_offers_its_legacy_version():
    info = tls.inspect(lb.client_hello(None, versions=(), legacy=0x0302), b"")
    assert info.client_versions == ["TLS 1.1"] and info.server_name is None


def test_server_hello_tls12_and_tls13():
    assert tls.inspect(b"", lb.server_hello(0x0303)).server_version == "TLS 1.2"
    assert tls.inspect(b"", lb.server_hello(tls13=True)).server_version == "TLS 1.3"


def test_a_plaintext_alert_names_the_problem():
    """TLS 1.2: the client does not trust the server's certificate and says so in clear."""
    info = tls.inspect(lb.client_hello("ldap.example") + lb.alert(2, 48), lb.server_hello(0x0303))
    assert info.alerts == [tls.Alert("client", "fatal", "unknown_ca")] and not info.completed


def test_alerts_after_change_cipher_spec_are_encrypted():
    info = tls.inspect(lb.client_hello() + lb.change_cipher_spec() + lb.tls_record(21, b"\x99" * 26), b"")
    assert info.alerts == [tls.Alert("client", None, "encrypted")]


def test_tls12_application_data_both_ways_means_the_handshake_completed():
    info = tls.inspect(lb.client_hello(versions=()) + lb.change_cipher_spec() + lb.app_data(),
                       lb.server_hello(0x0303) + lb.change_cipher_spec() + lb.app_data())
    assert info.completed and info.outcome() == "The TLS handshake completed and data flowed both ways."


def test_tls13_completes_only_when_the_client_sends_more_than_its_finished():
    server = lb.server_hello(tls13=True) + lb.change_cipher_spec() + lb.app_data(900)  # encrypted certificate etc.
    finished_then_data = lb.client_hello() + lb.change_cipher_spec() + lb.app_data(53) + lb.app_data(120)
    assert tls.inspect(finished_then_data, server).completed


def test_tls13_ending_after_server_hello_is_consistent_with_an_encrypted_alert():
    """The client rejects the server's certificate: in TLS 1.3 its alert is encrypted, so no alert is seen.
    Both sides have still sent application-data records (the server's encrypted certificate, the alert)."""
    server = lb.server_hello(tls13=True) + lb.change_cipher_spec() + lb.app_data(900)
    client = lb.client_hello("ldap.example") + lb.change_cipher_spec() + lb.app_data(19)
    info = tls.inspect(client, server)
    assert info.client_data and info.server_data  # the naive test would have called this complete
    assert not info.completed and info.alerts == [] and info.alert_sized_close
    text = info.outcome()
    assert text.startswith("The TLS 1.3 handshake ended after the ServerHello: the client sent one encrypted "
                           "record the size of an alert and nothing more.")
    assert "consistent with an encrypted certificate or trust alert" in text
    assert "not seeing one does not rule a trust problem out" in text


def test_tls13_ending_with_no_client_records_at_all():
    info = tls.inspect(lb.client_hello(), lb.server_hello(tls13=True) + lb.app_data(900))
    assert not info.completed and "no application data followed" in info.outcome()
    assert "does not rule a trust problem out" in info.outcome()


def test_no_alert_seen_is_never_reported_as_no_trust_problem():
    for client, server in ((lb.client_hello(), lb.server_hello(tls13=True)),
                           (lb.client_hello(versions=()), lb.server_hello(0x0303))):
        text = tls.inspect(client, server).outcome()
        assert "not ruled out" in text or "does not rule a trust problem out" in text


def test_outcomes_for_a_plaintext_alert_and_a_server_that_never_answers():
    alerted = tls.inspect(lb.client_hello() + lb.alert(2, 48), lb.server_hello(0x0303))
    assert alerted.outcome() == "The client sent a fatal unknown_ca alert, so the handshake failed."
    assert "never answered it with a ServerHello" in tls.inspect(lb.client_hello(), b"").outcome()
    assert "start of the TLS handshake is not in the capture" in tls.inspect(lb.app_data(), lb.app_data()).outcome()


def test_damaged_records_never_raise():
    rng = random.Random(7)
    samples = [lb.client_hello("ldap.example"), lb.server_hello(tls13=True), lb.alert(2, 48) + lb.app_data()]
    for _ in range(3000):
        b = bytearray(rng.choice(samples))
        for _ in range(rng.randint(1, 5)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        data = bytes(b[:rng.randrange(len(b) + 1)])
        tls.inspect(data, data)
