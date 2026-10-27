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


def test_application_data_both_ways_means_the_handshake_completed():
    info = tls.inspect(lb.client_hello() + lb.app_data(), lb.server_hello(tls13=True) + lb.change_cipher_spec()
                       + lb.app_data())
    assert info.completed and info.client_data and info.server_data


def test_damaged_records_never_raise():
    rng = random.Random(7)
    samples = [lb.client_hello("ldap.example"), lb.server_hello(tls13=True), lb.alert(2, 48) + lb.app_data()]
    for _ in range(3000):
        b = bytearray(rng.choice(samples))
        for _ in range(rng.randint(1, 5)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        data = bytes(b[:rng.randrange(len(b) + 1)])
        tls.inspect(data, data)
