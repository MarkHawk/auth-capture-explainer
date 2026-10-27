"""The test suite itself never reaches the network, not even loopback."""

import socket

import pytest


def test_outbound_connection_is_refused():
    with pytest.raises(AssertionError, match="network connection"):
        with socket.socket() as s:
            s.connect(("192.0.2.1", 80))  # RFC 5737 documentation address


def test_name_lookup_is_refused():
    with pytest.raises(AssertionError, match="resolve"):
        socket.getaddrinfo("example.com", 443)


def test_reverse_lookup_is_refused():
    with pytest.raises(AssertionError, match="resolve"):
        socket.gethostbyaddr("192.0.2.1")
