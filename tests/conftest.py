import importlib.util
import pathlib
import socket

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_script(name):
    """Import one of the scripts/ files as a module."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The tool only reads local files: any connection or name lookup fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("pcap-analyser attempted a network connection")

    def refuse_lookup(*args, **kwargs):
        raise AssertionError("pcap-analyser tried to resolve a name")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse_lookup)
    monkeypatch.setattr(socket, "gethostbyname", refuse_lookup)
    monkeypatch.setattr(socket, "gethostbyaddr", refuse_lookup)
