"""Every committed capture is safe to publish.

Each one is checked independently of how it was made, with the same checker
the capture script runs: no private addresses in IP headers or in text, no
home paths or private keys, no clear-text LDAP bind password (TCP is
reassembled to find every bind), and nothing matching the local
.personal-patterns file. Where identity-lab's .env is present (on the
machine the captures were taken on; set IDENTITY_LAB_ENV to point at it),
also no value from it anywhere, and no RADIUS message that verifies with the
lab's real shared secret. In CI there is no .env, and those two checks are
skipped; the rest always run.

Failures name the file and the kind of problem, never the value.
"""

import json
import os
import pathlib

import pytest

from conftest import ROOT, load_script
from test_sanitise_capture import pcapng_with_metadata, raw_ldaps

sc = load_script("sanitise_capture")

LAB_ENV = pathlib.Path(os.environ.get("IDENTITY_LAB_ENV", pathlib.Path.home() / "identity-lab" / ".env"))
CAPTURES = sorted((ROOT / "samples" / "lab").glob("*.pcap")) + sorted(
    (ROOT / "src" / "auth_capture_explainer" / "demo_samples").glob("*.pcap"))
MADE = {"real lab traffic", "repeated through a relay", "synthetic"}


def lab_env():
    return LAB_ENV if LAB_ENV.is_file() else None


@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: p.name)
def test_capture_is_safe(path):
    problems = sorted(set(sc.check_file(path, lab_env())))
    assert not problems, f"{path.name}: {problems}"


@pytest.mark.parametrize("path", CAPTURES, ids=lambda p: p.name)
def test_capture_says_how_it_was_made(path):
    meta = json.loads(path.with_name(path.name + ".meta.json").read_text())
    assert meta["made"] in MADE and meta["what"] and meta["rewritten"]


def test_the_lab_samples_are_all_there():
    names = {p.stem for p in CAPTURES}
    assert set(sc.RECIPES) <= names


def test_the_sample_secret_is_the_fake_one():
    sample = (ROOT / "samples" / "lab" / "sample.secret").read_bytes().rstrip(b"\n")
    assert sample == sc.SAMPLE_SECRET
    real = sc.env_values(lab_env()).get("RADIUS_SECRET")
    assert real is None or real != sample


@pytest.mark.skipif(lab_env() is None, reason="identity-lab's .env is not on this machine")
def test_the_lab_env_is_actually_checked():
    """Guard against the checks above passing because the .env was read wrongly."""
    values = sc.env_values(lab_env())
    assert {"RADIUS_SECRET", "LDAP_BIND_PASSWORD", "DEMO_PASSWORD"} <= set(values)


# --- the checker has teeth: each kind of leak, planted in a real committed capture, is caught ----

def planted(tmp_path, name, change):
    data = bytearray((ROOT / "samples" / "lab" / name).read_bytes())
    change(data)
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return sc.check_file(path)


FIRST_FRAME = 24 + 16  # past the pcap file header and the first record header


def test_a_real_mac_is_caught(tmp_path):
    def ethernet(data):
        data[FIRST_FRAME:FIRST_FRAME + 6] = bytes.fromhex("3c22fb0a1b2c")

    def cooked(data):
        data[FIRST_FRAME + 12:FIRST_FRAME + 18] = bytes.fromhex("3c22fb0a1b2c")

    assert "an Ethernet MAC address outside the documentation range" in planted(tmp_path, "ldap-good.pcap", ethernet)
    assert "a link-layer address outside the documentation range" in planted(tmp_path, "radius-accept.pcap", cooked)


def test_a_bind_password_of_another_value_is_caught(tmp_path):
    def other(data):
        i = data.find(sc.FIXED_BIND_PASSWORD)
        data[i:i + len(sc.FIXED_BIND_PASSWORD)] = b"hunter2!!"

    assert "an LDAP bind password not replaced by the fixed value" in planted(tmp_path, "ldap-good.pcap", other)


def test_a_mac_written_as_text_is_caught(tmp_path):
    """As a RADIUS station ID carries one; the check reads the whole file, so any text will do to plant it."""
    def station(data):
        i = data.find(b"ldap")
        data[i:i + 17] = b"3c-22-fb-0a-1b-2c"

    assert "a MAC address outside the documentation range, written as text" in planted(
        tmp_path, "ldap-good.pcap", station)


def test_pcapng_metadata_and_a_server_name_are_caught(tmp_path):
    raw = tmp_path / "meta.pcapng"
    raw.write_bytes(pcapng_with_metadata([(1.0, b"\x00" * 20)]))
    assert any(k.startswith("pcapng") for k in sc.check_file(raw))
    assert "a TLS server name (SNI) that is not neutral" in sc.check_file(raw_ldaps(tmp_path, "dc01.corp.example"))
