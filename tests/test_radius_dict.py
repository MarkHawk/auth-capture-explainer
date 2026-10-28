"""How attribute values may appear in a report: in full, as a length, or
hidden. The masking tests use a distinctive value and check that no part of
it, in text or hex, reaches the displayed string."""

import struct

import pytest

from auth_capture_explainer import radius_dict as rd
from auth_capture_explainer.radius_dict import Attribute

CANARY = b"canary-secret-0123456789"


def leaks(shown, value=CANARY):
    """True if any 6-byte run of value appears in shown, as text or as hex."""
    runs = [value[i:i + 6] for i in range(len(value) - 5)]
    return any(r.decode("latin-1") in shown or r.hex() in shown.lower() for r in runs)


SECRET_TYPES = [t for t, d in rd.ATTRIBUTES.items() if d.kind == rd.SECRET]
SECRET_VSAS = [k for k, d in rd.VENDOR_ATTRIBUTES.items() if d.kind == rd.SECRET]


def test_the_dictionary_hides_what_it_should():
    names = {rd.ATTRIBUTES[t].name for t in SECRET_TYPES} | {rd.VENDOR_ATTRIBUTES[k].name for k in SECRET_VSAS}
    assert {"User-Password", "CHAP-Password", "Tunnel-Password", "MS-CHAP-Response", "MS-CHAP2-Response",
            "MS-CHAP-Challenge", "MS-MPPE-Send-Key", "MS-MPPE-Recv-Key", "MS-CHAP2-Success"} <= names
    assert rd.ATTRIBUTES[rd.MESSAGE_AUTHENTICATOR].kind == rd.PRESENT


@pytest.mark.parametrize("attr_type", SECRET_TYPES)
def test_secret_attributes_show_only_their_length(attr_type):
    shown = Attribute(attr_type, CANARY).display()
    assert shown == f"(hidden, {len(CANARY)} bytes)" and not leaks(shown)


@pytest.mark.parametrize("vendor,vendor_type", SECRET_VSAS)
def test_secret_vendor_attributes_show_only_their_length(vendor, vendor_type):
    shown = Attribute(26, CANARY, vendor, vendor_type).display()
    assert shown == f"(hidden, {len(CANARY)} bytes)" and not leaks(shown)


def test_message_authenticator_shows_only_that_it_is_there():
    shown = Attribute(rd.MESSAGE_AUTHENTICATOR, CANARY[:16]).display()
    assert shown == "(present, value hidden)"


@pytest.mark.parametrize("attr_type", [rd.STATE, 25, 33, 60])
def test_opaque_values_show_their_length(attr_type):
    shown = Attribute(attr_type, CANARY).display()
    assert shown == f"({len(CANARY)} bytes)" and not leaks(shown)


def test_unknown_attributes_show_their_length_only():
    assert Attribute(250, CANARY).display() == f"({len(CANARY)} bytes)"
    unknown_vendor = Attribute(26, CANARY, 99999, 7)
    assert unknown_vendor.display() == f"({len(CANARY)} bytes)" and unknown_vendor.name == "VSA vendor 99999, type 7"
    assert Attribute(26, CANARY, 311, 99).name == "VSA vendor 311, type 99"
    assert Attribute(26, CANARY, 12356).name == "VSA vendor 12356"  # kept whole: not in the usual layout


def test_the_free_text_vsa_is_shown_in_full_under_a_numeric_label():
    a = Attribute(26, b"shell:priv-lvl=15", 9, 1)
    assert (a.name, a.display()) == ("VSA vendor 9, type 1", "shell:priv-lvl=15")


def test_eap_shows_the_header_never_the_contents():
    identity = b"\x02\x05\x00\x0e\x01" + b"alice@corp"  # EAP-Response/Identity
    shown = Attribute(rd.EAP_MESSAGE, identity).display()
    assert shown == "EAP-Response/Identity (id 5, 15 bytes)" and "alice" not in shown
    assert Attribute(rd.EAP_MESSAGE, b"\x01\x06\x00\x06\x19\x20").display() == "EAP-Request/PEAP (id 6, 6 bytes)"
    assert Attribute(rd.EAP_MESSAGE, b"\x04\x07\x00\x04").display() == "EAP-Failure (id 7, 4 bytes)"
    assert Attribute(rd.EAP_MESSAGE, b"\x01").display() == "(1 bytes)"


def test_text_values_are_shown_in_full():
    assert Attribute(rd.USER_NAME, b"dave").display() == "dave"
    assert Attribute(rd.REPLY_MESSAGE, "Mot de passe expiré".encode()).display() == "Mot de passe expiré"


def test_text_cannot_inject_terminal_control_sequences():
    shown = Attribute(rd.USER_NAME, b"dave\x1b[2J\r\nroot\x00").display()
    assert "\x1b" not in shown and "\r" not in shown and "\n" not in shown and "\x00" not in shown
    assert shown == "dave\\x1b[2J\\x0d\\x0aroot\\x00"


def test_invalid_utf8_is_escaped_not_dropped():
    assert Attribute(rd.USER_NAME, b"d\xffve").display() == "d\\xffve"


def test_long_text_is_shortened():
    shown = Attribute(rd.REPLY_MESSAGE, b"x" * 250).display()
    assert shown == "x" * rd.MAX_SHOWN + "... (250 bytes)"


@pytest.mark.parametrize("attr_type,value,shown", [
    (6, 2, "Framed-User (2)"),
    (6, 999, "999"),
    (5, 7, "7"),
    (40, 1, "Start (1)"),
    (49, 1, "User-Request (1)"),
    (61, 19, "Wireless-802.11 (19)"),
    (101, 503, "Session-Context-Not-Found (503)"),
])
def test_integers_and_enumerations(attr_type, value, shown):
    assert Attribute(attr_type, struct.pack("!I", value)).display() == shown


def test_wrong_size_values_are_reported_not_misread():
    assert Attribute(6, b"\x01").display() == "(invalid: 1 bytes, expected 4)"
    assert Attribute(rd.NAS_IP_ADDRESS, b"\x01\x02").display() == "(invalid: 2 bytes, expected 4)"
    assert Attribute(rd.NAS_IPV6_ADDRESS, b"\x01").display() == "(invalid: 1 bytes, expected 16)"
    assert Attribute(55, b"\x01").display() == "(invalid: 1 bytes, expected 4)"
    assert Attribute(64, b"\x01").display() == "(invalid: 1 bytes, expected 4)"


def test_addresses_and_dates():
    assert Attribute(rd.NAS_IP_ADDRESS, bytes([192, 0, 2, 10])).display() == "192.0.2.10"
    assert Attribute(rd.NAS_IPV6_ADDRESS, bytes.fromhex("20010db8" + "00" * 11 + "01")).display() == "2001:db8::1"
    assert Attribute(97, bytes([0, 64]) + bytes.fromhex("20010db800000001")).display() == "2001:db8:0:1::/64"
    assert Attribute(97, bytes([0, 200]) + b"\x00" * 16).display() == "(18 bytes)"
    assert Attribute(55, struct.pack("!I", 1_800_000_000)).display() == "2027-01-15 08:00:00 UTC"


def test_tagged_attributes():
    assert Attribute(64, bytes([1]) + (13).to_bytes(3, "big")).display() == "VLAN (13) (tag 1)"
    assert Attribute(64, bytes([0]) + (13).to_bytes(3, "big")).display() == "VLAN (13)"
    assert Attribute(81, b"\x01" + b"100").display() == "100 (tag 1)"
    assert Attribute(81, b"100").display() == "100"


def test_code_names():
    assert rd.code_name(3) == "Access-Reject" and rd.code_name(99) == "code 99"
