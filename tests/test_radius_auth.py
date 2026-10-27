"""Checking RADIUS messages against a shared secret. The first test uses the
worked example from RFC 2865 section 7.1, so the checks agree with the
standard's own numbers and not just with the test helpers."""

import pytest

import pcapbuild as pb
import radius_sign as sign
from pcap_analyser import layers, radius
from pcap_analyser import radius_auth as ra

SECRET, WRONG = b"sample-secret", b"another-secret"
RA = bytes(range(100, 116))


def msg(data, to_server=True, cut=None):
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, data) if to_server else pb.udp(pb.SERVER, pb.CLIENT, 1812, 40000, data)
    if cut is not None:
        return radius.decode(layers.decode(1, 0.0, layers.LINKTYPE_RAW, ip[:28 + cut], cut=True))
    return radius.decode(layers.decode(1, 0.0, layers.LINKTYPE_RAW, ip))


# RFC 2865 section 7.1: user "nemo", password "arctangent", secret "xyzzy5461".
RFC_REQUEST = bytes.fromhex(
    "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee"
    "0406c0a8011005060000000" "3")
RFC_ACCEPT = bytes.fromhex("0200002686fe220e7624ba2a1005f6bf9b55e0b206060000000" "10f06000000000e06c0a80103")


def test_rfc_2865_worked_example():
    request, accept = msg(RFC_REQUEST), msg(RFC_ACCEPT, to_server=False)
    assert ra.response_authenticator_ok(accept, request, b"xyzzy5461") is True
    assert ra.password_looks_right(request, b"xyzzy5461") is True
    assert ra.response_authenticator_ok(accept, request, b"xyzzy5462") is False
    assert ra.password_looks_right(request, b"xyzzy5462") is False
    assert ra.message_authenticator_ok(request, b"xyzzy5461") is None  # it carries none


def test_the_test_helper_agrees_with_the_rfc_example():
    hidden = sign.hide_password(b"arctangent", RFC_REQUEST[4:20], b"xyzzy5461")
    assert hidden == RFC_REQUEST[28:44]  # after the header (20) and User-Name (6), the attribute's own 2


def test_access_request_message_authenticator():
    request = msg(sign.access_request(1, RA, [(1, b"dave")], SECRET, password=b"letmein"))
    assert ra.message_authenticator_ok(request, SECRET) is True
    assert ra.message_authenticator_ok(request, WRONG) is False
    assert ra.password_looks_right(request, SECRET) is True
    assert ra.password_looks_right(request, WRONG) is False


def test_status_server_message_authenticator():
    request = msg(sign.status_server(9, RA, SECRET))
    assert ra.message_authenticator_ok(request, SECRET) is True
    assert ra.message_authenticator_ok(request, WRONG) is False


@pytest.mark.parametrize("code", [2, 3, 11])
def test_reply_authenticators_use_the_request(code):
    request = msg(sign.access_request(1, RA, [(1, b"dave")], SECRET))
    reply = msg(sign.reply(code, 1, RA, [(18, b"hello")], SECRET), to_server=False)
    assert ra.response_authenticator_ok(reply, request, SECRET) is True
    assert ra.message_authenticator_ok(reply, SECRET, request) is True
    assert ra.response_authenticator_ok(reply, request, WRONG) is False
    assert ra.message_authenticator_ok(reply, WRONG, request) is False
    other = msg(sign.access_request(1, bytes(16), [(1, b"dave")], SECRET))
    assert ra.response_authenticator_ok(reply, other, SECRET) is False  # the wrong request
    assert ra.message_authenticator_ok(reply, SECRET, None) is None  # no request to check against
    assert ra.response_authenticator_ok(reply, None, SECRET) is None


def test_accounting_request_authenticator():
    attrs = [(40, b"\x00\x00\x00\x01"), (44, b"sess-1")]
    plain = msg(sign.accounting_request(5, attrs, SECRET), )
    assert ra.request_authenticator_ok(plain, SECRET) is True
    assert ra.request_authenticator_ok(plain, WRONG) is False
    with_ma = msg(sign.accounting_request(5, attrs, SECRET, with_ma=True))
    assert ra.message_authenticator_ok(with_ma, SECRET) is True and ra.request_authenticator_ok(with_ma, SECRET)
    assert ra.request_authenticator_ok(msg(sign.access_request(1, RA, [], SECRET)), SECRET) is None


def test_messages_cut_short_cannot_be_checked():
    request = msg(sign.access_request(1, RA, [(1, b"dave")], SECRET, password=b"x"), cut=30)
    assert not request.complete
    assert ra.message_authenticator_ok(request, SECRET) is None
    assert ra.check_request(request, SECRET) == []


def test_a_message_authenticator_of_the_wrong_size_cannot_be_checked():
    data = pb.radius(1, 1, [(80, b"\x00" * 8)])
    assert ra.message_authenticator_ok(msg(data), SECRET) is None


@pytest.mark.parametrize("password,expected", [
    (b"p", True),
    (b"exactly16bytes!!", True),
    (b"a much longer password, over two blocks", True),
    (b"caf\xc3\xa9 au lait", True),  # UTF-8 text is fine
    (b"has\x00nul", False),
    (b"\x01\x02\x03", False),
])
def test_what_counts_as_a_readable_password(password, expected):
    request = msg(sign.access_request(1, RA, [], SECRET, password=password))
    assert ra.password_looks_right(request, SECRET) is expected


def test_password_attribute_of_a_bad_size_cannot_be_checked():
    assert ra.password_looks_right(msg(pb.radius(1, 1, [(2, b"\x00" * 10)])), SECRET) is None
    assert ra.password_looks_right(msg(pb.radius(1, 1, [(1, b"dave")])), SECRET) is None


def test_check_request_and_check_reply_name_their_methods():
    request = msg(sign.access_request(1, RA, [(1, b"dave")], SECRET, password=b"pw"))
    reply = msg(sign.reply(3, 1, RA, [], SECRET), to_server=False)
    assert [(c.method, c.ok) for c in ra.check_request(request, SECRET)] == [
        ("Message-Authenticator", True), ("User-Password", True)]
    assert [(c.method, c.ok) for c in ra.check_reply(reply, request, WRONG)] == [
        ("Response Authenticator", False), ("Message-Authenticator", False)]
    bare = msg(sign.reply(2, 1, RA, [], SECRET, with_ma=False), to_server=False)
    assert [c.method for c in ra.check_reply(bare, request, SECRET)] == ["Response Authenticator"]
