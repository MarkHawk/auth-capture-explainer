"""The BER decoder: the subset LDAP uses, and refusing everything else."""

import pytest

import ldap_build as lb
from auth_capture_explainer import ber
from auth_capture_explainer.ber import BerError, Incomplete


def test_short_and_long_lengths():
    for n in (0, 1, 127, 128, 255, 256, 70000):
        data = lb.octets(b"x" * n)
        e = ber.read(data)
        assert (e.cls, e.constructed, e.tag, len(e.value), e.start, e.end) == (0, False, 4, n, 0, len(data))


def test_read_at_an_offset_and_children():
    data = b"\xff\xff" + lb.seq(lb.integer(5), lb.octets("dn"))
    e = ber.read(data, 2)
    assert e.start == 2 and e.end == len(data)
    first, second = e.children()
    assert (first.integer(), second.text()) == (5, "dn")


def test_high_tag_numbers():
    e = ber.read(bytes([0x9F, 0x81, 0x00, 0x01, 0x07]))  # context, tag 128
    assert (e.cls, e.tag, e.value) == (ber.CONTEXT, 128, b"\x07")


@pytest.mark.parametrize("n", [0, 1, -1, 127, 128, -129, 2**31 - 1, -(2**63)])
def test_integers(n):
    assert ber.read(lb.integer(n)).integer() == n


@pytest.mark.parametrize("data,message", [
    (b"\x04\x80\x00\x00", "indefinite length"),
    (b"\x04\x85\x01\x02\x03\x04\x05", "a length of 5 bytes is too long"),
    (b"\x04\x84\x7f\xff\xff\xff", "over the"),
    (b"\x1f\x81\x81\x81\x81\x01\x00", "tag number is too long"),
])
def test_refused(data, message):
    with pytest.raises(BerError, match=message) as e:
        ber.read(data)
    assert not isinstance(e.value, Incomplete)


@pytest.mark.parametrize("data", [b"", b"\x30", b"\x30\x05\x02", b"\x04\x82\x01", b"\x1f\x81", b"\x30\x82\x01\x00" + b"\x00" * 10])
def test_incomplete_is_told_apart(data):
    with pytest.raises(Incomplete):
        ber.read(data)


def test_a_child_running_past_its_parent():
    e = ber.read(b"\x30\x03\x04\x05ab")
    with pytest.raises(BerError, match="runs past the end"):
        e.children()


def test_primitive_has_no_children():
    with pytest.raises(BerError, match="primitive"):
        ber.read(lb.octets("x")).children()


def test_nesting_limit():
    with pytest.raises(BerError, match="nested more than"):
        ber.read(lb.octets("x", identifier=0x30)).children(depth=ber.MAX_DEPTH)


@pytest.mark.parametrize("value,message", [(b"", "empty integer"), (b"\x01" * 9, "too long")])
def test_bad_integers(value, message):
    with pytest.raises(BerError, match=message):
        ber.to_integer(value)


def test_expect():
    e = ber.read(lb.integer(3))
    assert ber.expect(e, ber.UNIVERSAL, ber.INTEGER, "an integer") is e
    with pytest.raises(BerError, match="expected a string"):
        ber.expect(e, ber.UNIVERSAL, ber.OCTET_STRING, "a string")
