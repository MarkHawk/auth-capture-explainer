"""Sign RADIUS messages for tests, written from the RFCs independently of
pcap_analyser.radius_auth. The RFC 2865 worked example in test_radius_auth.py
and the real NAS packets in test_spike_local.py check that both agree with
the outside world, not just with each other."""

import hashlib
import hmac
import struct

MA = 80


def _with_ma(code, ident, authenticator_field, attrs, secret):
    """attrs: (type, value) pairs; a Message-Authenticator is appended and filled in."""
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    body_ma = body + bytes([MA, 18]) + b"\x00" * 16
    length = 20 + len(body_ma)
    unsigned = struct.pack("!BBH", code, ident, length) + authenticator_field + body_ma
    mac = hmac.new(secret, unsigned, hashlib.md5).digest()
    return body + bytes([MA, 18]) + mac, length


def access_request(ident, authenticator, attrs, secret, password=None):
    """An Access-Request (or, with code 12 in attrs' place, use status_server) with Message-Authenticator.
    password: plain bytes to hide as User-Password with the secret."""
    attrs = list(attrs)
    if password is not None:
        attrs.append((2, hide_password(password, authenticator, secret)))
    body, length = _with_ma(1, ident, authenticator, attrs, secret)
    return struct.pack("!BBH", 1, ident, length) + authenticator + body


def status_server(ident, authenticator, secret):
    body, length = _with_ma(12, ident, authenticator, [], secret)
    return struct.pack("!BBH", 12, ident, length) + authenticator + body


def reply(code, ident, request_authenticator, attrs, secret, with_ma=True):
    """A reply with Message-Authenticator (keyed with the request's authenticator) and Response Authenticator."""
    if with_ma:
        body, length = _with_ma(code, ident, request_authenticator, list(attrs), secret)
    else:
        body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
        length = 20 + len(body)
    header = struct.pack("!BBH", code, ident, length)
    response = hashlib.md5(header + request_authenticator + body + secret).digest()
    return header + response + body


def accounting_request(ident, attrs, secret, with_ma=False):
    zero = b"\x00" * 16
    if with_ma:
        body, length = _with_ma(4, ident, zero, list(attrs), secret)
    else:
        body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
        length = 20 + len(body)
    header = struct.pack("!BBH", 4, ident, length)
    return header + hashlib.md5(header + zero + body + secret).digest() + body


def hide_password(password, authenticator, secret):
    padded = password + b"\x00" * (-len(password) % 16 or (16 if not password else 0))
    out, previous = b"", authenticator
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i + 16], hashlib.md5(secret + previous).digest()))
        out += block
        previous = block
    return out
