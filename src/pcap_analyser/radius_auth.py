"""Check RADIUS messages against a shared secret.

RADIUS never sends the secret; it uses it as a key, in four places this
module can check:

- Message-Authenticator (RFC 3579, 5176): HMAC-MD5 over the whole message,
  keyed with the secret. Current NASes put it on every Access-Request, and
  servers on every reply. It is the decisive check: a server verifies it
  before anything else and drops the request if it fails.
- Response Authenticator (RFC 2865): an MD5 over the reply, the request's
  authenticator and the secret. It says whether the reply was made with the
  secret given, and needs the request in the capture.
- Request Authenticator of Accounting, CoA and Disconnect requests (RFC 2866,
  5176): an MD5 over the request and the secret.
- User-Password (RFC 2865): hidden by XOR with MD5(secret + Request
  Authenticator). With the wrong secret it decodes to random bytes, so
  whether it decodes to printable text says whether the NAS's secret is the
  one given. The decoded password itself never leaves password_looks_right().

Every check answers True (matches), False (does not match) or None (cannot
tell: the attribute is absent, the message was cut short, or the request is
missing). Nothing here returns, logs or raises with a value derived from the
secret, and comparisons are constant-time.
"""

import hashlib
import hmac
from dataclasses import dataclass

from pcap_analyser.radius import HEADER
from pcap_analyser.radius_dict import (
    ACCESS_REQUEST,
    ACCOUNTING_REQUEST,
    COA_REQUEST,
    DISCONNECT_REQUEST,
    MESSAGE_AUTHENTICATOR,
    STATUS_SERVER,
    USER_PASSWORD,
)

ZERO16 = b"\x00" * 16
# Requests whose authenticator is random, so only Message-Authenticator can be checked on them.
RANDOM_AUTHENTICATOR = (ACCESS_REQUEST, STATUS_SERVER)
# Requests whose authenticator is itself an MD5 keyed with the secret.
KEYED_AUTHENTICATOR = (ACCOUNTING_REQUEST, DISCONNECT_REQUEST, COA_REQUEST)


def _usable(msg):
    return msg is not None and msg.complete


def _ma_offset(raw):
    """Offset of the Message-Authenticator value in raw, or None. Walks the top-level attributes."""
    i = HEADER
    while i + 2 <= len(raw):
        attr_type, attr_len = raw[i], raw[i + 1]
        if attr_len < 2:
            return None
        if attr_type == MESSAGE_AUTHENTICATOR:
            return i + 2 if attr_len == 18 else None
        i += attr_len
    return None


def message_authenticator_ok(msg, secret, request=None):
    """Message-Authenticator on a request, or on a reply given the request it answers."""
    if not _usable(msg) or not msg.has(MESSAGE_AUTHENTICATOR):
        return None
    raw = msg.raw
    at = _ma_offset(raw)
    if at is None:
        return None
    if msg.is_request:
        authenticator = ZERO16 if msg.code in KEYED_AUTHENTICATOR else raw[4:HEADER]
    else:
        if not _usable(request):
            return None
        authenticator = request.authenticator
    signed = raw[:4] + authenticator + raw[HEADER:at] + ZERO16 + raw[at + 16:]
    return hmac.compare_digest(hmac.new(secret, signed, hashlib.md5).digest(), raw[at:at + 16])


def response_authenticator_ok(reply, request, secret):
    """The reply's Response Authenticator, which needs the request it answers."""
    if not _usable(reply) or not _usable(request):
        return None
    raw = reply.raw
    expected = hashlib.md5(raw[:4] + request.authenticator + raw[HEADER:] + secret).digest()
    return hmac.compare_digest(expected, reply.authenticator)


def request_authenticator_ok(msg, secret):
    """For Accounting, CoA and Disconnect requests, whose authenticator is keyed with the secret."""
    if not _usable(msg) or msg.code not in KEYED_AUTHENTICATOR:
        return None
    raw = msg.raw
    expected = hashlib.md5(raw[:4] + ZERO16 + raw[HEADER:] + secret).digest()
    return hmac.compare_digest(expected, msg.authenticator)


def password_looks_right(msg, secret):
    """True if User-Password decodes to printable text with this secret, False if to random bytes."""
    if msg is None or msg.code != ACCESS_REQUEST:
        return None
    attr = msg.get(USER_PASSWORD)
    if attr is None or not attr.value or len(attr.value) % 16:
        return None
    hidden, previous, plain = attr.value, msg.authenticator, bytearray()
    for i in range(0, len(hidden), 16):
        key = hashlib.md5(secret + previous).digest()
        block = hidden[i:i + 16]
        plain += bytes(a ^ b for a, b in zip(block, key))
        previous = block
    text = bytes(plain).rstrip(b"\x00")
    try:
        decoded = text.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(decoded) and decoded.isprintable()


@dataclass(frozen=True)
class Check:
    """The verdict on one message: which checks ran, and whether they matched."""

    message: object  # the radius.Message checked
    method: str  # "Message-Authenticator", "Response Authenticator", "Request Authenticator", "User-Password"
    ok: bool


def check_request(msg, secret):
    """Every check that applies to a request, as Checks. Empty when none can run."""
    checks = []
    for method, ok in (("Message-Authenticator", message_authenticator_ok(msg, secret)),
                       ("Request Authenticator", request_authenticator_ok(msg, secret)),
                       ("User-Password", password_looks_right(msg, secret))):
        if ok is not None:
            checks.append(Check(msg, method, ok))
    return checks


def check_reply(reply, request, secret):
    checks = []
    for method, ok in (("Response Authenticator", response_authenticator_ok(reply, request, secret)),
                       ("Message-Authenticator", message_authenticator_ok(reply, secret, request))):
        if ok is not None:
            checks.append(Check(reply, method, ok))
    return checks
