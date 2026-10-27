"""Decode LDAP messages (RFC 4511) from a reassembled TCP stream.

Only what a support engineer needs is read: binds (who, how, and the
result), searches (base, scope, filter, how many entries came back),
extended operations (StartTLS above all), unbind and abandon, and the
LDAPResult of every other operation. Attribute values in search results are
not kept, only attribute names: they are personal data and add nothing to
explaining a failure.

A simple bind's password is never kept: only its length, and whether it was
empty, which matters because a bind with a DN and an empty password is an
unauthenticated bind that many servers accept (RFC 4513, section 5.1.2).

A stream direction is read message by message. A message that cannot be
decoded is reported with its offset and skipped; if the framing itself is
lost, the reader looks ahead for the next plausible message rather than
giving up on the connection. After a StartTLS request, bytes that look like
a TLS record end the clear-text part of that direction; after a successful
SASL bind, so do bytes that look like a SASL security-layer buffer (a
4-byte length, then a signed or sealed token), which Kerberos and NTLM
binds negotiate and Active Directory uses by default.
"""

from dataclasses import dataclass, field

from pcap_analyser import ber
from pcap_analyser.ber import APPLICATION, CONTEXT, UNIVERSAL, BerError, Incomplete
from pcap_analyser.safetext import text

OPS = {
    0: "BindRequest", 1: "BindResponse", 2: "UnbindRequest", 3: "SearchRequest", 4: "SearchResultEntry",
    5: "SearchResultDone", 6: "ModifyRequest", 7: "ModifyResponse", 8: "AddRequest", 9: "AddResponse",
    10: "DelRequest", 11: "DelResponse", 12: "ModifyDNRequest", 13: "ModifyDNResponse", 14: "CompareRequest",
    15: "CompareResponse", 16: "AbandonRequest", 19: "SearchResultReference", 23: "ExtendedRequest",
    24: "ExtendedResponse", 25: "IntermediateResponse",
}
BIND_REQUEST, BIND_RESPONSE, UNBIND, SEARCH_REQUEST, SEARCH_ENTRY, SEARCH_DONE = 0, 1, 2, 3, 4, 5
ABANDON, SEARCH_REFERENCE, EXTENDED_REQUEST, EXTENDED_RESPONSE, INTERMEDIATE = 16, 19, 23, 24, 25
REQUESTS = {0, 2, 3, 6, 8, 10, 12, 14, 16, 23}
NO_RESPONSE = {UNBIND, ABANDON}  # requests that never get one
FINAL_RESPONSES = {1, 5, 7, 9, 11, 13, 15, 24}  # responses that end an operation
RESULT_OPS = FINAL_RESPONSES  # responses that carry an LDAPResult
RESPONSES_FOR = {0: {1}, 3: {4, 5, 19}, 6: {7}, 8: {9}, 10: {11}, 12: {13}, 14: {15}, 23: {24, 25}}

STARTTLS = "1.3.6.1.4.1.1466.20037"
NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036"
EXTENDED_NAMES = {
    STARTTLS: "StartTLS",
    NOTICE_OF_DISCONNECTION: "Notice of Disconnection",
    "1.3.6.1.4.1.4203.1.11.3": "Who am I?",
    "1.3.6.1.4.1.4203.1.11.1": "Password Modify",
    "1.3.6.1.4.1.1466.101.119.1": "Dynamic Refresh",
}
SCOPES = {0: "base", 1: "one", 2: "sub", 3: "children"}

MAX_FILTER = 200  # characters of a rendered filter
RESYNC_WINDOW = 64 * 1024  # bytes to look through for the next message after framing is lost


@dataclass
class Message:
    id: int
    op: int
    offset: int  # stream offset of the message's first byte
    length: int
    ts: float = None  # when its last byte arrived
    frame: int = None
    # bind request
    version: int = None
    dn: str = None  # bind name, entry name or target DN, depending on the operation
    auth: str = None  # "simple" or "sasl"
    password_length: int = None  # simple bind only; the password itself is never kept
    mechanism: str = None  # SASL mechanism
    # search request
    base: str = None
    scope: str = None
    filter: str = None
    attributes: list = field(default_factory=list)  # requested, or names returned in an entry
    # results
    result_code: int = None
    matched_dn: str = None
    diagnostic: str = None
    referrals: list = field(default_factory=list)
    # extended operations
    oid: str = None
    abandon_id: int = None
    controls: list = field(default_factory=list)  # control OIDs

    @property
    def name(self):
        return OPS.get(self.op, f"operation {self.op}")

    @property
    def is_request(self):
        return self.op in REQUESTS

    @property
    def is_starttls(self):
        return self.op in (EXTENDED_REQUEST, EXTENDED_RESPONSE) and self.oid == STARTTLS

    @property
    def extended_name(self):
        return EXTENDED_NAMES.get(self.oid, self.oid) if self.oid else None


@dataclass(frozen=True)
class Problem:
    offset: int
    frame: int
    reason: str


@dataclass
class Parsed:
    """One direction of one connection, decoded."""

    messages: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    tls_from: int = None  # stream offset where TLS records begin, if they do
    tls_frame: int = None
    sasl_from: int = None  # stream offset where SASL-wrapped (signed or sealed) messages begin
    sasl_frame: int = None
    unfinished: int = 0  # bytes at the end that did not make a whole message


def looks_like_tls(data):
    """True if data starts with a TLS record header: handshake, alert, change cipher spec or application
    data, record version 3.x."""
    return len(data) >= 3 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4


def looks_like_sasl_buffer(data):
    """True if data starts like a SASL security-layer buffer (RFC 4422, section 3.7): a 4-byte length,
    which for anything LDAP sends starts with a zero byte, unlike an LDAPMessage (0x30)."""
    if len(data) < 4 or data[0] != 0:
        return False
    return 4 <= int.from_bytes(data[:4], "big") <= ber.MAX_LENGTH


def parse_direction(chunks, starttls_seen=False, sasl_from=None):
    """Decode the chunks of one direction (tcpstream.Chunk). starttls_seen: a StartTLS request has been
    seen on this connection already (for the server's direction). sasl_from: the stream offset after a
    successful SASL bind, from which a SASL buffer ends the readable part."""
    out = Parsed()
    for chunk in chunks:
        data, pos = chunk.data, 0
        while pos < len(data):
            here = chunk.start + pos
            if (starttls_seen or here == 0) and looks_like_tls(data[pos:pos + 3]):
                out.tls_from, out.tls_frame = here, chunk.when(here)[1]
                return out
            if sasl_from is not None and here >= sasl_from and looks_like_sasl_buffer(data[pos:pos + 4]):
                out.sasl_from, out.sasl_frame = here, chunk.when(here)[1]
                return out
            try:
                element = ber.read(data, pos)
            except Incomplete:
                out.unfinished = len(data) - pos
                break
            except BerError as e:
                out.problems.append(Problem(chunk.start + pos, chunk.when(chunk.start + pos)[1], str(e)))
                pos = _resync(data, pos + 1)
                continue
            where = chunk.start + pos
            try:
                msg = decode(element, where)
            except BerError as e:
                out.problems.append(Problem(where, chunk.when(where)[1], f"{e}"))
            else:
                msg.ts, msg.frame = chunk.when(chunk.start + element.end - 1)
                out.messages.append(msg)
                if msg.is_starttls:
                    starttls_seen = True
            pos = element.end
    return out


def _resync(data, pos):
    """The offset of the next element that decodes as an LDAP message, or the end of data."""
    limit = min(len(data), pos + RESYNC_WINDOW)
    while pos < limit:
        if data[pos] == 0x30:
            try:
                decode(ber.read(data, pos), pos)
                return pos
            except BerError:
                pass
        pos += 1
    return len(data)


def decode(element, offset=0):
    """A Message from one LDAPMessage element. Raises BerError if it is not one."""
    ber.expect(element, UNIVERSAL, ber.SEQUENCE, "an LDAPMessage (a SEQUENCE)")
    parts = element.children()
    if len(parts) < 2:
        raise BerError("an LDAPMessage needs a message ID and an operation")
    ident = ber.expect(parts[0], UNIVERSAL, ber.INTEGER, "a message ID").integer()
    if not 0 <= ident <= 2**31 - 1:
        raise BerError(f"message ID {ident} is out of range")
    op = parts[1]
    if op.cls != APPLICATION or op.tag not in OPS:
        raise BerError(f"unknown LDAP operation (tag {op.tag})")
    msg = Message(ident, op.tag, offset, element.end - element.start)
    reader = _READERS.get(op.tag)
    if reader:
        reader(msg, op)
    elif op.tag in RESULT_OPS:
        _result(msg, op.children())
    for extra in parts[2:]:
        if extra.is_(CONTEXT, 0) and extra.constructed:  # controls
            for control in extra.children():
                fields = control.children() if control.constructed else []
                if fields and fields[0].is_(UNIVERSAL, ber.OCTET_STRING):
                    msg.controls.append(fields[0].text())
    return msg


def _bind_request(msg, op):
    fields = op.children()
    if len(fields) < 3:
        raise BerError("a BindRequest needs a version, a name and authentication")
    msg.version = ber.expect(fields[0], UNIVERSAL, ber.INTEGER, "a version").integer()
    msg.dn = text(ber.expect(fields[1], UNIVERSAL, ber.OCTET_STRING, "a bind name").value, limit=None)
    auth = fields[2]
    if auth.is_(CONTEXT, 0) and not auth.constructed:
        msg.auth, msg.password_length = "simple", len(auth.value)
    elif auth.is_(CONTEXT, 3) and auth.constructed:
        sasl = auth.children()
        if not sasl:
            raise BerError("SASL credentials without a mechanism")
        msg.auth, msg.mechanism = "sasl", text(sasl[0].value)
    else:
        raise BerError("unknown bind authentication choice")


def _result(msg, fields):
    """The LDAPResult at the start of fields."""
    if len(fields) < 3:
        raise BerError("an LDAPResult needs a result code, a matched DN and a diagnostic message")
    msg.result_code = ber.expect(fields[0], UNIVERSAL, ber.ENUMERATED, "a result code").integer()
    msg.matched_dn = text(ber.expect(fields[1], UNIVERSAL, ber.OCTET_STRING, "a matched DN").value, limit=None)
    msg.diagnostic = text(ber.expect(fields[2], UNIVERSAL, ber.OCTET_STRING, "a diagnostic message").value,
                          limit=None)
    for f in fields[3:]:
        if f.is_(CONTEXT, 3) and f.constructed:
            msg.referrals = [text(r.value) for r in f.children()]
    return fields[3:]


def _bind_response(msg, op):
    _result(msg, op.children())


def _search_request(msg, op):
    fields = op.children()
    if len(fields) < 8:
        raise BerError("a SearchRequest needs eight fields")
    msg.base = msg.dn = text(ber.expect(fields[0], UNIVERSAL, ber.OCTET_STRING, "a base DN").value, limit=None)
    msg.scope = SCOPES.get(fields[1].integer(), str(fields[1].integer()))
    msg.filter = render_filter(fields[6])
    if fields[7].constructed:
        msg.attributes = [text(a.value) for a in fields[7].children()]


def _search_entry(msg, op):
    fields = op.children()
    if not fields:
        raise BerError("a SearchResultEntry needs an object name")
    msg.dn = text(ber.expect(fields[0], UNIVERSAL, ber.OCTET_STRING, "an object name").value, limit=None)
    if len(fields) > 1 and fields[1].constructed:
        for attr in fields[1].children():
            parts = attr.children() if attr.constructed else []
            if parts:
                msg.attributes.append(text(parts[0].value))


def _search_reference(msg, op):
    if op.constructed:
        msg.referrals = [text(r.value) for r in op.children()]


def _extended_request(msg, op):
    fields = op.children()
    if not fields or not fields[0].is_(CONTEXT, 0):
        raise BerError("an ExtendedRequest needs a request name")
    msg.oid = fields[0].text()


def _extended_response(msg, op):
    for f in _result(msg, op.children()):
        if f.is_(CONTEXT, 10):
            msg.oid = f.text()


def _abandon(msg, op):
    msg.abandon_id = ber.to_integer(op.value)


def _delete(msg, op):
    msg.dn = text(op.value, limit=None)


def _nothing(msg, op):
    """UnbindRequest: NULL."""


_READERS = {
    BIND_REQUEST: _bind_request,
    BIND_RESPONSE: _bind_response,
    UNBIND: _nothing,
    SEARCH_REQUEST: _search_request,
    SEARCH_ENTRY: _search_entry,
    SEARCH_REFERENCE: _search_reference,
    EXTENDED_REQUEST: _extended_request,
    EXTENDED_RESPONSE: _extended_response,
    ABANDON: _abandon,
    10: _delete,
}


# --- search filters, as RFC 4515 text ---------------------------------------------------

def render_filter(element):
    """The filter as text, e.g. "(&(objectClass=person)(uid=dave))"; shortened past MAX_FILTER characters."""
    try:
        s = _filter(element, 0)
    except BerError:
        return "(unreadable filter)"
    return s if len(s) <= MAX_FILTER else s[:MAX_FILTER] + "..."


def _filter(e, depth):
    if depth > ber.MAX_DEPTH:
        raise BerError("filter nested too deep")
    if e.cls != CONTEXT:
        raise BerError("not a filter")
    if e.tag in (0, 1):  # and, or
        return "(" + "&|"[e.tag] + "".join(_filter(c, depth + 1) for c in e.children(depth)) + ")"
    if e.tag == 2:  # not
        inner = e.children(depth)
        if len(inner) != 1:
            raise BerError("a NOT filter holds one filter")
        return "(!" + _filter(inner[0], depth + 1) + ")"
    if e.tag in (3, 5, 6, 8):  # equality, >=, <=, approx
        ava = e.children(depth)
        if len(ava) != 2:
            raise BerError("an attribute value assertion needs two parts")
        op = {3: "=", 5: ">=", 6: "<=", 8: "~="}[e.tag]
        return f"({_attr(ava[0].value)}{op}{_escape(ava[1].value)})"
    if e.tag == 4:  # substrings
        parts = e.children(depth)
        if len(parts) != 2:
            raise BerError("a substrings filter needs a type and substrings")
        initial, anys, final = "", [], ""
        for s in parts[1].children(depth):
            if s.tag == 0:
                initial = _escape(s.value)
            elif s.tag == 1:
                anys.append(_escape(s.value))
            elif s.tag == 2:
                final = _escape(s.value)
        return f"({_attr(parts[0].value)}={initial}*{''.join(a + '*' for a in anys)}{final})"
    if e.tag == 7:  # present
        return f"({_attr(e.value)}=*)"
    if e.tag == 9:  # extensible match
        rule, attr, value, dn = None, "", b"", False
        for p in e.children(depth):
            if p.tag == 1:
                rule = _attr(p.value)
            elif p.tag == 2:
                attr = _attr(p.value)
            elif p.tag == 3:
                value = p.value
            elif p.tag == 4:
                dn = p.value not in (b"", b"\x00")
        return f"({attr}{':dn' if dn else ''}{':' + rule if rule else ''}:={_escape(value)})"
    raise BerError(f"unknown filter choice {e.tag}")


def _attr(value):
    return text(value, limit=None)


def _escape(value):
    """RFC 4515 escaping: the special characters and anything outside printable ASCII as \\hh."""
    return "".join(chr(b) if 0x20 <= b < 0x7F and chr(b) not in "*()\\" else f"\\{b:02x}" for b in value)
