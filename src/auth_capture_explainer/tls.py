"""Read what a TLS connection shows in clear, and nothing more.

auth-capture-explainer never decrypts. What TLS leaves in clear is still useful
when an encrypted LDAP connection fails:

- the ClientHello: the TLS versions the client offers and the server name
  it asks for (SNI);
- the ServerHello: the version the server picks;
- alerts sent before encryption starts, such as unknown_ca when the client
  does not trust the server's certificate (in TLS 1.2);
- whether the handshake completed and data flowed.

TLS 1.3 needs care. Everything after the ServerHello, including the
server's certificate, the client's Finished and any alert, travels as
encrypted records of the application-data type, so seeing such records from
both sides proves nothing. A TLS 1.3 handshake counts as complete only when
the client sent more than one of them (its Finished, then data). One that
stops short is reported as consistent with an encrypted alert, which is how
a client rejecting the server's certificate looks in TLS 1.3. Not seeing an
alert never counts as there being no trust problem.

Records are read up to MAX_RECORDS or MAX_BYTES per direction, and every
length is checked first. Anything that does not parse just ends the reading
of that direction; this is metadata, and a damaged record never stops the
rest of the report.
"""

import struct
from dataclasses import dataclass, field

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 20, 21, 22, 23
CLIENT_HELLO, SERVER_HELLO = 1, 2
EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS = 0, 43
MAX_RECORDS = 64
MAX_BYTES = 256 * 1024
# An encrypted TLS 1.3 alert: 2 bytes, the inner content type, a 16-byte tag, and perhaps some padding.
# A Finished is at least 4 + 32 + 1 + 16 = 53 bytes, so anything up to this size is alert-sized.
ALERT_RECORD_MAX = 40

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}


def version_name(v):
    return VERSIONS.get(v, f"version 0x{v:04x}")


@dataclass(frozen=True)
class Alert:
    side: str  # "client" or "server": who sent it
    level: str  # "warning", "fatal", or None when encrypted
    description: str  # e.g. "unknown_ca", or "encrypted" when it cannot be read


@dataclass
class TlsInfo:
    client_versions: list = field(default_factory=list)  # names, highest first
    server_name: str = None  # SNI
    server_version: str = None  # the version the server picked
    alerts: list = field(default_factory=list)
    client_records: list = field(default_factory=list)  # lengths of the client's application-data records
    server_records: list = field(default_factory=list)
    client_hello: bool = False
    server_hello: bool = False

    @property
    def client_data(self):
        return bool(self.client_records)

    @property
    def server_data(self):
        return bool(self.server_records)

    @property
    def tls13(self):
        return self.server_version == "TLS 1.3"

    @property
    def completed(self):
        """The handshake finished and data flowed. In TLS 1.3 the client's first encrypted record is its
        Finished (or an alert), so data has flowed only once it sends another."""
        if self.tls13:
            return len(self.client_records) >= 2 and self.server_data
        return self.client_data and self.server_data

    @property
    def plaintext_alerts(self):
        return [a for a in self.alerts if a.level is not None]

    @property
    def alert_sized_close(self):
        """TLS 1.3: the client's only encrypted record is the size of an alert, not of a Finished."""
        return self.tls13 and len(self.client_records) == 1 and self.client_records[0] <= ALERT_RECORD_MAX

    def outcome(self):
        """One or two sentences on how the handshake went, for a report. Never claims there was no trust
        problem: in TLS 1.3 a certificate or trust alert is encrypted and cannot be seen."""
        alerts = self.plaintext_alerts
        if alerts:
            a = alerts[0]
            who = "The client" if a.side == "client" else "The server"
            return f"{who} sent a {a.level} {a.description} alert, so the handshake failed."
        if not self.client_hello:
            return "The start of the TLS handshake is not in the capture, so how it went cannot be told."
        if not self.server_hello:
            return ("The client opened a TLS handshake and the server never answered it with a ServerHello: the "
                    "server does not speak TLS on this port, or the connection was cut.")
        if self.completed:
            return "The TLS handshake completed and data flowed both ways."
        if self.tls13:
            ended = ("the client sent one encrypted record the size of an alert and nothing more"
                     if self.alert_sized_close else "no application data followed")
            return ("The TLS 1.3 handshake ended after the ServerHello: " + ended + ". That is consistent with an "
                    "encrypted certificate or trust alert, such as the client not trusting the server's "
                    "certificate. TLS 1.3 encrypts alerts, so not seeing one does not rule a trust problem out.")
        return ("The TLS handshake ended after the ServerHello with no application data and no alert in clear. A "
                "certificate or trust problem is not ruled out.")


def inspect(client_bytes, server_bytes):
    """TlsInfo from the first bytes of each direction (each starting at a TLS record)."""
    info = TlsInfo()
    _direction(client_bytes, "client", info)
    _direction(server_bytes, "server", info)
    return info


def _direction(data, side, info):
    pos, records, encrypted = 0, 0, False
    data = data[:MAX_BYTES]
    while pos + 5 <= len(data) and records < MAX_RECORDS:
        ctype, _version, length = struct.unpack_from("!BHH", data, pos)
        body = data[pos + 5:pos + 5 + length]
        if ctype not in (CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA) or len(body) < length:
            return
        records += 1
        pos += 5 + length
        if ctype == CHANGE_CIPHER_SPEC:
            encrypted = True
        elif ctype == APPLICATION_DATA:
            getattr(info, f"{side}_records").append(length)
            encrypted = True  # TLS 1.3 sends everything after ServerHello as application data
        elif ctype == ALERT:
            if not encrypted and length == 2:
                level = {1: "warning", 2: "fatal"}.get(body[0], f"level {body[0]}")
                info.alerts.append(Alert(side, level, ALERTS.get(body[1], f"alert {body[1]}")))
            else:
                info.alerts.append(Alert(side, None, "encrypted"))
        elif ctype == HANDSHAKE and not encrypted:
            _handshake(body, side, info)


def _handshake(body, side, info):
    """The hello in the first handshake record (a hello is never fragmented in practice)."""
    if len(body) < 4:
        return
    htype = body[0]
    length = int.from_bytes(body[1:4], "big")
    msg = body[4:4 + length]
    try:
        if htype == CLIENT_HELLO and side == "client":
            _client_hello(msg, info)
        elif htype == SERVER_HELLO and side == "server":
            _server_hello(msg, info)
    except (struct.error, IndexError, ValueError):
        return


def _client_hello(msg, info):
    info.client_hello = True
    legacy = struct.unpack_from("!H", msg, 0)[0]
    pos = 2 + 32
    pos += 1 + msg[pos]  # session id
    pos += 2 + struct.unpack_from("!H", msg, pos)[0]  # cipher suites
    pos += 1 + msg[pos]  # compression methods
    offered = [legacy]
    for ext, value in _extensions(msg, pos):
        if ext == EXT_SERVER_NAME and len(value) >= 5 and value[2] == 0:
            name_len = struct.unpack_from("!H", value, 3)[0]
            info.server_name = value[5:5 + name_len].decode("ascii", errors="backslashreplace")
        elif ext == EXT_SUPPORTED_VERSIONS and value:
            n = value[0]
            offered = [struct.unpack_from("!H", value, 1 + i)[0] for i in range(0, n - 1, 2)]
    known = sorted({v for v in offered if v in VERSIONS}, reverse=True)  # drops GREASE values
    info.client_versions = [version_name(v) for v in known]


def _server_hello(msg, info):
    info.server_hello = True
    chosen = struct.unpack_from("!H", msg, 0)[0]
    pos = 2 + 32
    pos += 1 + msg[pos]  # session id
    pos += 2 + 1  # cipher suite, compression method
    for ext, value in _extensions(msg, pos):
        if ext == EXT_SUPPORTED_VERSIONS and len(value) == 2:
            chosen = struct.unpack("!H", value)[0]
    info.server_version = version_name(chosen)


def _extensions(msg, pos):
    if pos + 2 > len(msg):
        return
    end = min(len(msg), pos + 2 + struct.unpack_from("!H", msg, pos)[0])
    pos += 2
    while pos + 4 <= end:
        ext, length = struct.unpack_from("!HH", msg, pos)
        yield ext, msg[pos + 4:pos + 4 + length]
        pos += 4 + length
