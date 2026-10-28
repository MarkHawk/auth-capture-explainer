"""LDAP connections: what kind each is, and its requests paired with responses.

Each TCP connection on an LDAP port is one of:

- "ldap": clear-text LDAP, decoded and paired;
- "starttls": clear-text LDAP until a StartTLS, then TLS. What came before
  is paired as usual; nothing after it can be read;
- "tls": TLS from the first byte (LDAPS on 636, or TLS on a port the user
  named). Nothing inside can be read, only the handshake's clear-text parts;
- "sasl": clear-text LDAP until a SASL bind succeeds and negotiates a
  security layer (Kerberos or NTLM signing or sealing, the Active Directory
  default), then wrapped messages that cannot be read. The bind exchange is
  paired as usual, and the wrapped part is not reported as damage;
- "empty": no payload at all (a connection refused or never used);
- "unreadable": bytes that are neither LDAP nor the start of TLS, usually a
  connection the capture joined part-way through.

Requests pair with responses by message ID within a connection. A search
collects its entries and references until SearchResultDone. Unbind and
Abandon expect no response. A message ID 0 ExtendedResponse is the server's
unsolicited Notice of Disconnection, kept apart.
"""

from dataclasses import dataclass, field

from auth_capture_explainer import ldap, tcpstream, tls
from auth_capture_explainer.ldap import EXTENDED_RESPONSE, FINAL_RESPONSES, NO_RESPONSE, RESPONSES_FOR, SEARCH_ENTRY
from auth_capture_explainer.tls import TlsInfo

LDAP, STARTTLS, TLS, SASL, EMPTY, UNREADABLE = "ldap", "starttls", "tls", "sasl", "empty", "unreadable"


@dataclass(frozen=True)
class Ports:
    clear: frozenset = frozenset({389, 3268})
    tls: frozenset = frozenset({636, 3269})
    extra: frozenset = frozenset()  # given by the user; clear or TLS is told from the bytes

    LABELS = {636: "LDAPS", 3268: "Global Catalog", 3269: "Global Catalog over TLS"}

    @property
    def all(self):
        return self.clear | self.tls | self.extra

    def label(self, port):
        if port in self.LABELS and port in (self.clear | self.tls):
            return f"{port} ({self.LABELS[port]})"
        if port in self.extra:
            return f"{port} (non-standard port)"
        return str(port)

    def with_extra(self, ports):
        return Ports(self.clear, self.tls, frozenset(self.extra | set(ports)))


DEFAULT_PORTS = Ports()


@dataclass(eq=False)
class Operation:
    request: ldap.Message
    responses: list = field(default_factory=list)  # entries, references, intermediate responses
    result: ldap.Message = None  # the response that ends the operation
    abandoned: bool = False
    abandoned_at: float = None  # when the client sent the Abandon

    @property
    def name(self):
        return self.request.name

    @property
    def expects_response(self):
        return self.request.op not in NO_RESPONSE

    @property
    def answered(self):
        return self.result is not None

    @property
    def response_time(self):
        """Seconds from the request's last byte to the final response's last byte."""
        return None if self.result is None else self.result.ts - self.request.ts

    @property
    def first_response_time(self):
        first = self.responses[0] if self.responses else self.result
        return None if first is None else first.ts - self.request.ts

    @property
    def entries(self):
        return sum(1 for m in self.responses if m.op == SEARCH_ENTRY)

    @property
    def references(self):
        return sum(1 for m in self.responses if m.op == ldap.SEARCH_REFERENCE)


@dataclass(eq=False)
class Connection:
    stream: tcpstream.Stream
    port_label: str
    kind: str = LDAP
    operations: list = field(default_factory=list)
    orphan_responses: list = field(default_factory=list)  # responses to requests not in the capture
    notices: list = field(default_factory=list)  # Notice of Disconnection and other unsolicited responses
    problems: list = field(default_factory=list)  # ldap.Problem, from either direction
    tls: TlsInfo = None  # not tls.TlsInfo: the field's name would hide the module before Python 3.14
    tls_frame: int = None  # where TLS starts
    sasl_mechanism: str = None  # the SASL bind that started the security layer
    sasl_frame: int = None  # where the wrapped messages start
    unfinished: int = 0  # bytes at the end of either direction that did not make a whole message

    @property
    def client(self):
        return self.stream.client

    @property
    def server(self):
        return self.stream.server

    @property
    def server_port(self):
        return self.stream.server_port

    @property
    def encrypted(self):
        return self.kind in (TLS, STARTTLS)

    @property
    def protected(self):
        """Some or all of the connection cannot be read: TLS, or a SASL security layer."""
        return self.kind in (TLS, STARTTLS, SASL)

    @property
    def gaps(self):
        return self.stream.to_server.gaps + self.stream.to_client.gaps


@dataclass
class Result:
    ports: Ports
    connections: list = field(default_factory=list)


def analyse(packets, ports=DEFAULT_PORTS):
    result = Result(ports)
    for stream in tcpstream.streams(packets, ports.all):
        result.connections.append(_connection(stream, ports))
    result.connections.sort(key=lambda c: (c.stream.first_ts, c.stream.first_frame))
    return result


def _connection(stream, ports):
    conn = Connection(stream, ports.label(stream.server_port))
    up, down = stream.to_server, stream.to_client
    if not up.chunks and not down.chunks:
        conn.kind = EMPTY
        return conn
    client = ldap.parse_direction(up.chunks)
    starttls_asked = any(m.is_starttls and m.is_request for m in client.messages)
    if client.tls_from == 0 or (not client.messages and _starts_with_tls(down)):
        conn.kind = TLS
        conn.tls_frame = client.tls_frame or _first_frame(down)
        conn.tls = tls.inspect(_bytes_from(up, 0), _bytes_from(down, 0))
        return conn
    server = ldap.parse_direction(down.chunks, starttls_seen=starttls_asked)
    conn.problems = sorted(client.problems + server.problems, key=lambda p: p.offset)
    conn.unfinished = client.unfinished + server.unfinished
    if not client.messages and not server.messages:
        conn.kind = UNREADABLE
        return conn
    if client.tls_from is not None or server.tls_from is not None:
        conn.kind = STARTTLS
        conn.tls_frame = min(f for f in (client.tls_frame, server.tls_frame) if f is not None)
        conn.tls = tls.inspect(_bytes_from(up, client.tls_from), _bytes_from(down, server.tls_from))
    _pair(conn, client.messages, server.messages)
    bind = _sasl_layer_bind(conn)
    if bind is not None and conn.kind == LDAP:
        # Read again, stopping where the security layer starts, so its wrapped messages are not
        # mistaken for damaged LDAP.
        client = ldap.parse_direction(up.chunks, sasl_from=bind.request.offset + bind.request.length)
        server = ldap.parse_direction(down.chunks, sasl_from=bind.result.offset + bind.result.length)
        if client.sasl_from is not None or server.sasl_from is not None:
            conn.kind, conn.sasl_mechanism = SASL, bind.request.mechanism
            conn.sasl_frame = min(f for f in (client.sasl_frame, server.sasl_frame) if f is not None)
            conn.problems = sorted(client.problems + server.problems, key=lambda p: p.offset)
            conn.unfinished = client.unfinished + server.unfinished
            conn.operations, conn.orphan_responses, conn.notices = [], [], []
            _pair(conn, client.messages, server.messages)
    return conn


def _sasl_layer_bind(conn):
    """The first SASL bind that succeeded: after it, a security layer may wrap every message."""
    return next((op for op in conn.operations if op.request.op == ldap.BIND_REQUEST
                 and op.request.auth == "sasl" and op.answered and op.result.result_code == 0), None)


def _starts_with_tls(direction):
    return bool(direction.chunks) and direction.chunks[0].start == 0 and ldap.looks_like_tls(direction.chunks[0].data)


def _first_frame(direction):
    return direction.chunks[0].when(direction.chunks[0].start)[1] if direction.chunks else None


def _bytes_from(direction, offset):
    """The contiguous bytes of a direction from a stream offset (to the end of that chunk)."""
    if offset is None:
        return b""
    for chunk in direction.chunks:
        if chunk.start <= offset < chunk.end:
            return chunk.data[offset - chunk.start:]
    return b""


def _pair(conn, requests, responses):
    pending = {}
    ordered = sorted([(m.ts, 0, m) for m in requests] + [(m.ts, 1, m) for m in responses],
                     key=lambda x: (x[0], x[1]))
    for _, from_server, m in ordered:
        if not from_server:
            if not m.is_request:
                conn.problems.append(ldap.Problem(m.offset, m.frame, f"the client sent a {m.name}"))
                continue
            op = Operation(m)
            conn.operations.append(op)
            if m.op == ldap.ABANDON and m.abandon_id in pending:
                pending[m.abandon_id].abandoned, pending[m.abandon_id].abandoned_at = True, m.ts
            if op.expects_response:
                pending[m.id] = op
            continue
        if m.id == 0 and m.op == EXTENDED_RESPONSE:
            conn.notices.append(m)
            continue
        op = pending.get(m.id)
        if op is None or m.op not in RESPONSES_FOR.get(op.request.op, ()):
            conn.orphan_responses.append(m)
            continue
        if m.op in FINAL_RESPONSES:
            op.result = m
            del pending[m.id]
        else:
            op.responses.append(m)
