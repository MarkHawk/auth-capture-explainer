"""Pair RADIUS requests with their replies, and summarise by conversation.

An exchange is one request and its reply. A reply belongs to the request
with the same identifier, sent from the client's address and port to the
server's, which is how a NAS matches them itself; capture order does not
matter, so replies that arrive out of order still pair up.

What a NAS does when no reply comes is recorded rather than smoothed over:

- the same request again (same ID, same client port, within
  RETRANSMIT_WINDOW) is a retransmission of the same exchange. Most clients
  resend the identical bytes; a resend whose bytes differ (an accounting
  request with an updated Acct-Delay-Time) is counted as changed;
- a fresh request for the same user to the same server soon after an
  unanswered one is linked to it as a retry with a new ID;
- an ICMP error about a request (the server's port is unreachable, or a
  firewall refused it) or about a reply (the NAS had stopped listening) is
  attached to the exchange it concerns.

Timing: response_time runs from the latest attempt before the reply to the
reply, so a retransmission does not inflate it; total_time runs from the
first attempt. Access-Reject is summarised apart from the other replies,
because servers delay rejects on purpose (FreeRADIUS waits a second by
default, as a brake on password guessing), and counting that delay would
make every server with a wrong-password login look slow.
"""

from collections import Counter
from dataclasses import dataclass, field

from pcap_analyser import radius
from pcap_analyser.latency import Summary
from pcap_analyser.radius_dict import (
    ACCESS_REJECT,
    ACCESS_REQUEST,
    ACCOUNTING_REQUEST,
    ACCT_SESSION_ID,
    REPLIES,
    REPLY_MESSAGE,
    USER_NAME,
    code_name,
    text,
)

RETRANSMIT_WINDOW = 30.0  # seconds: the same ID again within this is a resend, not a new request
RETRY_WINDOW = 60.0  # seconds: a new ID for the same user after no reply is a retry
REPLY_DUE = 5.0  # seconds: a lone request this close to the end of the capture may be answered after it

NO_REPLY = "no reply"
CAPTURE_ENDED = "no reply before the capture ended"


@dataclass(eq=False)
class Exchange:
    client: str
    client_port: int
    server: str
    server_port: int
    id: int
    code: int
    attempts: list = field(default_factory=list)  # radius.Message: the request, then each resend
    reply: object = None  # radius.Message
    extra_replies: list = field(default_factory=list)  # further replies to the same request
    reply_from_elsewhere: bool = False  # the reply came from a different address or port than was asked
    icmp: list = field(default_factory=list)  # (layers.Packet, "request" or "reply")
    retry_of: object = None  # an earlier unanswered Exchange this re-sends under a new ID
    changed_resends: int = 0
    capture_end: float = None

    @property
    def request(self):
        return self.attempts[0]

    @property
    def name(self):
        return code_name(self.code)

    @property
    def retransmissions(self):
        return len(self.attempts) - 1

    @property
    def answered(self):
        return self.reply is not None

    @property
    def outcome(self):
        if self.reply is not None:
            return self.reply.name
        # A request sent just before the capture stopped may have been answered after it. Once the
        # client has resent it, though, the earlier attempts plainly went unanswered.
        if (not self.retransmissions and self.capture_end is not None
                and self.capture_end - self.attempts[-1].packet.ts < REPLY_DUE):
            return CAPTURE_ENDED
        return NO_REPLY

    @property
    def response_time(self):
        """Seconds from the latest attempt sent before the reply, to the reply."""
        if self.reply is None:
            return None
        sent = [a.packet.ts for a in self.attempts if a.packet.ts <= self.reply.packet.ts]
        return self.reply.packet.ts - (sent[-1] if sent else self.attempts[0].packet.ts)

    @property
    def total_time(self):
        if self.reply is None:
            return None
        return self.reply.packet.ts - self.attempts[0].packet.ts

    @property
    def span(self):
        """Seconds from the first attempt to the last."""
        return self.attempts[-1].packet.ts - self.attempts[0].packet.ts

    @property
    def user_name(self):
        attr = self.request.get(USER_NAME)
        return text(attr.value) if attr else None

    @property
    def reply_messages(self):
        if self.reply is None:
            return []
        return [text(a.value) for a in self.reply.all(REPLY_MESSAGE)]

    def subject(self):
        """What the request is about, for spotting a retry under a new ID."""
        if self.code == ACCOUNTING_REQUEST:
            attr = self.request.get(ACCT_SESSION_ID)
        else:
            attr = self.request.get(USER_NAME)
        return attr.value if attr else None


@dataclass
class Conversation:
    """Every exchange between one client and one server port (or, with client None, all clients)."""

    client: str
    server: str
    server_port: int
    exchanges: list = field(default_factory=list)

    @property
    def requests(self):
        return len(self.exchanges)

    @property
    def retransmissions(self):
        return sum(e.retransmissions for e in self.exchanges)

    @property
    def answered(self):
        return sum(1 for e in self.exchanges if e.answered)

    @property
    def outcomes(self):
        return Counter(e.outcome for e in self.exchanges)

    @property
    def response_times(self):
        """Every reply except Access-Reject (see the module docstring)."""
        return Summary.of(e.response_time for e in self.exchanges
                          if e.answered and e.reply.code != ACCESS_REJECT)

    @property
    def reject_times(self):
        return Summary.of(e.response_time for e in self.exchanges if e.answered and e.reply.code == ACCESS_REJECT)


@dataclass
class Result:
    ports: radius.Ports
    exchanges: list = field(default_factory=list)
    orphan_replies: list = field(default_factory=list)  # replies whose request is not in the capture
    malformed: list = field(default_factory=list)  # radius.Malformed
    stray_icmp: list = field(default_factory=list)  # ICMP errors about RADIUS ports matching no exchange

    def conversations(self):
        return _group(self.exchanges, lambda e: (e.client, e.server, e.server_port))

    def servers(self):
        return _group(self.exchanges, lambda e: (None, e.server, e.server_port))


def _group(exchanges, key):
    groups = {}
    for e in exchanges:
        k = key(e)
        if k not in groups:
            groups[k] = Conversation(*k)
        groups[k].exchanges.append(e)
    return list(groups.values())


def analyse(packets, ports=radius.DEFAULT_PORTS, capture_end=None):
    """Find, decode and pair every RADIUS message in packets (layers.Packet, any order)."""
    messages, malformed = radius.find(packets, ports)
    result = Result(ports, malformed=malformed)
    messages.sort(key=lambda m: (m.packet.ts, m.packet.frame))
    latest = {}  # (client, client_port, server, server_port, id) -> the newest Exchange with that key
    for m in messages:
        if m.is_request:
            _request(m, latest, result, capture_end)
        else:
            _reply(m, latest, result)
    _attach_icmp(packets, result, ports)
    return result


def _request(m, latest, result, capture_end):
    p = m.packet
    key = (p.src, p.sport, p.dst, p.dport, m.id)
    ex = latest.get(key)
    if (ex is not None and ex.reply is None and ex.code == m.code
            and p.ts - ex.attempts[-1].packet.ts <= RETRANSMIT_WINDOW):
        if m.raw != ex.attempts[0].raw:
            ex.changed_resends += 1
        ex.attempts.append(m)
        return
    ex = Exchange(p.src, p.sport, p.dst, p.dport, m.id, m.code, [m], capture_end=capture_end)
    ex.retry_of = _retried(ex, result.exchanges)
    latest[key] = ex
    result.exchanges.append(ex)


def _retried(ex, earlier):
    """The latest unanswered exchange that ex re-sends under a new ID, if any."""
    subject = ex.subject()
    if subject is None or ex.code not in (ACCESS_REQUEST, ACCOUNTING_REQUEST):
        return None
    for old in reversed(earlier):
        if (old.client, old.server, old.server_port, old.code) != (ex.client, ex.server, ex.server_port, ex.code):
            continue
        if ex.request.packet.ts - old.attempts[-1].packet.ts > RETRY_WINDOW:
            return None
        if old.subject() == subject:
            return old if old.reply is None else None  # answered: this is a new login, not a retry
    return None


def _reply(m, latest, result):
    p = m.packet
    ex = latest.get((p.dst, p.dport, p.src, p.sport, m.id))
    elsewhere = False
    if ex is None or m.code not in REPLIES.get(ex.code, ()):
        # A reply from another address or port than the request went to: a multi-homed server
        # or NAT. The NAS will usually discard it, so it is worth saying.
        ex = next((e for e in reversed(result.exchanges)
                   if (e.client, e.client_port, e.id) == (p.dst, p.dport, m.id)
                   and m.code in REPLIES.get(e.code, ()) and e.reply is None), None)
        elsewhere = ex is not None
    if ex is None:
        result.orphan_replies.append(m)
    elif ex.reply is None:
        ex.reply, ex.reply_from_elsewhere = m, elsewhere
    else:
        ex.extra_replies.append(m)


def _attach_icmp(packets, result, ports):
    wanted = ports.all
    for p in packets:
        if p.proto != "icmp" or p.icmp.proto != "udp":
            continue
        q = p.icmp
        if q.dport in wanted:  # it complains about a request: the original went client -> server
            match, about = (q.src, q.sport, q.dst, q.dport), "request"
        elif q.sport in wanted:  # it complains about a reply: the original went server -> client
            match, about = (q.dst, q.dport, q.src, q.sport), "reply"
        else:
            continue
        candidates = [e for e in result.exchanges
                      if (e.client, e.client_port, e.server, e.server_port) == match
                      and e.attempts[0].packet.ts <= p.ts]
        if candidates:
            candidates[-1].icmp.append((p, about))
        else:
            result.stray_icmp.append(p)
