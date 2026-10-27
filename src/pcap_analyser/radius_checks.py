"""Turn paired RADIUS exchanges into findings, per server and NAS.

A RADIUS server keeps one client entry per NAS, each with its own shared
secret, so the unit here is the pair: one NAS (client) talking to one server
address and port. Every finding carries details["pair"], and causes.py names
one likely cause per pair. Two NASes failing for different reasons against
the same server therefore read as two stories, not one blurred one.

What happens to other pairs on the same server is still context for a pair
(the server answering other NASes, another client entry verifying with the
secret given), and is passed along as details. It is only ever used to
support a conclusion about this pair, never to argue against one: another
client entry may legitimately hold a different secret.

Where the capture was taken matters for "no reply": a request seen arriving
at the server rules out a firewall in between, while the same silence seen
from the NAS does not. Linux cooked captures and pcapng record which way each
packet went on the capturing host, and capture_point() reads that; the user
can also say with captured_on. The reasoning is spelled out in the finding,
because a reader should be able to check it.
"""

import ipaddress
from collections import Counter
from dataclasses import dataclass

from pcap_analyser import radius_auth
from pcap_analyser import radius_exchange as rx
from pcap_analyser.findings import Finding, Status
from pcap_analyser.latency import Summary
from pcap_analyser.radius_dict import (
    ACCESS_CHALLENGE,
    ACCESS_REJECT,
    ACCESS_REQUEST,
    MESSAGE_AUTHENTICATOR,
    NAS_IDENTIFIER,
    STATUS_SERVER,
    text,
)
from pcap_analyser.wording import article, listing, plural, secs, times

SLOW = 1.0  # seconds at p95, for replies other than Access-Reject: a NAS typically times out at 2 to 5 s
SECRET_HELP = "--secret (prompts), --secret-file or --secret-env"
SIGNED_REQUESTS = (ACCESS_REQUEST, STATUS_SERVER)


@dataclass(frozen=True)
class CapturePoint:
    where: str  # "server", "client", "path" or None when the capture does not say
    certain: bool  # True when packet directions (or the user) settle it
    reason: str  # one or two sentences, for the report
    loopback_answering: bool = False  # the capturing host also answers RADIUS on its loopback address


def server_key(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def pair_key(client, server, port):
    return f"{client} -> {server_key(server, port)}"


def server_label(address, port, ports):
    """e.g. "192.0.2.2:1812" or "192.0.2.2:1645 (legacy authentication port)"."""
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{ports.label(port)}"


def is_loopback(address):
    return ipaddress.ip_address(address).is_loopback


def client_label(address, exchanges):
    """The client's address, with the NAS-Identifier it gives when it gives one."""
    names = sorted({text(a.value) for e in exchanges if e.client == address
                    for a in e.request.all(NAS_IDENTIFIER)})
    if len(names) == 1:
        return f'{address} (NAS-Identifier "{names[0]}")'
    return address


def is_loopback_pair(conv):
    return is_loopback(conv.client) or is_loopback(conv.server)


@dataclass
class Pair:
    """One NAS and one server port, with what the rest of the capture says around them."""

    client: str
    server: str
    port: int
    exchanges: list  # this pair's
    server_exchanges: list  # every exchange with this server port, from any client
    everything: list  # every exchange in the capture
    ports: object
    label: str  # the server's
    who: str  # the client's

    @property
    def others_answered(self):
        """Other clients the same server port answered."""
        return list(dict.fromkeys(e.client for e in self.server_exchanges if e.client != self.client and e.answered))


def check(result, secret=None, captured_on=None):
    """Findings for a radius_exchange.Result. secret: a secret.Secret or None."""
    findings = []
    if not result.exchanges and not result.orphan_replies and not result.malformed:
        return findings
    convs = sorted(result.conversations(), key=is_loopback_pair)  # health checks on loopback last
    for conv in convs:
        server_exchanges = [e for e in result.exchanges if (e.server, e.server_port) == (conv.server, conv.server_port)]
        pair = Pair(conv.client, conv.server, conv.server_port, conv.exchanges, server_exchanges, result.exchanges,
                    result.ports, server_label(conv.server, conv.server_port, result.ports),
                    client_label(conv.client, conv.exchanges))
        findings += _pair_findings(pair, secret, captured_on)
    findings += _global_findings(result, secret)
    return findings


def _pair_findings(pair, secret, captured_on):
    ctx = dict(pair=pair_key(pair.client, pair.server, pair.port), server=server_key(pair.server, pair.port),
               server_label=pair.label, client=pair.client, client_label=pair.who,
               loopback=is_loopback(pair.client) or is_loopback(pair.server))
    unanswered = [e for e in pair.exchanges if e.outcome == rx.NO_REPLY]
    point = capture_point(pair.exchanges, captured_on, pair.everything) if unanswered else None
    out = []
    for make in (_unanswered, _capture_point, _capture_ended, _answering, _icmp, _message_authenticator,
                 _reply_message_authenticator, _message_authenticator_position, _rejects, _challenges,
                 _response_time, _reply_from_elsewhere, _reused_ids, _legacy_port):
        f = make(pair, point)
        if f is not None:
            f.details = {**ctx, **f.details}
            out.append(f)
    if secret is not None:
        f = _secret(pair, secret)
        f.details = {**ctx, **f.details}
        out.append(f)
    return out


def _global_findings(result, secret):
    out = []
    if result.malformed:
        first = min(result.malformed, key=lambda m: m.packet.frame)
        reasons = Counter(m.reason for m in result.malformed)
        out.append(Finding(
            "radius.malformed", Status.WARN, "Unreadable RADIUS",
            f"{plural(len(result.malformed), 'packet')} on RADIUS ports could not be read as RADIUS "
            f"(first at frame {first.packet.frame}: {first.reason}). They are left out of everything else.",
            details={"count": len(result.malformed), "reasons": dict(reasons), "first_frame": first.packet.frame}))
    if result.orphan_replies:
        n = len(result.orphan_replies)
        out.append(Finding(
            "radius.orphan_replies", Status.INFO, "Replies without requests",
            f"{plural(n, 'reply', 'replies')} answer{'s' if n == 1 else ''} a request that is not in the capture, "
            "usually because the capture started after the request was sent.",
            details={"count": n}))
    if secret is None and result.exchanges:
        out.append(Finding(
            "radius.secret", Status.SKIP, "Shared secret",
            f"Not checked. Add {SECRET_HELP} to check the shared secret against these packets.",
            details={"given": False}))
    elif secret is not None:
        for note in secret.warnings():
            out.append(Finding("radius.secret_shape", Status.INFO, "Secret given", note))
    return out


# --- capture point ---------------------------------------------------------------

def capture_point(exchanges, captured_on=None, everything=()):
    """Where the capture was taken, judged from one pair's requests and replies.
    everything: all exchanges in the capture, to spot a RADIUS server answering on loopback."""
    if captured_on in ("server", "client"):
        return CapturePoint(captured_on, True, f"You said the capture was taken on the {captured_on}.")
    remote = [e for e in exchanges if not is_loopback(e.server) and not is_loopback(e.client)]
    requests = [a for e in remote for a in e.attempts]
    replies = [r for e in remote for r in ([e.reply] if e.reply else []) + e.extra_replies]
    seen = {}
    for m in requests:
        # A router sees each request arrive and leave: same bytes, moments apart, both directions.
        seen.setdefault((m.packet.src, m.packet.sport, m.id, m.authenticator), set()).add(m.packet.direction)
    if any({"in", "out"} <= d for d in seen.values()):
        return CapturePoint("path", True, "Each request was seen both arriving and leaving, so the capture was "
                                          "taken on a router or firewall between the client and the server.")
    if any(r.packet.direction == "out" for r in replies):
        return CapturePoint("server", True, "The server's replies are marked as leaving this host, so the capture "
                                            "was taken on the server.")
    if requests and all(m.packet.direction == "in" for m in requests):
        loopback = any(is_loopback(e.server) and e.answered for e in everything)
        reason = ("The requests are marked as arriving at this host, and none was passed on, so the capture "
                  "was taken on the server: they reached it, and a firewall in between is ruled out.")
        if loopback:
            reason += " This host also answers RADIUS on its loopback address."
        return CapturePoint("server", True, reason, loopback)
    if requests and all(m.packet.direction == "out" for m in requests):
        return CapturePoint("client", True, "The requests are marked as leaving this host, so the capture was "
                                            "taken on the client (the NAS). From here a request that is never "
                                            "answered may not have reached the server at all.")
    return CapturePoint(None, False, "The capture does not record which way packets went, so it cannot say "
                                     "whether it was taken on the client, the server or in between. Add "
                                     "--captured-on server or --captured-on client if you know.")


def _capture_point(pair, point):
    if point is None or is_loopback(pair.server):
        return None
    return Finding("radius.capture_point", Status.INFO, "Capture point", point.reason,
                   details={"where": point.where, "certain": point.certain,
                            "loopback_answering": point.loopback_answering})


# --- per-pair findings ----------------------------------------------------------------

def _unanswered(pair, point):
    missing = [e for e in pair.exchanges if e.outcome == rx.NO_REPLY]
    if not missing:
        return None
    users = [e.user_name for e in missing]
    resends = sum(e.retransmissions for e in missing)
    if len(missing) == 1:
        e = missing[0]
        s = f"{pair.who} sent {article(e.name)} {e.name}"
        s += f" for {listing(users)}" if e.user_name else ""
        s += f" to {pair.label}"
        if e.retransmissions:
            s += (f", then resent it {times(e.retransmissions)} over {secs(e.span)} "
                  f"(ID {e.id}, same authenticator). None of the {len(e.attempts)} attempts got a reply")
        else:
            s += ". It got no reply"
    else:
        kinds = listing([e.name for e in missing], quote=False)
        s = f"{pair.who} sent {len(missing)} requests ({kinds})"
        s += f" for {listing(users)}" if any(users) else ""
        s += f" to {pair.label}"
        if resends:
            s += f", with {plural(resends, 'resend')} in all"
        total = len(pair.exchanges)
        s += ". None got a reply" if len(missing) == total else f". {len(missing)} of {total} got no reply"
    retried = [e for e in missing if e.retry_of is not None]
    if retried:
        s += f", and {plural(len(retried), 'was', 'were')} retried under a new ID"
    icmp = [i for e in missing for i, about in e.icmp if about == "request"]
    s += "." + (" No ICMP error came back." if not icmp else f" {plural(len(icmp), 'ICMP error')} came back "
                                                            "(see ICMP errors).")
    lacking = [e for e in missing if e.code in SIGNED_REQUESTS and e.request.position(MESSAGE_AUTHENTICATOR) is None]
    return Finding("radius.unanswered", Status.FAIL, "Requests unanswered", s, details={
        "unanswered": len(missing),
        "users": [u for u in dict.fromkeys(users) if u],
        "retransmitted": any(e.retransmissions or e.retry_of for e in missing),
        "resends": resends,
        "icmp": bool(icmp),
        "lacking_message_authenticator": len(lacking),
        "capture_point": point.where if point else None,
        "capture_point_certain": point.certain if point else False,
        "others_answered": pair.others_answered,
    })


def _capture_ended(pair, point):
    late = [e for e in pair.exchanges if e.outcome == rx.CAPTURE_ENDED]
    if not late:
        return None
    e = late[-1]
    gap = e.capture_end - e.attempts[-1].packet.ts
    lead = (f"{plural(len(late), 'request')} from {pair.who} to {pair.label} {'was' if len(late) == 1 else 'were'} "
            f"sent shortly before the capture stopped (the last {secs(gap)} before)")
    return Finding("radius.capture_ended", Status.INFO, "Capture ended", (
        f"{lead}, sooner than a reply is due ({secs(e.reply_window)}, {e.reply_window_source}). "
        "A reply may have come after the capture stopped, so these are not counted as unanswered."),
        details={"count": len(late), "reply_window": e.reply_window, "reply_window_source": e.reply_window_source})


def _answering(pair, point):
    answered = [e for e in pair.exchanges if e.answered]
    if not answered:
        return None
    outcomes = Counter(e.reply.name for e in answered)
    shown = ", ".join(f"{n} {name}" for name, n in outcomes.most_common())
    s = f"{pair.label} answered {len(answered)} of {len(pair.exchanges)} requests from {pair.who} ({shown})."
    return Finding("radius.answering", Status.PASS, "Server answering", s, details={
        "answered": len(answered), "requests": len(pair.exchanges), "outcomes": dict(outcomes)})


ICMP_MEANING = {
    "port unreachable": "nothing is listening on that UDP port there",
    "administratively prohibited": "a firewall refused the request",
    "host unreachable": "the server's address could not be reached",
    "network unreachable": "there is no route to the server's network",
    "address unreachable": "the server's address could not be reached",
    "no route": "there is no route to the server's network",
}


def _icmp(pair, point):
    about_requests = [i for e in pair.exchanges for i, about in e.icmp if about == "request"]
    about_replies = [i for e in pair.exchanges for i, about in e.icmp if about == "reply"]
    if not about_requests and not about_replies:
        return None
    sentences = []
    reasons = Counter(i.icmp.reason for i in about_requests)
    for reason, n in reasons.most_common():
        senders = list(dict.fromkeys(i.src for i in about_requests if i.icmp.reason == reason))
        by = ("from the server itself" if senders == [pair.server]
              else f"from {listing(senders, quote=False)} (not the server: a router or firewall on the way)")
        meaning = ICMP_MEANING.get(reason, "the request could not be delivered")
        sentences.append(f"Requests from {pair.who} to {pair.label} drew ICMP {reason} {times(n)}, {by}: {meaning}.")
    if about_replies:
        sentences.append(f"{plural(len(about_replies), 'reply', 'replies')} from {pair.label} drew ICMP port "
                         f"unreachable from {pair.client}: it had stopped listening, usually because it had given up "
                         "waiting.")
    status = Status.FAIL if about_requests else Status.WARN
    return Finding("radius.icmp", status, "ICMP errors", " ".join(sentences), details={
        "reasons": dict(reasons), "senders": list(dict.fromkeys(i.src for i in about_requests)),
        "about_replies": len(about_replies)})


BLASTRADIUS = "the BlastRADIUS attack (CVE-2024-3596)"


def _message_authenticator(pair, point):
    """Requests with no Message-Authenticator at all."""
    signed = [e for e in pair.exchanges if e.code in SIGNED_REQUESTS]
    if not signed:
        return None
    lacking = [e for e in signed if e.request.position(MESSAGE_AUTHENTICATOR) is None]
    if not lacking:
        return Finding("radius.message_authenticator", Status.PASS, "Message-Authenticator",
                       f"Present on every Access-Request and Status-Server from {pair.who} (value hidden).",
                       details={"lacking": 0, "requests": len(signed)})
    s = (f"{len(lacking)} of {len(signed)} Access-Requests from {pair.who} carry no Message-Authenticator. Servers "
         f"hardened against {BLASTRADIUS} require it, and drop requests without it, often without logging anything "
         "at the normal log level.")
    return Finding("radius.message_authenticator", Status.WARN, "Message-Authenticator", s, details={
        "lacking": len(lacking), "requests": len(signed),
        "lacking_unanswered": sum(1 for e in lacking if not e.answered)})


def _replies(pair):
    return [r for e in pair.exchanges for r in ([e.reply] if e.reply else []) + e.extra_replies]


def _reply_message_authenticator(pair, point):
    """Replies with no Message-Authenticator at all: the side BlastRADIUS forges."""
    replies = [r for r in _replies(pair) if r.code in (2, 3, 11)]
    if not replies:
        return None
    lacking = [r for r in replies if r.position(MESSAGE_AUTHENTICATOR) is None]
    if not lacking:
        return Finding("radius.reply_message_authenticator", Status.PASS, "Reply Message-Authenticator",
                       f"Present on every reply from {pair.label} to {pair.who} (value hidden).",
                       details={"lacking": 0, "replies": len(replies)})
    return Finding("radius.reply_message_authenticator", Status.WARN, "Reply Message-Authenticator", (
        f"{len(lacking)} of {len(replies)} replies from {pair.label} to {pair.who} carry no Message-Authenticator. "
        f"Without it a NAS cannot detect a forged Access-Accept, which is how {BLASTRADIUS} works; servers patched "
        "for it add one to every reply."), details={"lacking": len(lacking), "replies": len(replies)})


def _message_authenticator_position(pair, point):
    """Message-Authenticator present but not the first attribute, told apart from absent."""
    requests = [e.request for e in pair.exchanges if e.code in SIGNED_REQUESTS]
    replies = [r for r in _replies(pair) if r.code in (2, 3, 11)]
    late_requests = [m for m in requests if (m.position(MESSAGE_AUTHENTICATOR) or 0) > 0]
    late_replies = [m for m in replies if (m.position(MESSAGE_AUTHENTICATOR) or 0) > 0]
    if not late_requests and not late_replies:
        return None
    parts = []
    if late_requests:
        parts.append(f"{len(late_requests)} of {len(requests)} requests from {pair.who}")
    if late_replies:
        parts.append(f"{len(late_replies)} of {len(replies)} replies from {pair.label}")
    return Finding("radius.message_authenticator_position", Status.INFO, "Message-Authenticator position", (
        f"Message-Authenticator is present but not the first attribute in {' and '.join(parts)}. It still "
        f"protects the message; the hardening advice after {BLASTRADIUS} is to put it first, and some patched "
        "implementations expect that."),
        details={"requests_not_first": len(late_requests), "replies_not_first": len(late_replies)})


def _rejects(pair, point):
    rejected = [e for e in pair.exchanges if e.answered and e.reply.code == ACCESS_REJECT]
    if not rejected:
        return None
    users = [e.user_name for e in rejected]
    messages = list(dict.fromkeys(m for e in rejected for m in e.reply_messages))
    s = f"{pair.label} rejected {plural(len(rejected), 'Access-Request')} from {pair.who}"
    s += f" for {listing(users)}" if any(users) else ""
    s += f". Reply-Message: {listing(messages)}." if messages else ". No Reply-Message was given."
    accepted = any(e.answered and e.reply.code != ACCESS_REJECT and e.code == ACCESS_REQUEST for e in pair.exchanges)
    return Finding("radius.rejects", Status.FAIL, "Access-Reject", s, details={
        "rejects": len(rejected), "users": [u for u in dict.fromkeys(users) if u], "reply_messages": messages,
        "none_accepted": not accepted,
        "lacking_message_authenticator": sum(1 for e in rejected
                                             if e.request.position(MESSAGE_AUTHENTICATOR) is None)})


def _challenges(pair, point):
    n = sum(1 for e in pair.exchanges if e.answered and e.reply.code == ACCESS_CHALLENGE)
    if not n:
        return None
    return Finding("radius.challenges", Status.INFO, "Access-Challenge",
                   f"{pair.label} sent {pair.who} {plural(n, 'Access-Challenge')}: a multi-step login such as EAP "
                   "was in progress, and each challenge expects a further Access-Request.", details={"count": n})


def _response_time(pair, point):
    answered = [e for e in pair.exchanges if e.answered]
    if not answered:
        return None
    normal = [e for e in answered if e.reply.code != ACCESS_REJECT]
    rejects = [e for e in answered if e.reply.code == ACCESS_REJECT]
    times = Summary.of(e.response_time for e in normal)
    late = [e for e in normal if e.retransmissions and e.reply.packet.ts > e.attempts[1].packet.ts]
    reject_note = ""
    if rejects:
        rt = Summary.of(e.response_time for e in rejects)
        reject_note = (f" {plural(len(rejects), 'Access-Reject')} (after {secs(rt.p50)}) "
                       f"{'is' if len(rejects) == 1 else 'are'} left out: servers delay rejects on purpose.")
    details = {"count": times.count, "p50": times.p50, "p95": times.p95, "max": times.max,
               "late_replies": len(late), "rejects": len(rejects)}
    if not normal:
        after = secs(Summary.of(e.response_time for e in rejects).p50)
        return Finding("radius.response_time", Status.INFO, "Response times",
                       f"Only Access-Rejects came back from {pair.label} to {pair.who}, after {after}; servers "
                       "delay rejects on purpose, so this says nothing about the server's speed.", details=details)
    s = (f"{pair.label} to {pair.who}: {plural(times.count, 'reply', 'replies')}, p50 {secs(times.p50)}, "
         f"p95 {secs(times.p95)}, slowest {secs(times.max)}.")
    status = Status.PASS
    if times.p95 >= SLOW:
        status = Status.WARN
        s += " That is slow: a NAS typically gives up after 2 to 5 seconds."
    if late:
        status = Status.WARN
        s += (f" {plural(len(late), 'reply', 'replies')} came only after the client had resent its request, "
              "so the server is slower than the client's timeout.")
    return Finding("radius.response_time", status, "Response times", s + reject_note, details=details)


def _reply_from_elsewhere(pair, point):
    odd = [e for e in pair.exchanges if e.reply_from_elsewhere]
    if not odd:
        return None
    sources = listing([server_key(e.reply.packet.src, e.reply.packet.sport) for e in odd], quote=False)
    return Finding("radius.reply_from_elsewhere", Status.WARN, "Reply from another address", (
        f"{plural(len(odd), 'reply', 'replies')} to requests {pair.who} sent to {pair.label} came from {sources} "
        "instead. A NAS discards a reply from an address it did not send to, so the user sees a timeout. Usually "
        "the server has several addresses and answers from the wrong one, or NAT rewrites one direction only."),
        details={"count": len(odd), "from": sources})


def _reused_ids(pair, point):
    reused = [e for e in pair.exchanges if e.reused_id_of is not None]
    if not reused:
        return None
    return Finding("radius.reused_ids", Status.WARN, "Identifier reused", (
        f"{pair.who} reused a request ID {times(len(reused))} while an earlier request with that ID was still "
        "unanswered. A reply can then match only one of them; the other times out. This points at the client "
        "(too many requests in flight on one port, or a restart)."), details={"count": len(reused)})


def _legacy_port(pair, point):
    if not pair.ports.is_legacy(pair.port):
        return None
    return Finding("radius.legacy_port", Status.INFO, "Legacy port", (
        f"Port {pair.port} is the pre-standard RADIUS port that older NASes and servers still default to (the "
        "standard ports are 1812 and 1813). If one side uses the old port and the other the new, requests go "
        "unanswered."), details={"port": pair.port})


# --- the shared secret --------------------------------------------------------------

def _secret(pair, secret):
    """Check the secret against this NAS's requests and the server's replies to it: one client entry."""
    key = secret.value
    client_checks, resends = [], 0
    for e in pair.exchanges:
        client_checks += radius_auth.check_request(e.request, key)
        distinct = {e.request.raw}
        for a in e.attempts[1:]:
            if a.raw in distinct:
                resends += 1  # identical bytes: checking again adds nothing
            else:
                distinct.add(a.raw)
                client_checks += radius_auth.check_request(a, key)
    server_checks = [c for e in pair.exchanges for r in ([e.reply] if e.reply else []) + e.extra_replies
                     for c in radius_auth.check_reply(r, e.request, key)]
    server, server_strong = _verdict(server_checks)
    client, client_strong = _verdict(client_checks)
    sentences = []
    if server is True:
        sentences.append(f"The secret you gave matches this server: {_count_ok(server_checks)}.")
    elif server is False:
        sentences.append(f"The secret you gave does not match this server: {_count_bad(server_checks)}.")
    elif server == "mixed":
        sentences.append(f"The secret you gave matches some of this server's replies to {pair.who} but not others: "
                         f"{_count_bad(server_checks)}. Two servers may share this address, or the secret changed "
                         "during the capture.")
    else:
        sentences.append(f"No reply from this server to {pair.who} could be checked, so this says nothing about the "
                         "server's own secret.")
    if client is True:
        how = "" if client_strong else ", though only from readable text, so this is likely rather than certain"
        sentences.append(f"It matches the client {pair.who}: {_count_ok(client_checks, resends)}{how}.")
    elif client is False:
        how = "" if client_strong else ", which makes a different secret likely rather than certain"
        sentences.append(f"It does not match the client {pair.who}: {_count_bad(client_checks, resends)}{how}.")
    elif client == "mixed":
        sentences.append(f"It matches some requests from the client {pair.who} but not others: "
                         f"{_count_bad(client_checks, resends)}.")
    else:
        sentences.append(f"Nothing from the client {pair.who} could be checked (no Message-Authenticator or "
                         "User-Password).")
    if any(v is False or v == "mixed" for v in (server, client)):
        status = Status.FAIL
        sentences += secret.warnings()
    elif any(v is True for v in (server, client)):
        status = Status.PASS
    else:
        status = Status.SKIP
    return Finding("radius.secret", status, "Shared secret", " ".join(sentences), details={
        "given": True, "server_match": server, "server_strong": server_strong,
        "client_match": client, "client_strong": client_strong,
        "reject_fails": any(not c.ok and c.message.code == ACCESS_REJECT for c in server_checks)})


def _verdict(checks):
    """(verdict, strong): True, False, "mixed" or None, and whether a strong check backs the verdict."""
    if not checks:
        return None, False
    oks = {c.ok for c in checks}
    if len(oks) == 2:
        return "mixed", all(c.strong for c in checks)
    verdict = oks.pop()
    return verdict, any(c.strong for c in checks)


def _resend_note(resends):
    return f" (and {plural(resends, 'identical resend')})" if resends else ""


def _where(mine, bad, noun):
    if len(mine) == 1:
        return f"its {noun}"
    if bad == len(mine):
        return f"both of its {noun}s" if len(mine) == 2 else f"all {len(mine)} of its {noun}s"
    return f"{bad} of its {len(mine)} {noun}s"


def _count_ok(checks, resends=0):
    """e.g. "Message-Authenticator verifies on its Access-Request (and 2 identical resends)"."""
    parts = []
    for method in dict.fromkeys(c.method for c in checks if c.ok):
        mine = [c for c in checks if c.method == method and c.ok]
        noun = _msg_word(mine)
        where = _where(mine, len(mine), noun)
        if method == "User-Password":
            padded = all(c.strong for c in mine)
            parts.append("its User-Password decodes to readable text "
                         + ("with the zero padding RFC 2865 adds" if padded
                            else "(it fills its last block, so there is no padding to confirm it)"))
        else:
            parts.append(f"{method} verifies on {where}")
    parts[0] += _resend_note(resends)
    return " and ".join(parts)


def _count_bad(checks, resends=0):
    """e.g. "Message-Authenticator fails on its Access-Request (and 2 identical resends), and its
    User-Password decodes to unprintable bytes"."""
    parts = []
    for method in dict.fromkeys(c.method for c in checks):
        mine = [c for c in checks if c.method == method]
        bad = sum(1 for c in mine if not c.ok)
        if not bad:
            continue
        where = _where(mine, bad, _msg_word(mine))
        if method == "User-Password":
            parts.append("its User-Password decodes to unprintable bytes" if len(mine) == 1
                         else f"its User-Password decodes to unprintable bytes on {where}")
        else:
            parts.append(f"{method} fails on {where}")
    parts[0] += _resend_note(resends)
    return ", and ".join(parts)


def _msg_word(checks):
    names = {c.message.name for c in checks}
    return names.pop() if len(names) == 1 else "message"
