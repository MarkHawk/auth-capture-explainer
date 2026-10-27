"""Turn paired RADIUS exchanges into findings, per server.

Each server (address and port) gets its own findings, with details["server"]
set, so a capture with two servers reads as two stories. The findings state
what the capture shows; causes.py then names the likely reason.

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

SLOW = 1.0  # seconds at p95, for replies other than Access-Reject: a NAS typically times out at 2 to 5 s
SECRET_HELP = "--secret (prompts), --secret-file or --secret-env"
MAX_NAMES = 3  # users or clients named in one sentence before "and N more"


@dataclass(frozen=True)
class CapturePoint:
    where: str  # "server", "client", "path" or None when the capture does not say
    certain: bool  # True when packet directions (or the user) settle it
    reason: str  # one or two sentences, for the report
    loopback_answering: bool = False  # the capturing host also answers RADIUS on its loopback address


def server_key(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def server_label(address, port, ports):
    """e.g. "192.0.2.2:1812" or "192.0.2.2:1645 (legacy authentication port)"."""
    label = ports.label(port)
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{label}"


def is_loopback(address):
    return ipaddress.ip_address(address).is_loopback


def client_label(address, exchanges):
    """The client's address, with the NAS-Identifier it gives when it gives one."""
    names = sorted({text(a.value) for e in exchanges if e.client == address
                    for a in e.request.all(NAS_IDENTIFIER)})
    if len(names) == 1:
        return f'{address} (NAS-Identifier "{names[0]}")'
    return address


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _times(n):
    return {1: "once", 2: "twice"}.get(n, f"{n} times")


def _names(values, quote=True):
    values = list(dict.fromkeys(v for v in values if v))
    shown = [f'"{v}"' if quote else v for v in values[:MAX_NAMES]]
    if len(values) > MAX_NAMES:
        shown.append(f"{len(values) - MAX_NAMES} more")
    if len(shown) <= 1:
        return "".join(shown)
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def _secs(s):  # also used by causes
    if s is None:
        return "-"
    if s < 0.001:
        return "under 1 ms"
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"


def check(result, secret=None, captured_on=None):
    """Findings for a radius_exchange.Result. secret: a secret.Secret or None."""
    findings = []
    if not result.exchanges and not result.orphan_replies and not result.malformed:
        return findings
    servers = sorted(result.servers(), key=lambda c: is_loopback(c.server))  # health checks on loopback last
    for conv in servers:
        findings += _server_findings(conv, result, secret, captured_on)
    findings += _global_findings(result, secret)
    return findings


def _server_findings(conv, result, secret, captured_on):
    key = server_key(conv.server, conv.server_port)
    label = server_label(conv.server, conv.server_port, result.ports)
    ctx = dict(server=key, server_label=label)
    exchanges = conv.exchanges
    out = []
    unanswered = [e for e in exchanges if e.outcome == rx.NO_REPLY]
    point = capture_point(exchanges, captured_on, result.exchanges) if unanswered else None
    for make in (_unanswered, _capture_ended, _answering, _icmp, _message_authenticator, _rejects,
                 _challenges, _response_time, _reply_from_elsewhere, _reused_ids, _legacy_port):
        f = make(exchanges, label, result.ports, point)
        if f is not None:
            f.details = {**ctx, **f.details}
            out.append(f)
    if point is not None and not is_loopback(conv.server):
        out.insert(1, Finding("radius.capture_point", Status.INFO, "Capture point", point.reason,
                              details={**ctx, "where": point.where, "certain": point.certain,
                                       "loopback_answering": point.loopback_answering}))
    if secret is not None:
        f = _secret(exchanges, label, secret)
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
            f"{_plural(len(result.malformed), 'packet')} on RADIUS ports could not be read as RADIUS "
            f"(first at frame {first.packet.frame}: {first.reason}). They are left out of everything else.",
            details={"count": len(result.malformed), "reasons": dict(reasons), "first_frame": first.packet.frame}))
    if result.orphan_replies:
        n = len(result.orphan_replies)
        out.append(Finding(
            "radius.orphan_replies", Status.INFO, "Replies without requests",
            f"{_plural(n, 'reply', 'replies')} answer{'s' if n == 1 else ''} a request that is not in the capture, "
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
    """Where the capture was taken, judged from the requests and replies to one server.
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
    both = any({"in", "out"} <= d for d in seen.values())
    if both:
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


# --- per-server findings -----------------------------------------------------------

def _unanswered(exchanges, label, ports, point):
    missing = [e for e in exchanges if e.outcome == rx.NO_REPLY]
    if not missing:
        return None
    sentences = []
    by_client = {}
    for e in missing:
        by_client.setdefault(e.client, []).append(e)
    for client, mine in by_client.items():
        total = sum(1 for e in exchanges if e.client == client)
        who = client_label(client, exchanges)
        resends = sum(e.retransmissions for e in mine)
        kinds = _names([e.name for e in mine], quote=False)
        users = [e.user_name for e in mine]
        if len(mine) == 1:
            e = mine[0]
            s = f"{who} sent {_article(e.name)} {e.name}"
            s += f" for {_names(users)}" if e.user_name else ""
            s += f" to {label}"
            if e.retransmissions:
                s += (f", then resent it {_times(e.retransmissions)} over {_secs(e.span)} "
                      f"(ID {e.id}, same authenticator). None of the {len(e.attempts)} attempts got a reply")
            else:
                s += ". It got no reply"
        else:
            s = f"{who} sent {len(mine)} requests ({kinds})"
            s += f" for {_names(users)}" if any(users) else ""
            s += f" to {label}"
            if resends:
                s += f", with {_plural(resends, 'resend')} in all"
            s += ". None got a reply" if len(mine) == total else f". {len(mine)} of {total} got no reply"
        retried = [e for e in mine if e.retry_of is not None]
        if retried:
            s += f", and {_plural(len(retried), 'was', 'were')} retried under a new ID"
        sentences.append(s + ".")
    icmp = [i for e in missing for i, about in e.icmp if about == "request"]
    sentences.append("No ICMP error came back." if not icmp else
                     f"{_plural(len(icmp), 'ICMP error')} came back (see ICMP errors).")
    lacking = [e for e in missing if e.code in (ACCESS_REQUEST, STATUS_SERVER)
               and not e.request.has(MESSAGE_AUTHENTICATOR)]
    return Finding("radius.unanswered", Status.FAIL, "Requests unanswered", " ".join(sentences), details={
        "unanswered": len(missing),
        "clients": list(by_client),
        "users": [u for u in dict.fromkeys(e.user_name for e in missing) if u],
        "retransmitted": any(e.retransmissions or e.retry_of for e in missing),
        "resends": sum(e.retransmissions for e in missing),
        "icmp": bool(icmp),
        "lacking_message_authenticator": len(lacking),
        "capture_point": point.where if point else None,
        "capture_point_certain": point.certain if point else False,
    })


def _article(word):
    return "an" if word[:1].upper() in "AEIOU" else "a"


def _capture_ended(exchanges, label, ports, point):
    late = [e for e in exchanges if e.outcome == rx.CAPTURE_ENDED]
    if not late:
        return None
    e = late[-1]
    gap = e.capture_end - e.attempts[-1].packet.ts
    lead = (f"{_plural(len(late), 'request')} to {label} {'was' if len(late) == 1 else 'were'} sent shortly before "
            f"the capture stopped (the last {_secs(gap)} before)")
    return Finding("radius.capture_ended", Status.INFO, "Capture ended", (
        f"{lead}, sooner than a reply is due ({_secs(e.reply_window)}, {e.reply_window_source}). "
        "A reply may have come after the capture stopped, so these are not counted as unanswered."),
        details={"count": len(late), "reply_window": e.reply_window, "reply_window_source": e.reply_window_source})


def _answering(exchanges, label, ports, point):
    answered = [e for e in exchanges if e.answered]
    if not answered:
        return None
    outcomes = Counter(e.reply.name for e in answered)
    shown = ", ".join(f"{n} {name}" for name, n in outcomes.most_common())
    clients = list(dict.fromkeys(e.client for e in answered))
    who = _names([client_label(c, exchanges) for c in clients], quote=False)
    s = f"{label} answered {len(answered)} of {len(exchanges)} requests ({shown}), from {who}."
    return Finding("radius.answering", Status.PASS, "Server answering", s, details={
        "answered": len(answered), "requests": len(exchanges), "answered_clients": clients,
        "outcomes": dict(outcomes),
    })


ICMP_MEANING = {
    "port unreachable": "nothing is listening on that UDP port there",
    "administratively prohibited": "a firewall refused the request",
    "host unreachable": "the server's address could not be reached",
    "network unreachable": "there is no route to the server's network",
    "address unreachable": "the server's address could not be reached",
    "no route": "there is no route to the server's network",
}


def _icmp(exchanges, label, ports, point):
    about_requests = [(i, e) for e in exchanges for i, about in e.icmp if about == "request"]
    about_replies = [(i, e) for e in exchanges for i, about in e.icmp if about == "reply"]
    if not about_requests and not about_replies:
        return None
    sentences = []
    reasons = Counter(i.icmp.reason for i, _ in about_requests)
    for reason, n in reasons.most_common():
        senders = list(dict.fromkeys(i.src for i, e in about_requests if i.icmp.reason == reason))
        server = about_requests[0][1].server
        by = ("from the server itself" if senders == [server]
              else f"from {_names(senders, quote=False)} (not the server: a router or firewall on the way)")
        meaning = ICMP_MEANING.get(reason, "the request could not be delivered")
        sentences.append(f"Requests to {label} drew ICMP {reason} {_times(n)}, {by}: {meaning}.")
    if about_replies:
        sentences.append(f"{_plural(len(about_replies), 'reply', 'replies')} from {label} drew ICMP port unreachable "
                         "from the client: it had stopped listening, usually because it had given up waiting.")
    status = Status.FAIL if about_requests else Status.WARN
    return Finding("radius.icmp", status, "ICMP errors", " ".join(sentences), details={
        "reasons": dict(reasons), "senders": list(dict.fromkeys(i.src for i, _ in about_requests)),
        "about_replies": len(about_replies),
    })


def _message_authenticator(exchanges, label, ports, point):
    access = [e for e in exchanges if e.code in (ACCESS_REQUEST, STATUS_SERVER)]
    if not access:
        return None
    lacking = [e for e in access if not e.request.has(MESSAGE_AUTHENTICATOR)]
    if not lacking:
        return Finding("radius.message_authenticator", Status.PASS, "Message-Authenticator",
                       f"Present on every Access-Request and Status-Server to {label} (value hidden).",
                       details={"lacking": 0, "requests": len(access)})
    clients = _names([client_label(c, exchanges) for c in dict.fromkeys(e.client for e in lacking)], quote=False)
    unanswered = sum(1 for e in lacking if not e.answered)
    s = (f"{len(lacking)} of {len(access)} Access-Requests from {clients} carry no Message-Authenticator. Servers "
         "hardened against the BlastRADIUS attack (CVE-2024-3596) require it, and drop requests without it, "
         "often without logging anything at the normal log level.")
    return Finding("radius.message_authenticator", Status.WARN, "Message-Authenticator", s, details={
        "lacking": len(lacking), "requests": len(access), "lacking_unanswered": unanswered,
    })


def _rejects(exchanges, label, ports, point):
    rejected = [e for e in exchanges if e.answered and e.reply.code == ACCESS_REJECT]
    if not rejected:
        return None
    users = [e.user_name for e in rejected]
    messages = list(dict.fromkeys(m for e in rejected for m in e.reply_messages))
    s = f"{label} rejected {_plural(len(rejected), 'Access-Request')}"
    s += f" for {_names(users)}" if any(users) else ""
    s += f'. Reply-Message: {_names(messages)}.' if messages else ". No Reply-Message was given."
    accepted_clients = {e.client for e in exchanges if e.answered and e.reply.code != ACCESS_REJECT
                        and e.code == ACCESS_REQUEST}
    all_rejected_from = [c for c in dict.fromkeys(e.client for e in rejected) if c not in accepted_clients]
    return Finding("radius.rejects", Status.FAIL, "Access-Reject", s, details={
        "rejects": len(rejected), "users": [u for u in dict.fromkeys(users) if u], "reply_messages": messages,
        "clients_with_no_accept": all_rejected_from,
        "lacking_message_authenticator": sum(1 for e in rejected if not e.request.has(MESSAGE_AUTHENTICATOR)),
    })


def _challenges(exchanges, label, ports, point):
    n = sum(1 for e in exchanges if e.answered and e.reply.code == ACCESS_CHALLENGE)
    if not n:
        return None
    return Finding("radius.challenges", Status.INFO, "Access-Challenge",
                   f"{label} sent {_plural(n, 'Access-Challenge')}: a multi-step login such as EAP was in progress, "
                   "and each challenge expects a further Access-Request from the client.", details={"count": n})


def _response_time(exchanges, label, ports, point):
    answered = [e for e in exchanges if e.answered]
    if not answered:
        return None
    normal = [e for e in answered if e.reply.code != ACCESS_REJECT]
    rejects = [e for e in answered if e.reply.code == ACCESS_REJECT]
    times = Summary.of(e.response_time for e in normal)
    late = [e for e in normal if e.retransmissions and e.reply.packet.ts > e.attempts[1].packet.ts]
    reject_note = ""
    if rejects:
        rt = Summary.of(e.response_time for e in rejects)
        reject_note = (f" {_plural(len(rejects), 'Access-Reject')} (after {_secs(rt.p50)}) "
                       f"{'is' if len(rejects) == 1 else 'are'} left out: servers delay rejects on purpose.")
    details = {"count": times.count, "p50": times.p50, "p95": times.p95, "max": times.max,
               "late_replies": len(late), "rejects": len(rejects)}
    if not normal:
        after = _secs(Summary.of(e.response_time for e in rejects).p50)
        return Finding("radius.response_time", Status.INFO, "Response times",
                       f"Only Access-Rejects came back from {label}, after {after}; servers delay rejects on "
                       "purpose, so this says nothing about the server's speed.", details=details)
    s = f"{label}: {times.count} replies, p50 {_secs(times.p50)}, p95 {_secs(times.p95)}, slowest {_secs(times.max)}."
    status = Status.PASS
    if times.p95 >= SLOW:
        status = Status.WARN
        s += " That is slow: a NAS typically gives up after 2 to 5 seconds."
    if late:
        status = Status.WARN
        s += (f" {_plural(len(late), 'reply', 'replies')} came only after the client had resent its request, "
              "so the server is slower than the client's timeout.")
    return Finding("radius.response_time", status, "Response times", s + reject_note, details=details)


def _reply_from_elsewhere(exchanges, label, ports, point):
    odd = [e for e in exchanges if e.reply_from_elsewhere]
    if not odd:
        return None
    sources = _names([server_key(e.reply.packet.src, e.reply.packet.sport) for e in odd], quote=False)
    return Finding("radius.reply_from_elsewhere", Status.WARN, "Reply from another address", (
        f"{_plural(len(odd), 'reply', 'replies')} to requests sent to {label} came from {sources} instead. A NAS "
        "discards a reply from an address it did not send to, so the user sees a timeout. Usually the server has "
        "several addresses and answers from the wrong one, or NAT rewrites one direction only."),
        details={"count": len(odd), "from": sources})


def _reused_ids(exchanges, label, ports, point):
    reused = [e for e in exchanges if e.reused_id_of is not None]
    if not reused:
        return None
    clients = _names([client_label(c, exchanges) for c in dict.fromkeys(e.client for e in reused)], quote=False)
    return Finding("radius.reused_ids", Status.WARN, "Identifier reused", (
        f"{clients} reused a request ID {_times(len(reused))} while an earlier request with that ID was still "
        "unanswered. A reply can then match only one of them; the other times out. This points at the client "
        "(too many requests in flight on one port, or a restart)."), details={"count": len(reused)})


def _legacy_port(exchanges, label, ports, point):
    port = exchanges[0].server_port
    if not ports.is_legacy(port):
        return None
    return Finding("radius.legacy_port", Status.INFO, "Legacy port", (
        f"Port {port} is the pre-standard RADIUS port that older NASes and servers still default to (the standard "
        "ports are 1812 and 1813). If one side uses the old port and the other the new, requests go unanswered."),
        details={"port": port})


# --- the shared secret --------------------------------------------------------------

def _secret(exchanges, label, secret):
    key = secret.value
    by_client = {}
    for e in exchanges:
        by_client.setdefault(e.client, []).extend(radius_auth.check_request(e.request, key))
    server_checks = []
    for e in exchanges:
        for reply in ([e.reply] if e.reply else []) + e.extra_replies:
            server_checks += radius_auth.check_reply(reply, e.request, key)
    server = _verdict(server_checks)
    clients = {c: _verdict(checks) for c, checks in by_client.items()}
    sentences = []
    if server is True:
        sentences.append(f"The secret you gave matches this server: {_count_ok(server_checks)}.")
    elif server is False:
        sentences.append(f"The secret you gave does not match this server: {_count_bad(server_checks)}.")
    elif server == "mixed":
        sentences.append(f"The secret you gave matches some of this server's replies but not others: "
                         f"{_count_bad(server_checks)}. Two servers may share this address, or the secret "
                         "changed during the capture.")
    else:
        sentences.append("No reply from this server could be checked, so this says nothing about the server's "
                         "own secret.")
    for client, verdict in clients.items():
        who = client_label(client, exchanges)
        checks = by_client[client]
        if verdict is True:
            sentences.append(f"It matches the client {who}: {_count_ok(checks)}.")
        elif verdict is False:
            sentences.append(f"It does not match the client {who}: {_count_bad(checks)}.")
        elif verdict == "mixed":
            sentences.append(f"It matches some requests from the client {who} but not others: {_count_bad(checks)}.")
        else:
            sentences.append(f"Nothing from the client {who} could be checked (no Message-Authenticator or "
                             "User-Password).")
    verdicts = [server, *clients.values()]
    if any(v is False or v == "mixed" for v in verdicts):
        status = Status.FAIL
        sentences += secret.warnings()
    elif any(v is True for v in verdicts):
        status = Status.PASS
    else:
        status = Status.SKIP
    rejects_fail = any(not c.ok and c.message.code == ACCESS_REJECT for c in server_checks)
    return Finding("radius.secret", status, "Shared secret", " ".join(sentences), details={
        "given": True, "server_match": server, "client_match": clients, "reject_fails": rejects_fail,
    })


def _verdict(checks):
    if not checks:
        return None
    oks = {c.ok for c in checks}
    return "mixed" if len(oks) == 2 else oks.pop()


def _count_ok(checks):
    """e.g. "Response Authenticator verifies on 2 Access-Accepts"."""
    methods = Counter(c.method for c in checks if c.ok)
    parts = []
    for method, n in methods.items():
        noun = _msg_word(checks, method)
        if method == "User-Password":
            parts.append("its User-Password decodes to readable text" if n == 1
                         else f"User-Password decodes to readable text on {n} {noun}s")
        else:
            parts.append(f"{method} verifies on {f'its {noun}' if n == 1 else f'{n} {noun}s'}")
    return " and ".join(parts)


def _count_bad(checks):
    """e.g. "Message-Authenticator fails on all 3 of its Access-Requests, and its User-Password decodes
    to unprintable bytes"."""
    parts = []
    for method in dict.fromkeys(c.method for c in checks):
        mine = [c for c in checks if c.method == method]
        bad = sum(1 for c in mine if not c.ok)
        if not bad:
            continue
        noun = _msg_word(mine, method)
        if len(mine) == 1:
            where = f"its {noun}"
        elif bad == len(mine):
            where = f"both of its {noun}s" if len(mine) == 2 else f"all {len(mine)} of its {noun}s"
        else:
            where = f"{bad} of its {len(mine)} {noun}s"
        if method == "User-Password":
            parts.append(f"its User-Password decodes to unprintable bytes on {where}" if len(mine) > 1
                         else "its User-Password decodes to unprintable bytes")
        else:
            parts.append(f"{method} fails on {where}")
    return ", and ".join(parts)


def _msg_word(checks, method):
    names = {c.message.name for c in checks if c.method == method}
    return names.pop() if len(names) == 1 else "message"
