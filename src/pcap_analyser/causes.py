"""Name the likely root cause behind a NAS and server pair's findings, for known patterns only.

Findings say what the capture shows, one statement each. A pattern here
recognises a familiar failure from the findings' details (not their
wording), says what it most likely is, what to do first, and which evidence
points which way, so the reader can weigh it rather than take it on trust.

Causes are per pair (one NAS, one server port), because each NAS has its own
client entry and secret on the server: one NAS with a secret mismatch and
another whose users are simply rejected are two causes, side by side.
Within a pair, patterns are tried most decisive first and the first match
wins: a secret checked with --secret beats an inference from silence, and
an ICMP error beats a guess. When nothing matches there is no likely cause.

A cause is "confirmed" when the capture settles it (keyed-hash checks that
verify on one side and not the other, an ICMP error saying why), and
otherwise "likely". The wording keeps that distinction.

Other pairs on the same server, and the capturing host's own loopback
RADIUS, may lend support to a mismatch on this pair (see _support()). They
never count against one: another client entry may hold another secret.
"""

from dataclasses import dataclass, field

from pcap_analyser import runbooks
from pcap_analyser.findings import Status
from pcap_analyser.radius_checks import SECRET_HELP
from pcap_analyser.wording import secs


@dataclass
class Cause:
    pattern: str  # stable id, e.g. "radius-secret-mismatch"
    label: str  # a few words, for one-line summaries
    summary: str  # what is most likely wrong, in a few sentences
    first_step: str  # the first thing to do
    runbook: str = None
    confirmed: bool = False
    evidence: list = field(default_factory=list)  # sentences: what points to this, what points elsewhere
    explains: list = field(default_factory=list)  # check_ids of the findings this accounts for
    server: str = None  # the server label the cause is about
    client: str = None  # and the client (NAS) label


def likely_causes(findings):
    """One Cause per pair whose findings match a known pattern, in the order the pairs appear.

    A pair on a loopback address is the capturing host checking itself, not what anyone is
    troubleshooting, so it gets a cause only when the capture holds nothing else."""
    by_pair = {}
    for f in findings:
        if "pair" in f.details:
            by_pair.setdefault(f.details["pair"], []).append(f)
    secrets = {p: next((f for f in mine if f.check_id == "radius.secret"), None) for p, mine in by_pair.items()}
    real = [p for p, mine in by_pair.items() if not mine[0].details["loopback"]]
    causes = []
    for pair in (real or list(by_pair)):
        mine = by_pair[pair]
        found = {}
        for f in mine:
            found.setdefault(f.check_id, f)
        found["_support"] = _support(mine[0].details, found, secrets)
        for pattern in RADIUS_PATTERNS:
            cause = pattern(found)
            if cause:
                cause.server = mine[0].details["server_label"]
                cause.client = mine[0].details["client_label"]
                cause.explains = [c for c in cause.explains if c in found]
                causes.append(cause)
                break
    return causes


@dataclass
class Support:
    """What other client entries say about the secret given. Only ever used to support a mismatch."""

    matches_elsewhere: list = field(default_factory=list)  # sentences: another entry verifies with it
    fails_elsewhere: list = field(default_factory=list)  # sentences: another entry's replies do not verify


def _support(details, found, secrets):
    """Evidence from other pairs on this server and, when the capture was taken on the server, from the
    capturing host's loopback RADIUS. It may support a mismatch on this pair; it is never used against one."""
    support = Support()
    point = found.get("radius.capture_point")
    on_server = point is not None and point.details["where"] == "server"
    for other, sec in secrets.items():
        if other == details["pair"] or sec is None or sec.status == Status.SKIP:
            continue
        same_server = sec.details["server"] == details["server"]
        local = sec.details["loopback"] and on_server and not same_server
        if not (same_server or local):
            continue
        if local:
            where, caveat = "RADIUS on this host's loopback address", "unless the loopback client entry has its own"
        else:
            where, caveat = f"The server's replies to {sec.details['client_label']}", "for that client's entry at least"
        if sec.details["server_match"] is True and sec.details["server_strong"]:
            support.matches_elsewhere.append(f"{where[0].upper()}{where[1:]} verifies with the secret you gave, so "
                                             f"the server does use it ({caveat}).")
        elif sec.details["server_match"] is False:
            support.fails_elsewhere.append(f"{where[0].upper()}{where[1:]} does not verify with the secret you "
                                           f"gave, which suggests the server holds another ({caveat}).")
    return support


def _get(found, check_id, *statuses):
    f = found.get(check_id)
    return f if f is not None and (not statuses or f.status in statuses) else None


def _times(n):
    return {1: "once", 2: "twice"}.get(n, f"{n} times")


def _names(values):
    values = list(values)
    return values[0] if len(values) == 1 else ", ".join(values[:-1]) + " and " + values[-1]


# --- RADIUS patterns -------------------------------------------------------------------

def _secret_confirmed(found):
    sec = _get(found, "radius.secret", Status.FAIL)
    if not sec:
        return None
    d = sec.details
    server, client = d["server_match"], d["client_match"]
    who = d["client_label"]
    support = found["_support"]
    dropped = " and drops them without replying" if _get(found, "radius.unanswered", Status.FAIL) else ""
    explains = ["radius.secret", "radius.unanswered", "radius.rejects"]
    client_bad = client is False or client == "mixed"
    if server is True and client_bad:
        confirmed = d["server_strong"] and d["client_strong"]
        return Cause(
            "radius-secret-mismatch", "shared secret mismatch, confirmed" if confirmed else "shared secret mismatch",
            f"The secret you gave matches the server's replies to {who}, but {who} signs its requests with a "
            "different one. The NAS and the server's client entry for it hold different secrets, so the server "
            f"cannot verify its requests{dropped}.",
            f"Set the secret on {who} again from the same source as the server's client entry: paste it rather "
            "than retype it, and check for trailing spaces.",
            runbooks.RADIUS_SECRET_MISMATCH, confirmed,
            [f"For a secret mismatch: the server's replies verify with the secret you gave, and {who}'s requests "
             "do not."], explains)
    if server is False and client is True:
        confirmed = d["server_strong"] and d["client_strong"]
        summary = (f"{who} uses the secret you gave, but the server's replies to it are made with a different one: "
                   "the server's client entry for this NAS holds another secret.")
        if d["reject_fails"]:
            summary += (" Its Access-Rejects are not about the users' passwords: with a different secret the "
                        "server decodes every password to random bytes and rejects it, which looks exactly like "
                        "a wrong password.")
        return Cause(
            "radius-secret-mismatch", "shared secret mismatch, confirmed" if confirmed else "shared secret mismatch",
            summary,
            f"Set the secret in the server's client entry for {who} to match the NAS, from one source, then "
            "restart or reload the RADIUS server.",
            runbooks.RADIUS_SECRET_MISMATCH, confirmed,
            [f"For a secret mismatch: {who}'s requests verify with the secret you gave, and the server's replies "
             "to it do not."], explains)
    if client_bad and server is None:
        evidence = [f"For a secret mismatch: {who}'s requests do not verify with the secret you gave."]
        evidence += support.matches_elsewhere
        evidence.append("Not settled: no reply to this NAS could be checked, so this assumes the secret you gave "
                        "is the one in its client entry.")
        return Cause(
            "radius-secret-mismatch", "shared secret mismatch",
            f"{who} signs its requests with a secret other than the one you gave. If you gave the secret in the "
            f"server's client entry for {who}, the two sides differ, so the server cannot verify its "
            f"requests{dropped}.",
            f"Check that the secret you gave is the one in the server's client entry for {who}; if it is, set the "
            "secret on the NAS again from that source.",
            runbooks.RADIUS_SECRET_MISMATCH, False, evidence, explains)
    if server is False or server == "mixed":
        neither = client_bad
        return Cause(
            "radius-secret-unknown", "the secret given matches neither side" if neither else "server secret differs",
            ("The secret you gave matches neither the server's replies nor the NAS's requests, so it is not the "
             "secret either side uses for this NAS. Get the current value before drawing conclusions.") if neither
            else (f"The server's replies to {who} do not verify with the secret you gave. If you gave {who}'s "
                  "secret, the server's client entry for it holds a different one."),
            "Get the current secret from where it is stored, and check again with it. To compare the two sides "
            "without reading the secret aloud, compare a hash of it.",
            runbooks.RADIUS_SECRET_MISMATCH, False, [], explains)
    return None


def _unreachable(found):
    icmp = _get(found, "radius.icmp", Status.FAIL)
    if not icmp:
        return None
    reasons = icmp.details["reasons"]
    senders = icmp.details["senders"]
    reason = max(reasons, key=reasons.get)
    label = icmp.details["server_label"]
    port = icmp.details["server"].rsplit(":", 1)[-1]
    evidence = [f"Direct: ICMP {r} came back {_times(n)}." for r, n in reasons.items()]
    explains = ["radius.icmp", "radius.unanswered"]
    if reason == "port unreachable":
        return Cause(
            "radius-port-closed", "nothing listening on the RADIUS port",
            f"Nothing is listening for RADIUS on {label}: the RADIUS service there is stopped, or it listens on "
            "another port (the standard 1812 against the legacy 1645, for example).",
            "Check that the RADIUS service is running on the server, which UDP ports it listens on, and that the "
            "NAS sends to the same port.", None, True, evidence, explains)
    if reason == "administratively prohibited":
        where = ", ".join(senders)
        return Cause(
            "radius-firewall", "a firewall refuses RADIUS",
            f"A firewall ({where}) refuses the requests to {label}, and says so with ICMP.",
            f"Allow UDP {port} from the NAS to the RADIUS server on {where}, and the replies back.",
            None, True, evidence, explains)
    return Cause(
        "radius-unreachable", "the server cannot be reached",
        f"The RADIUS server at {label} cannot be reached ({reason}, reported by {', '.join(senders)}): the server "
        "is down, or there is no route to it.",
        "Check that the server is up and that the NAS has a route to it.", None, True, evidence, explains)


def _reply_from_elsewhere(found):
    odd = _get(found, "radius.reply_from_elsewhere")
    if not odd:
        return None
    return Cause(
        "radius-reply-wrong-address", "replies from the wrong address",
        f"The server answers, but from {odd.details['from']} rather than the address the NAS sent to, so the NAS "
        "discards the replies and logs a timeout.",
        "Make the RADIUS server reply from the address the NAS sends to (bind it to that address), or fix the NAT "
        "so that both directions are translated.",
        None, True, [], ["radius.reply_from_elsewhere", "radius.unanswered"])


def _no_message_authenticator(found):
    un = _get(found, "radius.unanswered", Status.FAIL)
    if not un or un.details["icmp"] or not un.details["lacking_message_authenticator"]:
        return None
    if un.details["lacking_message_authenticator"] < un.details["unanswered"]:
        return None
    n = un.details["lacking_message_authenticator"]
    return Cause(
        "radius-no-message-authenticator", "requests without Message-Authenticator",
        "The NAS sends Access-Requests without Message-Authenticator and gets no reply. A server that requires it "
        "(the default since the BlastRADIUS fixes, CVE-2024-3596) drops such requests without a word: an old NAS "
        "or old firmware, rather than a wrong secret.",
        "Update the NAS, or turn on Message-Authenticator in its RADIUS settings. Do not relax the server's "
        "requirement: that reopens the BlastRADIUS hole.",
        runbooks.RADIUS_SECRET_MISMATCH, False,
        [f"For an old NAS: {n} unanswered request{'s' if n > 1 else ''} carry no Message-Authenticator.",
         "To confirm: in debug mode the server says the packet does not contain the required "
         "Message-Authenticator."],
        ["radius.unanswered", "radius.message_authenticator"])


def _secret_ruled_out(found):
    """The NAS's requests verify with the secret given, and the server stays silent."""
    un = _get(found, "radius.unanswered", Status.FAIL)
    sec = _get(found, "radius.secret", Status.PASS)
    if not un or not sec or sec.details["client_match"] is not True:
        return None
    who = sec.details["client_label"]
    support = found["_support"]
    if support.fails_elsewhere:
        # Elsewhere on this server the secret given does not verify: it looks like the NAS's, not the server's.
        return Cause(
            "radius-secret-mismatch", "shared secret mismatch, most likely",
            f"{who}'s requests verify with the secret you gave, but other traffic to this server does not. The "
            "secret you gave looks like the NAS's, and the server most likely holds a different one for it, so it "
            "cannot verify the requests and drops them without replying.",
            f"Compare the secret on {who} with the server's client entry for it (a hash of each, not the value), "
            "then set them the same from one source. To confirm, run this again with the server's secret.",
            runbooks.RADIUS_SECRET_MISMATCH, False,
            [f"For a secret mismatch: {who}'s requests verify with the secret you gave.", *support.fails_elsewhere],
            ["radius.unanswered", "radius.secret", "radius.capture_point"])
    strength = "" if sec.details["client_strong"] else " (from readable text only, so not certain)"
    return Cause(
        "radius-unanswered-secret-ok", "no reply, but the secret matches",
        f"{who}'s requests verify with the secret you gave{strength}, so if that is the secret in the server's "
        "client entry for it, the secret is not why they go unanswered. The likelier causes are the server not "
        "knowing this NAS (its address missing from the client list, often after NAT or a new source address) or "
        "a firewall on the way.",
        f"Check that the server's client list has {un.details['client']}'s address as the server sees it, and "
        "look in the server's log for \"unknown client\".",
        runbooks.RADIUS_SECRET_MISMATCH, False,
        [f"Against a secret mismatch: {who}'s requests verify with the secret you gave."],
        ["radius.unanswered", "radius.secret", "radius.capture_point"])


def _secret_likely(found):
    un = _get(found, "radius.unanswered", Status.FAIL)
    if not un or un.details["icmp"] or not un.details["retransmitted"]:
        return None
    others = un.details["others_answered"]
    point = _get(found, "radius.capture_point")
    on_server = un.details["capture_point"] == "server"
    loopback = bool(point and point.details.get("loopback_answering"))
    if not (others or on_server):
        return None
    who = un.details["client"]
    for_mismatch = [f"the request was resent {_times(un.details['resends'])} and never answered",
                    "no ICMP error came back"]
    if others:
        for_mismatch.append(f"the server answered {_names(others)} meanwhile")
    elif loopback:
        for_mismatch.append("this host answers RADIUS on its loopback address meanwhile")
    evidence = ["For a secret mismatch: " + "; ".join(for_mismatch) + "."]
    evidence += found["_support"].fails_elsewhere
    if on_server:
        evidence.append("Against a firewall: the requests were seen arriving at the server.")
        lead = f"The server receives {who}'s requests and stays silent"
        lead += ", while it answers others" if others or loopback else ""
    else:
        evidence.append("Against a firewall, partly: the server answers other clients, though a rule for this "
                        "NAS alone cannot be ruled out from this capture.")
        lead = f"The server answers other clients but not {who}"
    evidence.append("Looks the same on the wire: an unknown client (the NAS's address missing from the server's "
                    "client list); the server's log tells them apart.")
    return Cause(
        "radius-secret-mismatch", "shared secret mismatch, most likely",
        f"{lead}, which is how a RADIUS server treats requests it cannot authenticate: the NAS's shared secret "
        "most likely differs from the server's client entry for it. An unknown client looks the same on the "
        "wire; the server's log tells them apart.",
        f"Look in the server's log for \"Shared secret is incorrect\" or \"unknown client\" for {who}, then set "
        f"the secret again on both sides from one source. To confirm from this capture, run it again with "
        f"{SECRET_HELP} and the server's secret.",
        runbooks.RADIUS_SECRET_MISMATCH, False, evidence,
        ["radius.unanswered", "radius.capture_point", "radius.answering"])


def _silent(found):
    un = _get(found, "radius.unanswered", Status.FAIL)
    if not un or un.details["icmp"]:
        return None
    where = {"client": "the client", "path": "a device on the path"}.get(un.details["capture_point"],
                                                                         "where this capture was taken")
    label = un.details["server_label"]
    evidence = ["For a firewall, routing or a stopped server: the server answered nothing at all, to any client."]
    if un.details["retransmitted"]:
        evidence.append(f"For a secret mismatch or an unknown client: the request was resent "
                        f"{_times(un.details['resends'])} and never answered, with no ICMP error.")
    evidence.append("To tell them apart: capture on the RADIUS server itself, or check its log.")
    return Cause(
        "radius-no-reply", "no reply from the server",
        f"{label} answered nothing in this capture. Seen from {where}, the possibilities cannot be told apart: "
        "the requests may not reach the server (a firewall or routing), the server may be down, or it may be "
        "dropping them (a shared secret mismatch, or the NAS not being in its client list).",
        "Take a capture on the RADIUS server while a login is tried, or check its log for the NAS's address. If "
        "the requests arrive there, look at the secret and the client list; if they do not, look at the path.",
        runbooks.RADIUS_SECRET_MISMATCH, False, evidence, ["radius.unanswered", "radius.capture_point"])


def _rejected(found):
    rej = _get(found, "radius.rejects", Status.FAIL)
    if not rej:
        return None
    sec = _get(found, "radius.secret", Status.PASS)
    verified = bool(sec and sec.details["server_match"] is True)
    users = rej.details["users"]
    who = _names([f'"{u}"' for u in users]) if users else "the user"
    messages = rej.details["reply_messages"]
    said = f' with "{messages[0]}"' if len(messages) == 1 else ""
    summary = f"The server rejected the login for {who}{said}."
    evidence, runbook = [], None
    if verified:
        summary += (" The reject verifies with the secret you gave, so it is a genuine answer from the server: the "
                    "problem is the user's password or account, not the NAS or the network.")
        evidence.append("Against a secret mismatch: the server's replies verify with the secret you gave.")
    else:
        summary += " A reject is usually about the user's password or account."
        nas = rej.details["client_label"]
        if rej.details["none_accepted"] and (len(users) >= 3 or rej.details["lacking_message_authenticator"]):
            summary += (f" But every login through {nas} is rejected and none accepted: if that is true of many "
                        "users, check the shared secret, because a server with a different secret that does not "
                        "require Message-Authenticator rejects every password.")
            evidence.append(f"For a secret mismatch: {len(users)} different users rejected through one NAS, none "
                            "accepted.")
            runbook = runbooks.RADIUS_SECRET_MISMATCH
        evidence.append(f"Not checked: the secret. Add {SECRET_HELP} to tell a genuine reject from a mismatch.")
    return Cause(
        "radius-user-rejected", "login rejected by the server", summary,
        "Check the user's password and account (locked, expired, missing from a required group) in the directory "
        "or user store behind the RADIUS server; the server's log names the reason.",
        runbook, verified, evidence, ["radius.rejects", "radius.secret"])


def _slow(found):
    rt = _get(found, "radius.response_time", Status.WARN)
    if not rt:
        return None
    d = rt.details
    late = f", and {d['late_replies']} came only after the NAS had resent" if d["late_replies"] else ""
    return Cause(
        "radius-slow", "slow server",
        f"{d['server_label']} is slow to reply to {d['client_label']} (p50 {secs(d['p50'])}, p95 "
        f"{secs(d['p95'])}{late}), close to or past the 2 to 5 seconds after which a NAS gives up and tries again "
        "or fails over.",
        "Check what the server waits on for each login: the directory or database behind it, DNS lookups, or a "
        "proxy to another RADIUS server. Raising the NAS's timeout only hides it.",
        None, True, [], ["radius.response_time"])


RADIUS_PATTERNS = (
    _secret_confirmed,
    _unreachable,
    _reply_from_elsewhere,
    _no_message_authenticator,
    _secret_ruled_out,
    _secret_likely,
    _silent,
    _rejected,
    _slow,
)
