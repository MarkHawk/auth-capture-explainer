"""Name the likely root cause behind a client and server pair's findings, for known patterns only.

Findings say what the capture shows, one statement each. A pattern here
recognises a familiar failure from the findings' details (not their
wording), says what it most likely is, what to do first, and which evidence
points which way, so the reader can weigh it rather than take it on trust.

Causes are per pair: one client and one server port. For RADIUS that is a
NAS, which has its own client entry and secret on the server, so one NAS
with a secret mismatch and another whose users are simply rejected are two
causes, side by side. For LDAP it is usually an application or identity
provider and its directory.
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

from auth_capture_explainer import ldap_codes, runbooks
from auth_capture_explainer.findings import Status
from auth_capture_explainer.radius_checks import SECRET_HELP
from auth_capture_explainer.wording import secs


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
    real = [p for p, mine in by_pair.items() if not mine[0].details.get("loopback")]
    causes = []
    for pair in (real or list(by_pair)):
        mine = by_pair[pair]
        found, every = {}, {}
        for f in mine:
            found.setdefault(f.check_id, f)
            every.setdefault(f.check_id, []).append(f)
        found["_all"] = every
        ldap_pair = mine[0].details.get("protocol") == "ldap"
        if not ldap_pair:
            found["_support"] = _support(mine[0].details, found, secrets)
        for pattern in (LDAP_PATTERNS if ldap_pair else RADIUS_PATTERNS):
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
            [f"For a secret mismatch: the server's replies verify with the secret you gave, and the requests from "
             f"{who} do not."], explains)
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
            [f"For a secret mismatch: the requests from {who} verify with the secret you gave, and the server's replies "
             "to it do not."], explains)
    if client_bad and server is None:
        evidence = [f"For a secret mismatch: the requests from {who} do not verify with the secret you gave."]
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
            else (f"The server's replies to {who} do not verify with the secret you gave. If you gave the secret of "
                  f"{who}, the server's client entry for it holds a different one."),
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
            f"The requests from {who} verify with the secret you gave, but other traffic to this server does not. The "
            "secret you gave looks like the NAS's, and the server most likely holds a different one for it, so it "
            "cannot verify the requests and drops them without replying.",
            f"Compare the secret on {who} with the server's client entry for it (a hash of each, not the value), "
            "then set them the same from one source. To confirm, run this again with the server's secret.",
            runbooks.RADIUS_SECRET_MISMATCH, False,
            [f"For a secret mismatch: the requests from {who} verify with the secret you gave.",
             *support.fails_elsewhere],
            ["radius.unanswered", "radius.secret", "radius.capture_point"])
    strength = "" if sec.details["client_strong"] else " (from readable text only, so not certain)"
    return Cause(
        "radius-unanswered-secret-ok", "no reply, but the secret matches",
        f"The requests from {who} verify with the secret you gave{strength}, so if that is the secret in the server's "
        "client entry for it, the secret is not why they go unanswered. The likelier causes are the server not "
        "knowing this NAS (its address missing from the client list, often after NAT or a new source address) or "
        "a firewall on the way.",
        f"Check that the server's client list has {un.details['client']}'s address as the server sees it, and "
        "look in the server's log for \"unknown client\".",
        runbooks.RADIUS_SECRET_MISMATCH, False,
        [f"Against a secret mismatch: the requests from {who} verify with the secret you gave."],
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
        lead = f"The server receives the requests from {who} and stays silent"
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


# --- LDAP patterns ---------------------------------------------------------------------

def _all(found, check_id, *statuses):
    return [f for f in found["_all"].get(check_id, []) if not statuses or f.status in statuses]


def _bind(found, test):
    return next((f for f in _all(found, "ldap.bind_failed") if test(f.details)), None)


def _ad_suffix(d):
    lead = d.get("ad_leading")
    return f", Active Directory code {lead}" if lead else ""


AD_DIAGNOSTICS = ("the \"16 LDAP Interface Events\" diagnostic logging value (under "
                  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics) set to 2")
AD_SIGNING_EVENTS = ("On Active Directory the Directory Service event log tells: event 2888 counts binds rejected for "
                     "not being signed (2887 counts unsigned binds while signing is not yet required), and event "
                     f"2889 names each client, but only with {AD_DIAGNOSTICS}.")
AD_CBT_EVENTS = ("On Active Directory, events 3039 to 3041 in the Directory Service event log cover binds without "
                 f"valid channel binding; 3039, which names each client, needs {AD_DIAGNOSTICS}.")


def _ldap_signing(found):
    f = _bind(found, lambda d: d["signing_required"])
    if not f:
        return None
    d = f.details
    return Cause(
        "ldap-signing-required", "LDAP signing or channel binding enforcement",
        f"The directory refused a simple bind as {d['dn'] or 'anonymous'} with "
        f"{d['result_code']} strongerAuthRequired{_ad_suffix(d)}: it requires binds on an unprotected connection "
        "to be signed, and a simple bind cannot be. On Active Directory this is LDAP signing enforcement (the "
        "domain controller policy \"LDAP server signing requirements\" set to require signing, the default on "
        "current Windows Server), usually rolled out together with LDAP channel binding.",
        "Bind over LDAPS (636) or after StartTLS, or use a SASL bind that signs (GSSAPI or GSS-SPNEGO). Do not "
        "relax the directory's requirement: it protects against relay attacks.",
        None, False,
        ["For signing enforcement: resultCode 8 on a simple bind over an unencrypted connection"
         + (", and Active Directory's 00002028 says binds must be signed." if d.get("ad_leading") == "00002028"
            else "."),
         "Not settled from the capture: which policy applies. " + AD_SIGNING_EVENTS],
        ["ldap.bind_failed"])


def _ldap_channel_binding(found):
    f = _bind(found, lambda d: d["channel_binding"])
    if not f:
        return None
    return Cause(
        "ldap-channel-binding", "LDAP channel binding rejected",
        "The directory rejected the bind's channel binding (80090346): LDAP channel binding is enforced, and the "
        "client's binding to its TLS connection is missing or does not match. A TLS-inspecting proxy or a load "
        "balancer that terminates TLS between the client and the directory causes exactly this.",
        "Connect the client straight to the directory over LDAPS, with no device terminating TLS in between, and "
        "use a client that supports channel binding (Extended Protection for Authentication). " + AD_CBT_EVENTS,
        None, True, ["Direct: the diagnosticMessage carries 80090346, the channel binding error."],
        ["ldap.bind_failed"])


def _ldap_tls_required(found):
    f = _bind(found, lambda d: d["result_code"] == 13)
    if not f:
        return None
    return Cause(
        "ldap-tls-required", "the directory requires TLS",
        f"The directory refused the bind as {f.details['dn'] or 'anonymous'} with 13 confidentialityRequired: it "
        "only accepts binds over an encrypted connection.",
        "Connect with LDAPS (636) or send StartTLS before binding. Do not lower the directory's requirement: a "
        "simple bind without TLS sends the password in clear.",
        None, True, ["Direct: resultCode 13 confidentialityRequired."], ["ldap.bind_failed"])


AD_BIND_REASONS = {
    "525": ("the bind DN does not exist: the account was moved, renamed or deleted, or the DN is mistyped",
            "Find the account's current DN in the directory and correct it in the application."),
    "52e": ("the password stored in the application does not match the directory",
            "Test the DN and password with ldapwhoami (ldp.exe on Windows), then make the stored password match."),
    "530": ("the account may not log on at this time of day", "Change the account's logon hours."),
    "531": ("the account may only log on from certain computers", "Allow the application's host for this account."),
    "532": ("the account's password has expired", "Set a new password, then update the application with it."),
    "533": ("the account is disabled", "Enable the account, if it should be in use."),
    "701": ("the account has expired", "Extend or remove the account's expiry date."),
    "773": ("the password must be changed before the account can be used",
            "Set a new password, then update the application with it."),
    "775": ("the account is locked out, often by the application itself retrying an old password",
            "Fix the password stored in the application first, then unlock the account; otherwise the "
            "application locks it again."),
}


def _bind_cause(f, role):
    d = f.details
    dn = d["dn"] or "anonymous"
    reason = AD_BIND_REASONS.get(d.get("ad_data"))
    code = ldap_codes.describe(d["result_code"])
    evidence = [f"For {'a service account' if role == 'service' else 'a user account' if role == 'user' else 'either'}: "
                f"{d['role_reason']}."] if d.get("role_reason") else []
    if d.get("ad_data") is None and d["result_code"] == 49:
        evidence.append("Not settled by the result code: 49 means a wrong password, or a DN that does not exist "
                        "(OpenLDAP answers 49 for both); Active Directory adds a data code that tells them apart.")
    first = (reason[1] if reason else
             "Test the bind DN and the password the application stores with ldapwhoami (ldp.exe on Windows), then "
             "make the stored password match the directory.")
    why = f": {reason[0]}" if reason else ""
    return dn, code, why, first, evidence


def _ldap_service_bind(found):
    f = _bind(found, lambda d: d["role"] == "service" and d["result_code"] in (49, 48, 53))
    if not f:
        return None
    dn, code, why, first, evidence = _bind_cause(f, "service")
    return Cause(
        "ldap-service-bind-failed", "the service account cannot bind",
        f"The application's directory service account {dn} cannot bind ({code}){why}. Without it the application "
        "cannot look up any user, so every directory login fails, whatever password the user types.",
        first, runbooks.LDAP_BIND_FAILURE, f.details["role_certain"], evidence, ["ldap.bind_failed"])


def _ldap_user_bind(found):
    f = _bind(found, lambda d: d["role"] == "user" and d["result_code"] in (49, 48, 53))
    if not f:
        return None
    dn, code, why, first, evidence = _bind_cause(f, "user")
    if not AD_BIND_REASONS.get(f.details.get("ad_data")):
        first = ("Have the user check their password, and check the account (locked, expired, disabled) in the "
                 "directory. This is one user's problem, not an outage.")
    return Cause(
        "ldap-user-bind-failed", "the user's own bind failed",
        f"The user {dn} could not bind ({code}){why}. The application's own account and the user lookup are not "
        "the problem: this is one person's password or account, not an outage.",
        first, runbooks.LDAP_BIND_FAILURE, f.details["role_certain"], evidence, ["ldap.bind_failed"])


def _ldap_bind_unknown_role(found):
    f = _bind(found, lambda d: d["result_code"] in (49, 48, 53))
    if not f:
        return None
    dn, code, why, first, evidence = _bind_cause(f, None)
    return Cause(
        "ldap-bind-failed", "a bind was rejected",
        f"A bind as {dn} was rejected ({code}){why}. Whether it is the application's service account (every "
        "login fails) or one user (only they fail) is not clear from the capture.",
        first + " Add --service-dn with the application's bind DN to tell the two apart.",
        runbooks.LDAP_BIND_FAILURE, False, evidence, ["ldap.bind_failed"])


def _ldap_dn_missing(found):
    f = _bind(found, lambda d: d["result_code"] == 32) or next(
        (s for s in _all(found, "ldap.search_failed") if s.details["result_code"] == 32), None)
    if not f:
        return None
    d = f.details
    what = f"the bind DN {d['dn']}" if f.check_id == "ldap.bind_failed" else f"the search base {d['base']}"
    near = f" The closest entry that does exist is {d['matched_dn']}." if d.get("matched_dn") else ""
    return Cause(
        "ldap-dn-not-found", "a DN that does not exist",
        f"The directory says {what} does not exist (32 noSuchObject).{near} The entry was moved, renamed or "
        "deleted, or the application's setting is mistyped.",
        "Find the entry's current DN in the directory and correct the application's setting.",
        runbooks.LDAP_BIND_FAILURE, True, ["Direct: resultCode 32 noSuchObject."],
        ["ldap.bind_failed", "ldap.search_failed"])


def _ldap_access(found):
    f = next((s for s in _all(found, "ldap.search_failed") + _all(found, "ldap.operation_failed")
              if s.details["result_code"] == 50), None)
    if not f:
        return None
    return Cause(
        "ldap-insufficient-access", "the account lacks permission",
        "The directory refused an operation with 50 insufficientAccessRights: the account the application binds "
        "as is not allowed to read or change what it asked for.",
        "Grant the application's account read access to the users and groups it needs (and nothing more).",
        None, True, ["Direct: resultCode 50 insufficientAccessRights."],
        ["ldap.search_failed", "ldap.operation_failed"])


def _ldap_bind_needed(found):
    f = next((s for s in _all(found, "ldap.search_failed")
              if s.details.get("ad_leading") == "000004dc" or (s.details["result_code"] == 1 and not s.details["bound"])),
             None)
    if not f:
        return None
    return Cause(
        "ldap-bind-needed", "searched without binding",
        "The application searched without a successful bind first, and the directory refuses anonymous "
        "searches (Active Directory does by default).",
        "Configure the application with a service account to bind as before it searches.",
        None, True, ["Direct: the search failed with no successful bind before it on the connection."],
        ["ldap.search_failed"])


def _ldap_unauthenticated(found):
    f = next(iter(_all(found, "ldap.unauthenticated_bind", Status.FAIL)), None)
    if not f:
        return None
    after = f.details.get("followed_by") or []
    followed = (f" It was followed on the same connection by {', and '.join(after)}: an unauthenticated bind carries "
                "only anonymous rights, so those follow from it rather than from the account's permissions or the "
                "user's entry.") if after else ""
    return Cause(
        "ldap-unauthenticated-bind", "unauthenticated bind accepted",
        f"The application sent a bind as {f.details['dn']} with an empty password, and the directory accepted it as "
        "an unauthenticated bind. That proves nothing about the password: if the application takes it as a "
        f"successful login, anyone can log in as anyone by leaving the password empty.{followed}",
        "Make the application reject an empty password before it binds, and set the directory to refuse "
        "unauthenticated binds.",
        None, True, ["Direct: a simple bind with a DN, a zero-length password and resultCode 0."],
        ["ldap.unauthenticated_bind"])


def _ldap_user_not_found(found):
    f = _get(found, "ldap.search_empty", Status.WARN)
    if not f or not f.details["lookups"]:
        return None
    look = f.details["lookups"][0]
    return Cause(
        "ldap-user-not-found", "the user was not found",
        f"The application looked the user up with {look['filter']} under {look['base'] or 'the root DSE'} and found "
        "nothing, so it cannot go on to check their password. The user is not under that base DN, or the filter "
        "uses a different attribute from the one the directory holds log-on names in.",
        "Search for the user yourself (ldapsearch, or Active Directory Users and Computers) to see where they are "
        "and which attribute holds their log-on name, then correct the application's base DN or filter.",
        None, False, [], ["ldap.search_empty"])


def _ldap_tls_failed(found):
    f = _get(found, "ldap.tls", Status.FAIL, Status.WARN)
    if not f:
        return None
    d = f.details
    names = ", ".join(d["server_names"]) or "the directory's name"
    if d["alerts"]:
        summary = (f"The TLS handshake to the directory failed with a {d['alerts'][0]} alert, sent in clear. "
                   "That is a certificate or trust problem between the client and the directory.")
        confirmed, evidence = True, [f"Direct: a {d['alerts'][0]} alert."]
    else:
        summary = ("The TLS handshake to the directory ended before any data flowed, with no alert in clear. That "
                   "is consistent with an encrypted certificate or trust alert (TLS 1.3 encrypts them), so a trust "
                   "problem is likely and not ruled out.")
        confirmed = False
        evidence = ["For a trust problem: the handshake stopped after the server sent its certificate"
                    + (", and the client's only reply was the size of an alert." if d["alert_sized_close"] else ".")]
    return Cause(
        "ldap-tls-failed", "TLS handshake failed", summary,
        f"Check that the client trusts the CA that signed the directory's certificate, and that the certificate "
        f"names {names}. Test from the client host with: openssl s_client -connect <host>:636 -servername {names}",
        None, confirmed, evidence, ["ldap.tls"])


def _ldap_starttls_refused(found):
    f = _get(found, "ldap.starttls_refused")
    if not f:
        return None
    return Cause(
        "ldap-starttls-refused", "StartTLS refused",
        "The directory refused StartTLS, so the connection stayed unencrypted. It has no certificate configured "
        "for StartTLS, or does not offer it on this port.",
        "Configure a certificate for the directory's StartTLS, or connect with LDAPS on 636 instead.",
        None, True, [], ["ldap.starttls_refused"])


def _ldap_refused(found):
    f = _get(found, "ldap.refused")
    if not f:
        return None
    return Cause(
        "ldap-connection-refused", "connections refused",
        f"{f.details['server_label']} resets connections before any data: nothing listens on that port, or a "
        "firewall resets them.",
        "Check that the directory service is running and listening on that port, and that no firewall between "
        "the client and the directory resets the connection.",
        None, True, ["Direct: the server reset the connection with no data exchanged."], ["ldap.refused"])


def _ldap_unanswered(found):
    f = _get(found, "ldap.unanswered")
    if not f:
        return None
    return Cause(
        "ldap-no-response", "the directory did not respond",
        "Requests to the directory went unanswered" + (" until the directory closed the connection"
                                                      if f.details.get("closed_by") == "server"
                                                      else " until the client gave up") + ". The directory is "
        "overloaded or hung, or a device on the path drops the traffic.",
        "Check the directory's health and its access log for these requests, then the path between them.",
        None, False, [], ["ldap.unanswered"])


def _ldap_slow(found):
    f = _get(found, "ldap.response_time", Status.WARN)
    if not f:
        return None
    d = f.details
    return Cause(
        "ldap-slow", "slow directory",
        f"{d['server_label']} is slow to respond (p50 {secs(d['p50'])}, p95 {secs(d['p95'])}, slowest a "
        f"{d['slowest']}). Every login waits on it.",
        "Check the directory's load and its indexes: an unindexed attribute in a user search is a common cause.",
        None, True, [], ["ldap.response_time"])


LDAP_PATTERNS = (
    _ldap_signing,
    _ldap_channel_binding,
    _ldap_tls_required,
    _ldap_service_bind,
    _ldap_user_bind,
    _ldap_bind_unknown_role,
    _ldap_unauthenticated,  # above the causes it can explain: missing permission, a user not found
    _ldap_dn_missing,
    _ldap_access,
    _ldap_bind_needed,
    _ldap_user_not_found,
    _ldap_tls_failed,
    _ldap_starttls_refused,
    _ldap_refused,
    _ldap_unanswered,
    _ldap_slow,
)
