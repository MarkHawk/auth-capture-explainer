"""Turn LDAP connections into findings, per client and server.

As for RADIUS, the unit is the pair: one client (usually an application or
an identity provider) and one directory address and port. Every finding
carries details["pair"], and causes.py names one likely cause per pair.

The question a ticket usually turns on is whose bind failed. An application
binds twice per login: first as its own service account, to look the user
up, then as the user, to check their password. A failing service bind
breaks every login; a failing user bind is one person's problem. bind_role()
works that out from, in order of strength:

1. what the user said (service_dns, user_dns);
2. behaviour: a successful bind as that DN followed by searches on the same
   connection (an application's own account); failing that, a DN that a
   search returned as an entry (a user being checked after being looked up).
   Bind-then-search comes first because a service account's own entry can
   turn up in search results too (in a group lookup, say);
3. the DN's wording: ou=services, svc, and so on for a service account,
   ou=people or ou=users for a person. This is a hint, and is called one.

Encrypted connections (LDAPS, StartTLS, a SASL security layer) are reported
as such, with what the handshake shows and how to get a readable capture,
and no claim about what is inside.
"""

import re
from collections import Counter
from dataclasses import dataclass

from pcap_analyser import ldap, ldap_codes
from pcap_analyser import ldap_exchange as lx
from pcap_analyser.findings import Finding, Status
from pcap_analyser.latency import Summary
from pcap_analyser.radius_checks import server_key
from pcap_analyser.wording import article, listing, plural, secs

SLOW = 1.0  # seconds at p95
USER_FILTER = re.compile(r"\((?:uid|samaccountname|userprincipalname|mail|cn)=[^*)]", re.IGNORECASE)

SERVICE_WORDS = {"svc", "service", "services", "serviceaccount", "serviceaccounts", "system", "app", "apps",
                 "application", "applications", "bind", "binder", "proxy", "ldapbind", "readonly", "robot", "daemon"}
USER_WORDS = {"people", "users", "user", "staff", "employees", "persons", "students"}

READABLE_CAPTURE = (
    "To see the LDAP itself, capture where it is in clear: between a TLS-terminating proxy or load balancer and "
    "the directory, or on a test client using plain LDAP or StartTLS on a trusted network. Failing that, have "
    "the application log the LDAP result codes it gets, or read the directory's own access log. pcap-analyser "
    "does not decrypt TLS, even with keys.")


@dataclass(frozen=True)
class Role:
    role: str  # "service", "user" or None
    reason: str
    certain: bool  # from what the user said or from behaviour; False for a wording hint


def normalise_dn(dn):
    """Lower case, with spaces around separators removed, for comparing DNs."""
    return re.sub(r"\s*([,=+])\s*", r"\1", dn.strip()).lower()


def _words(dn):
    """The words in a DN's values (or a UPN's or DOMAIN\\name's account part)."""
    if "@" in dn and "=" not in dn:
        dn = dn.split("@", 1)[0]
    if "\\" in dn and "=" not in dn:
        dn = dn.split("\\", 1)[1]
    values = [part.split("=", 1)[-1] for part in re.split(r"(?<!\\),", dn)]
    words = set()
    for value in values:
        words.update(w for w in re.split(r"[^a-z0-9]+", value.lower()) if w)
        words.add(re.sub(r"[^a-z0-9]", "", value.lower()))
    return words


def bind_role(dn, result, service_dns=(), user_dns=()):
    """The likely role of a bind DN, judged across every connection in result (ldap_exchange.Result)."""
    key = normalise_dn(dn)
    if key in {normalise_dn(d) for d in service_dns}:
        return Role("service", "you named it as a service account", True)
    if key in {normalise_dn(d) for d in user_dns}:
        return Role("user", "you named it as a user", True)
    returned = {normalise_dn(m.dn) for c in result.connections for op in c.operations for m in op.responses
                if m.op == ldap.SEARCH_ENTRY and m.dn}
    for conn in result.connections:
        ops = conn.operations
        for i, op in enumerate(ops):
            if (op.request.op == ldap.BIND_REQUEST and normalise_dn(op.request.dn or "") == key and op.answered
                    and op.result.result_code == 0
                    and any(o.request.op == ldap.SEARCH_REQUEST for o in ops[i + 1:])):
                return Role("service", "a successful bind as this DN was followed by searches on the same "
                                       "connection, as an application's own account does", True)
    if key in returned:
        return Role("user", "an earlier search returned this DN as an entry, as an application does when it "
                            "looks a user up before checking their password", True)
    words = _words(dn)
    hint = sorted(words & SERVICE_WORDS)
    if hint:
        return Role("service", f"its name suggests one (\"{hint[0]}\"), though nothing in the capture shows how it "
                               "was used", False)
    hint = sorted(words & USER_WORDS)
    if hint:
        return Role("user", f"its name suggests a person (\"{hint[0]}\"), though nothing in the capture shows how "
                            "it was used", False)
    return Role(None, "nothing in the capture or the DN says whether it is a service account or a user", False)


@dataclass
class Pair:
    client: str
    server: str
    port: int
    connections: list
    result: object  # the whole ldap_exchange.Result
    label: str
    service_dns: tuple
    user_dns: tuple
    capture_end: float

    @property
    def operations(self):
        return [op for c in self.connections for op in c.operations]

    def ops(self, kind):
        return [op for op in self.operations if op.request.op == kind]


def pair_key(client, server, port):
    return f"{client} -> {server_key(server, port)}"


def check(result, service_dns=(), user_dns=(), capture_end=None):
    """Findings for an ldap_exchange.Result."""
    findings = []
    groups = {}
    for conn in result.connections:
        groups.setdefault((conn.client, conn.server, conn.server_port), []).append(conn)
    for (client, server, port), conns in groups.items():
        host = f"[{server}]" if ":" in server else server
        pair = Pair(client, server, port, conns, result, f"{host}:{result.ports.label(port)}",
                    tuple(service_dns), tuple(user_dns), capture_end)
        ctx = dict(pair=pair_key(client, server, port), server=server_key(server, port), server_label=pair.label,
                   client=client, client_label=client, protocol="ldap")
        for make in PAIR_CHECKS:
            for f in make(pair):
                f.details = {**ctx, **f.details}
                findings.append(f)
    findings += _global(result)
    return findings


# --- binds ---------------------------------------------------------------------------------

def _who_bound(req):
    if req.auth == "sasl":
        return f"a {req.mechanism} (SASL) bind" + (f" as {req.dn}" if req.dn else "")
    if not req.dn:
        return "an anonymous bind"
    return f"a bind as {req.dn}"


def _is_unauthenticated(req):
    """A simple bind with a DN and an empty password (RFC 4513, section 5.1.2): reported on its own."""
    return req.auth == "simple" and bool(req.dn) and req.password_length == 0


def _failed_binds(pair):
    failed = [op for op in pair.ops(ldap.BIND_REQUEST) if op.answered and not _is_unauthenticated(op.request)
              and op.result.result_code not in (ldap_codes.SUCCESS, ldap_codes.SASL_BIND_IN_PROGRESS)]
    groups = {}
    for op in failed:
        ad = ldap_codes.ad_data(op.result.diagnostic)
        key = (normalise_dn(op.request.dn or ""), op.request.auth, op.result.result_code, ad.code if ad else None)
        groups.setdefault(key, []).append(op)
    out = []
    for ops in groups.values():
        first = ops[0]
        req, res = first.request, first.result
        code = res.result_code
        meaning = ldap_codes.MEANINGS.get(code)
        s = (f"{pair.client} tried {_who_bound(req)} on {pair.label}: resultCode {ldap_codes.describe(code)}"
             + (f" ({meaning})" if meaning else "") + ".")
        s += (f" Diagnostic message: \"{res.diagnostic}\"." if res.diagnostic
              else " The directory gave no diagnosticMessage.")
        ad = ldap_codes.ad_data(res.diagnostic)
        if ad:
            s += f" Active Directory reason: data {ad.code}, {ad.name}: {ad.meaning}."
        lead = ldap_codes.ad_leading(res.diagnostic)
        if lead and not ad:
            s += f" Active Directory code {lead[0]}: {lead[1]}."
        if res.matched_dn:
            s += f" The closest existing entry is {res.matched_dn}."
        if len(ops) > 1:
            s += f" {len(ops)} attempts, all with this result."
        role = bind_role(req.dn, pair.result, pair.service_dns, pair.user_dns) if req.dn else Role(None, "", False)
        if role.role:
            s += (f" This is {'a service account' if role.role == 'service' else 'a user'}"
                  f"{'' if role.certain else ', probably'}: {role.reason}.")
        out.append(Finding("ldap.bind_failed", Status.FAIL, "Bind rejected", s, details={
            "dn": req.dn, "auth": req.auth, "mechanism": req.mechanism, "result_code": code,
            "ad_data": ad.code if ad else None, "ad_leading": lead[0] if lead else None,
            "attempts": len(ops), "role": role.role, "role_certain": role.certain, "role_reason": role.reason,
            "signing_required": req.auth == "simple" and ldap_codes.signing_required(code, res.diagnostic),
            "channel_binding": ldap_codes.channel_binding_rejected(res.diagnostic),
            "matched_dn": res.matched_dn}))
    return out


def _good_binds(pair):
    ok = [op for op in pair.ops(ldap.BIND_REQUEST) if op.answered and op.result.result_code == 0
          and not _is_unauthenticated(op.request)]
    if not ok:
        return []
    names = [(op.request.dn or "anonymous") if op.request.auth == "simple" else f"{op.request.mechanism} (SASL)"
             for op in ok]
    return [Finding("ldap.binds", Status.PASS, "Binds succeeded",
                    f"{plural(len(ok), 'bind')} from {pair.client} to {pair.label} succeeded: "
                    f"{listing(names, quote=False)}.", details={"count": len(ok), "dns": list(dict.fromkeys(names))})]


def _unauthenticated(pair):
    """A simple bind with a DN and an empty password: RFC 4513's unauthenticated bind."""
    out = []
    for op in pair.ops(ldap.BIND_REQUEST):
        req = op.request
        if not _is_unauthenticated(req):
            continue
        accepted = op.answered and op.result.result_code == 0
        s = (f"{pair.client} sent a simple bind as {req.dn} with an empty password. That is an unauthenticated "
             "bind (RFC 4513, section 5.1.2): it proves nothing about the password")
        if accepted:
            s += (", and the directory accepted it. An application that treats a successful bind as a successful "
                  "login would let anyone in as this user with an empty password.")
        elif op.answered:
            s += (f", and the directory refused it ({ldap_codes.describe(op.result.result_code)}), as it should. "
                  "The application should still reject an empty password before it binds.")
        else:
            s += ". No response was captured."
        after = _after_on_connection(pair, op) if accepted else []
        if after:
            s += f" On the same connection it was followed by {listing(after, quote=False)}."
        out.append(Finding("ldap.unauthenticated_bind", Status.FAIL if accepted else Status.WARN,
                           "Unauthenticated bind", s, details={"dn": req.dn, "accepted": accepted, "followed_by": after}))
    return out


def _after_on_connection(pair, op):
    """What went wrong after op on its connection, up to the next bind: failed results and empty searches.
    After an unauthenticated bind these follow from it, as it carries only anonymous rights."""
    for conn in pair.connections:
        if op not in conn.operations:
            continue
        out = []
        for later in conn.operations[conn.operations.index(op) + 1:]:
            if later.request.op == ldap.BIND_REQUEST:
                break
            if not later.answered:
                continue
            what = later.request.extended_name or later.name
            if later.result.result_code not in (0, 5, 6):
                out.append(f"a {what} that failed with {ldap_codes.describe(later.result.result_code)}")
            elif later.request.op == ldap.SEARCH_REQUEST and later.entries == 0:
                out.append(f"a search for {later.request.filter} that found nothing")
        return out
    return []


# --- searches and other operations ------------------------------------------------------------

def _searches(pair):
    searches = [op for op in pair.ops(ldap.SEARCH_REQUEST) if op.answered]
    out = []
    failed = [op for op in searches if op.result.result_code not in (0, ldap_codes.REFERRAL, 4)]
    for op in failed:
        res = op.result
        meaning = ldap_codes.MEANINGS.get(res.result_code)
        s = (f"A search by {pair.client} under {op.request.base or 'the root DSE'} for {op.request.filter} failed: "
             f"{ldap_codes.describe(res.result_code)}" + (f" ({meaning})" if meaning else "") + ".")
        if res.diagnostic:
            s += f" Diagnostic message: \"{res.diagnostic}\"."
        lead = ldap_codes.ad_leading(res.diagnostic)
        if lead:
            s += f" Active Directory code {lead[0]}: {lead[1]}."
        if res.matched_dn:
            s += f" The closest existing entry is {res.matched_dn}."
        out.append(Finding("ldap.search_failed", Status.FAIL, "Search failed", s, details={
            "base": op.request.base, "filter": op.request.filter, "result_code": res.result_code,
            "ad_leading": lead[0] if lead else None, "bound": _bound_before(pair, op)}))
    limited = [op for op in searches if op.result.result_code == 4]
    if limited:
        out.append(Finding("ldap.search_limited", Status.WARN, "Size limit", (
            f"{plural(len(limited), 'search', 'searches')} by {pair.client} hit the size limit "
            f"(4 sizeLimitExceeded) and returned only part of the matches; an application that expects one "
            "user may pick the wrong one or none."), details={"count": len(limited)}))
    empty = [op for op in searches if op.result.result_code == 0 and op.entries == 0]
    lookups = [op for op in empty if USER_FILTER.search(op.request.filter or "")]
    if empty:
        shown = listing([f"{op.request.filter} under {op.request.base or 'the root DSE'}" for op in empty], quote=False)
        s = f"{plural(len(empty), 'search', 'searches')} by {pair.client} found nothing: {shown}."
        if lookups:
            s += (" A user lookup that finds nothing means the user is not under that base DN, or the filter's "
                  "attribute is not the one the directory uses for log-on names.")
        out.append(Finding("ldap.search_empty", Status.WARN if lookups else Status.INFO, "Searches found nothing",
                           s, details={"count": len(empty), "lookups": [
                               {"base": op.request.base, "filter": op.request.filter} for op in lookups]}))
    good = [op for op in searches if op.result.result_code == 0]
    if good:
        entries = sum(op.entries for op in good)
        out.append(Finding("ldap.searches", Status.PASS, "Searches answered",
                           f"{plural(len(good), 'search', 'searches')} by {pair.client} answered, "
                           f"{plural(entries, 'entry', 'entries')} in total.",
                           details={"count": len(good), "entries": entries}))
    referrals = [op for op in searches if op.result.result_code == ldap_codes.REFERRAL or op.references]
    if referrals:
        out.append(Finding("ldap.referrals", Status.INFO, "Referrals", (
            f"{plural(len(referrals), 'search', 'searches')} by {pair.client} came back with referrals to other "
            "servers: the entries are held elsewhere (on Active Directory, often another domain; the Global "
            "Catalog on 3268 searches the whole forest)."), details={"count": len(referrals)}))
    return out


def _bound_before(pair, op):
    """Whether a bind succeeded on the same connection before this operation."""
    for conn in pair.connections:
        if op in conn.operations:
            before = conn.operations[:conn.operations.index(op)]
            return any(o.request.op == ldap.BIND_REQUEST and o.answered and o.result.result_code == 0
                       and (o.request.dn or o.request.auth == "sasl") for o in before)
    return False


def _other_results(pair):
    out = []
    for op in pair.operations:
        if op.request.op in (ldap.BIND_REQUEST, ldap.SEARCH_REQUEST) or not op.answered:
            continue
        code = op.result.result_code
        if code in (0, 5, 6) or (op.request.is_starttls):
            continue
        what = op.request.extended_name or op.name
        s = f"{what} from {pair.client} failed: {ldap_codes.describe(code)}."
        if op.result.diagnostic:
            s += f" Diagnostic message: \"{op.result.diagnostic}\"."
        out.append(Finding("ldap.operation_failed", Status.FAIL, "Operation failed", s,
                           details={"operation": what, "result_code": code}))
    return out


def _unanswered(pair):
    """Requests with no response, told apart by how the wait ended: the client gave up (Abandon, Unbind, or
    closing the connection), the server closed it, or the capture ended while they were still pending.
    Each is reported with the real time it waited; there is no fixed grace period."""
    out = []
    for conn in pair.connections:
        waiting = [op for op in conn.operations if op.expects_response and not op.answered]
        ended, pending = [], []
        for op in waiting:
            how = _how_the_wait_ended(conn, op)
            if how is None:
                pending.append(op)
            else:
                ended.append((op, how))
        if ended:
            parts = [f"{article(_op_name(op))} {_op_name(op)}, {phrase}" for op, (phrase, _) in ended]
            s = (f"{plural(len(ended), 'request')} from {pair.client} to {pair.label} got no response: "
                 f"{'; '.join(parts)}.")
            by = [who for _, (_, who) in ended]
            out.append(Finding("ldap.unanswered", Status.FAIL, "No response", s, details={
                "count": len(ended), "operations": [_op_name(op) for op, _ in ended],
                "ended_by": by, "closed_by": "server" if "server" in by else "client"}))
        if pending:
            end = pair.capture_end if pair.capture_end is not None else conn.stream.last_ts
            waits = [end - op.request.ts for op in pending]
            names = listing([_op_name(op) for op in pending], quote=False)
            waited = (f"after {secs(waits[0])}" if len(pending) == 1
                      else f"after {secs(min(waits))} to {secs(max(waits))}")
            out.append(Finding("ldap.pending", Status.WARN, "No response yet", (
                f"{plural(len(pending), 'request')} from {pair.client} to {pair.label} ({names}) had no response "
                f"{waited}; the capture ended while {'it was' if len(pending) == 1 else 'they were'} still "
                "pending, so a response may have come later, or not at all."),
                details={"count": len(pending), "waited": max(waits), "operations": [_op_name(op) for op in pending]}))
    return out


def _op_name(op):
    return op.request.extended_name or op.name


def _how_the_wait_ended(conn, op):
    """(phrase, "client" or "server") saying how the wait for a response ended, or None if still pending."""
    sent = op.request.ts
    if op.abandoned:
        return f"which the client abandoned {secs(op.abandoned_at - sent)} later", "client"
    unbind = next((o for o in conn.operations if o.request.op == ldap.UNBIND and o.request.ts >= sent), None)
    if unbind is not None:
        return f"then the client unbound {secs(unbind.request.ts - sent)} later", "client"
    closes = []
    for side, d in (("client", conn.stream.to_server), ("server", conn.stream.to_client)):
        if d.rst or d.fin:
            closes.append((d.last_ts, side, "reset" if d.rst else "closed"))
    if not closes:
        return None
    when, side, verb = min(closes)
    return f"then the {side} {verb} the connection {secs(max(when - sent, 0))} later", side


def _notices(pair):
    notices = [n for c in pair.connections for n in c.notices]
    if not notices:
        return []
    n = notices[0]
    s = (f"{pair.label} sent {pair.client} an unsolicited {n.extended_name or 'notice'} "
         f"({ldap_codes.describe(n.result_code)})")
    s += f": \"{n.diagnostic}\"." if n.diagnostic else "."
    s += " The server was closing the connection on its own initiative (shutting down, or an idle or "
    s += "administrative limit)."
    return [Finding("ldap.notice", Status.WARN, "Notice of Disconnection", s,
                    details={"count": len(notices), "result_code": n.result_code})]


def _response_time(pair):
    answered = [op for op in pair.operations if op.answered]
    if not answered:
        return []
    times = Summary.of(op.response_time for op in answered)
    slowest = max(answered, key=lambda op: op.response_time)
    s = (f"{pair.label} to {pair.client}: {plural(times.count, 'response')}, p50 {secs(times.p50)}, "
         f"p95 {secs(times.p95)}, slowest {secs(times.max)} (a {slowest.name}).")
    status = Status.PASS
    if times.p95 >= SLOW:
        status = Status.WARN
        s += (" That is slow: applications typically time out LDAP operations after a few seconds, and a slow "
              "bind or user search delays every login.")
    return [Finding("ldap.response_time", status, "Response times", s, details={
        "count": times.count, "p50": times.p50, "p95": times.p95, "max": times.max, "slowest": slowest.name})]


# --- connections that cannot be read ----------------------------------------------------------

def _tls(pair):
    conns = [c for c in pair.connections if c.encrypted]
    if not conns:
        return []
    kinds = Counter("StartTLS" if c.kind == lx.STARTTLS else "TLS from the start" for c in conns)
    shown = ", ".join(f"{n} {k}" for k, n in kinds.items())
    infos = [c.tls for c in conns if c.tls is not None]
    s = (f"{plural(len(conns), 'connection')} from {pair.client} to {pair.label} "
         f"{'uses' if len(conns) == 1 else 'use'} TLS ({shown}): the LDAP "
         "inside cannot be read, and this tool makes no claim about it.")
    names = list(dict.fromkeys(i.server_name for i in infos if i.server_name))
    if names:
        s += f" Server name asked for: {listing(names, quote=False)}."
    versions = list(dict.fromkeys(i.server_version for i in infos if i.server_version))
    if versions:
        s += f" TLS version chosen: {listing(versions, quote=False)}."
    outcomes = list(dict.fromkeys(i.outcome() for i in infos))
    s += " " + " ".join(outcomes)
    alerted = [i for i in infos if any(a.level == "fatal" for a in i.plaintext_alerts)]
    unfinished = [i for i in infos if not i.completed and not i.plaintext_alerts]
    status = Status.FAIL if alerted else Status.WARN if unfinished else Status.INFO
    return [Finding("ldap.tls", status, "Encrypted (TLS)", s, next_step=READABLE_CAPTURE, details={
        "connections": len(conns), "starttls": kinds.get("StartTLS", 0), "server_names": names,
        "versions": versions, "alerts": [a.description for i in infos for a in i.plaintext_alerts],
        "completed": sum(1 for i in infos if i.completed), "unfinished": len(unfinished),
        "tls13_unfinished": sum(1 for i in unfinished if i.tls13 and i.server_hello),
        "alert_sized_close": sum(1 for i in infos if i.alert_sized_close)})]


def _starttls_refused(pair):
    refused = [op for op in pair.operations if op.request.is_starttls and op.answered and op.result.result_code != 0]
    if not refused:
        return []
    res = refused[0].result
    s = (f"{pair.label} refused StartTLS from {pair.client}: {ldap_codes.describe(res.result_code)}"
         + (f" (\"{res.diagnostic}\")" if res.diagnostic else "") + ". The connection stayed unencrypted, so any "
         "simple bind on it sends its password in clear.")
    return [Finding("ldap.starttls_refused", Status.FAIL, "StartTLS refused", s,
                    details={"result_code": res.result_code})]


def _sasl_layer(pair):
    conns = [c for c in pair.connections if c.kind == lx.SASL]
    if not conns:
        return []
    mechs = listing(list(dict.fromkeys(c.sasl_mechanism for c in conns if c.sasl_mechanism)), quote=False)
    return [Finding("ldap.sasl_layer", Status.INFO, "Signed or sealed (SASL)", (
        f"After a {mechs} bind, {plural(len(conns), 'connection')} from {pair.client} to {pair.label} "
        f"{'continues' if len(conns) == 1 else 'continue'} signed or sealed by the SASL security layer (Kerberos or NTLM; Active Directory's default). "
        "What follows the bind cannot be read, and this tool makes no claim about it."),
        next_step=READABLE_CAPTURE, details={"connections": len(conns), "mechanisms": mechs})]


def _unreadable(pair):
    out = []
    unreadable = [c for c in pair.connections if c.kind == lx.UNREADABLE]
    if unreadable:
        out.append(Finding("ldap.unreadable", Status.WARN, "Unreadable connections", (
            f"{plural(len(unreadable), 'connection')} from {pair.client} to {pair.label} carried bytes that are "
            "neither LDAP nor the start of TLS, usually because the capture joined them part-way through "
            "(encrypted traffic looks like this)."), details={"count": len(unreadable)}))
    empty = [c for c in pair.connections if c.kind == lx.EMPTY]
    reset = [c for c in empty if c.stream.reset_by in ("server", "both")]
    if reset:
        out.append(Finding("ldap.refused", Status.FAIL, "Connections refused", (
            f"{pair.label} reset {plural(len(reset), 'connection')} from {pair.client} before any data: nothing "
            "is listening on that port, or a firewall resets the connections."), details={"count": len(reset)}))
    elif empty:
        out.append(Finding("ldap.empty", Status.INFO, "Empty connections", (
            f"{plural(len(empty), 'connection')} from {pair.client} to {pair.label} carried no data (opened and "
            "closed, as a health check does)."), details={"count": len(empty)}))
    return out


def _damage(pair):
    problems = [p for c in pair.connections for p in c.problems]
    gaps = sum(c.gaps for c in pair.connections)
    if not problems and not gaps:
        return []
    parts = []
    if problems:
        first = min(problems, key=lambda p: p.frame or 0)
        parts.append(f"{plural(len(problems), 'message')} could not be read (first at frame {first.frame}: "
                     f"{first.reason})")
    if gaps:
        parts.append(f"{plural(gaps, 'gap')} where the capture missed packets, so some messages may be missing")
    return [Finding("ldap.damaged", Status.WARN, "Damaged or missing data",
                    f"On connections from {pair.client} to {pair.label}: " + "; ".join(parts) + ".",
                    details={"problems": len(problems), "gaps": gaps})]


PAIR_CHECKS = (_failed_binds, _unauthenticated, _good_binds, _searches, _other_results, _starttls_refused,
               _unanswered, _notices, _tls, _sasl_layer, _unreadable, _damage, _response_time)


def _global(result):
    orphans = sum(len(c.orphan_responses) for c in result.connections)
    if not orphans:
        return []
    return [Finding("ldap.orphan_responses", Status.INFO, "Responses without requests", (
        f"{plural(orphans, 'response')} answer requests that are not in the capture, usually because it started "
        "after they were sent."), details={"count": orphans})]
