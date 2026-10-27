"""Render a Report as text for a person, or as JSON for another tool.

The text report reads top to bottom as a support engineer would work: what
the capture holds, the findings (grouped by client and server when there is
more than one pair), the likely cause of each failing pair with its evidence
and first step, a table of conversations, and a verdict.

The JSON carries the same content in a stable shape, with schema_version for
consumers to check. Neither ever contains the shared secret, a password or
anything derived from them: the Report does not hold them.
"""

import datetime as dt
import json
import os
import textwrap
from collections import Counter

from pcap_analyser import __version__, ldap, runbooks
from pcap_analyser import ldap_exchange as lx
from pcap_analyser import radius_exchange as rx
from pcap_analyser.analyse import link_names
from pcap_analyser.findings import Status
from pcap_analyser.latency import Summary
from pcap_analyser.radius_checks import client_label, server_label
from pcap_analyser.wording import plural, secs

WIDTH = 100
SCHEMA_VERSION = 1
COLOURS = {Status.PASS: "32", Status.WARN: "33", Status.FAIL: "31;1", Status.INFO: "36", Status.SKIP: "2"}
STATUS_ORDER = (Status.FAIL, Status.WARN, Status.PASS, Status.INFO, Status.SKIP)
OUTCOME_WIDTH = 34


def use_colour(stream):
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def _wrap(text, width, first="", rest=""):
    return textwrap.wrap(text, width, initial_indent=first, subsequent_indent=rest,
                         break_long_words=False, break_on_hyphens=False) or [first.rstrip()]


def _when(ts):
    return dt.datetime.fromtimestamp(ts, dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# --- text --------------------------------------------------------------------------------

def render_text(report, colour=False):
    def paint(text, status):
        return f"\033[{COLOURS[status]}m{text}\033[0m" if colour else text

    out = [f"pcap-analyser {__version__}", *_header(report)]
    out += ["", "== Findings =="]
    width = max((len(f.title) for f in report.findings), default=0)
    indent = " " * (2 + 4 + 2 + width + 2)
    groups = _groups(report.findings)
    for heading, findings in groups:
        if heading and sum(1 for h, _ in groups if h) > 1:
            out += ["", f"  -- {heading} --"]
        for f in findings:
            head = f"  {paint(f.status.value, f.status)}{' ' * (4 - len(f.status.value))}  {f.title:<{width}}  "
            body = _wrap(f.summary, WIDTH - len(indent))
            out.append(head + body[0])
            out += [indent + line for line in body[1:]]
            if f.next_step and f.status in (Status.FAIL, Status.WARN, Status.INFO):
                out += _wrap(f.next_step, WIDTH, indent + "Next: ", indent + "      ")
            if f.runbook:
                out.append(f"{indent}Runbook: identity-lab {f.runbook}")
    if not report.findings:
        out.append("  (nothing to report)")
    out += _cause_lines(report)
    out += _conversation_lines(report)
    out += _server_lines(report)
    out += ["", verdict_line(report)]
    return "\n".join(out) + "\n"


def _header(report):
    cap = report.capture
    when = ""
    if cap.first_ts is not None:
        when = f" over {secs(cap.last_ts - cap.first_ts)}, from {_when(cap.first_ts)}"
    stopped = ", stopped early" if cap.stopped_early else ""
    lines = [f"Capture:  {cap.name} ({cap.format}, {', '.join(link_names(cap)) or 'no packets'}, "
             f"{plural(cap.frames, 'packet')}{when}{stopped})"]
    lines.append(f"Seen:     {seen_line(report)}")
    opts = report.options
    if opts["secret_given"]:
        lines.append(f"Secret:   given from {opts['secret_source']} (never shown)")
    if opts["captured_on"]:
        lines.append(f"Taken on: the {opts['captured_on']}, as you said")
    return lines


def seen_line(report):
    rad, lda = report.radius, report.ldap
    if rad.exchanges:
        clients = len({e.client for e in rad.exchanges})
        servers = len({(e.server, e.server_port) for e in rad.exchanges})
        radius_text = (f"RADIUS {plural(len(rad.exchanges), 'request')} from {plural(clients, 'client')} to "
                       f"{plural(servers, 'server')}")
    else:
        radius_text = "RADIUS none"
    if lda.connections:
        kinds = Counter(KIND_WORDS[c.kind] for c in lda.connections)
        detail = ", ".join(f"{n} {k}" for k, n in kinds.items())
        ldap_text = f"LDAP {plural(len(lda.connections), 'connection')} ({detail})"
    else:
        ldap_text = "LDAP none"
    return f"{radius_text}; {ldap_text}"


KIND_WORDS = {lx.LDAP: "clear text", lx.STARTTLS: "StartTLS", lx.TLS: "TLS", lx.SASL: "SASL signed or sealed",
              lx.EMPTY: "empty", lx.UNREADABLE: "unreadable"}


def _protocol(f):
    return f.details.get("protocol") or f.check_id.split(".")[0]


def _groups(findings):
    """[(heading or None, findings)]: capture-level first, then each pair, then anything else."""
    top = [f for f in findings if f.check_id.startswith("capture.")]
    pairs, rest = {}, []
    for f in findings:
        if f.check_id.startswith("capture."):
            continue
        if "pair" in f.details:
            d = f.details
            heading = f"{d['client_label']} to {d['server_label']} ({_protocol(f).upper()})"
            pairs.setdefault(heading, []).append(f)
        else:
            rest.append(f)
    out = [(None, top)] if top else []
    out += list(pairs.items())
    if rest:
        out.append((None, rest))
    return out


def _cause_lines(report):
    if not report.causes:
        return []
    out = ["", "== Likely cause =="]
    titles = {}
    for f in report.findings:
        titles.setdefault((f.details.get("server_label"), f.details.get("client_label"), f.check_id), f.title)
    for i, cause in enumerate(report.causes):
        out += ([""] if i else []) + [f"  For {cause.client} to {cause.server}: {cause.label}"]
        out += _wrap(cause.summary, WIDTH, "  ", "  ")
        rows = [("How sure", "confirmed by the capture" if cause.confirmed
                 else "likely: the evidence points to it, but does not settle it")]
        rows += [("Evidence", e) for e in cause.evidence]
        rows.append(("First", cause.first_step))
        if cause.runbook:
            rows.append(("Runbook", f"identity-lab {cause.runbook}"))
            rows.append(("", runbooks.url(cause.runbook)))
        explained = [titles.get((cause.server, cause.client, c), c) for c in cause.explains]
        if explained:
            rows.append(("Explains", ", ".join(dict.fromkeys(explained))))
        label_width = max(len(label) for label, _ in rows) + 1
        for label, text in rows:
            first = f"  {(label + ':') if label else '':<{label_width}}  "
            out += _wrap(text, WIDTH, first, " " * len(first))
    return out


def conversation_rows(report):
    """One row per client and server pair: protocol, client, server, requests, resends, answered, outcome,
    p50 and p95 (Access-Rejects left out of the times, as everywhere)."""
    rows = []
    for conv in report.radius.conversations():
        normal = conv.response_times
        rows.append({
            "protocol": "RADIUS", "client": conv.client, "client_label": client_label(conv.client, conv.exchanges),
            "server": server_label(conv.server, conv.server_port, report.radius.ports),
            "requests": conv.requests, "resent": conv.retransmissions, "answered": conv.answered,
            "outcome": _radius_outcome(conv), "p50": normal.p50, "p95": normal.p95,
        })
    groups = {}
    for conn in report.ldap.connections:
        groups.setdefault((conn.client, conn.server, conn.server_port), []).append(conn)
    for (client, server, port), conns in groups.items():
        ops = [op for c in conns for op in c.operations if op.expects_response]
        times = Summary.of(op.response_time for op in ops if op.answered)
        host = f"[{server}]" if ":" in server else server
        rows.append({
            "protocol": "LDAP", "client": client, "client_label": client,
            "server": f"{host}:{report.ldap.ports.label(port)}",
            "requests": len(ops), "resent": None, "answered": sum(1 for op in ops if op.answered),
            "outcome": _ldap_outcome(conns), "p50": times.p50, "p95": times.p95,
        })
    return rows


SHORT = {"Access-Accept": "Accept", "Access-Reject": "Reject", "Access-Challenge": "Challenge",
         "Accounting-Response": "Accounting OK", rx.NO_REPLY: "no reply", rx.CAPTURE_ENDED: "capture ended"}


def _radius_outcome(conv):
    counts = Counter()
    for e in conv.exchanges:
        word = SHORT.get(e.outcome, e.outcome)
        if e.code == 12 and e.answered:
            word = "Status-Server OK"
        counts[word] += 1
    return ", ".join(f"{word} x{n}" if n > 1 else word for word, n in counts.items())


def _ldap_outcome(conns):
    counts = Counter()
    for conn in conns:
        if conn.kind in (lx.TLS, lx.EMPTY, lx.UNREADABLE):
            counts[KIND_WORDS[conn.kind]] += 1
            continue
        for op in conn.operations:
            name = {ldap.BIND_REQUEST: "bind", ldap.SEARCH_REQUEST: "search", ldap.UNBIND: "unbind",
                    ldap.ABANDON: "abandon"}.get(op.request.op, op.request.extended_name or op.name)
            if not op.expects_response:
                counts[name] += 1
            elif op.answered:
                code = op.result.result_code
                counts[f"{name} {'OK' if code == 0 else code}"] += 1
            else:
                counts[f"{name} no reply"] += 1
        if conn.kind in (lx.STARTTLS, lx.SASL):
            counts["then " + KIND_WORDS[conn.kind]] += 1
    return ", ".join(f"{word} x{n}" if n > 1 else word for word, n in counts.items())


def _table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    numeric = [all(isinstance(r[i], int) for r in rows) for i in range(len(headers))]

    def line(cells):
        return "  " + "  ".join(str(c).rjust(w) if n else str(c).ljust(w)
                                for c, w, n in zip(cells, widths, numeric)).rstrip()

    return [line(headers), *(line(r) for r in rows)]


def _tsecs(s):
    """A duration for a table cell."""
    return "<1 ms" if s is not None and s < 0.001 else secs(s)


def _short(text, width):
    return text if len(text) <= width else text[:width - 3] + "..."


def _conversation_lines(report):
    rows = conversation_rows(report)
    if not rows:
        return []
    table = [[r["protocol"], r["client"], r["server"], r["requests"], "-" if r["resent"] is None else r["resent"],
              r["answered"], _short(r["outcome"], OUTCOME_WIDTH), _tsecs(r["p50"]), _tsecs(r["p95"])] for r in rows]
    return ["", "== Conversations =="] + _table(
        ["Proto", "Client", "Server", "Requests", "Resent", "Answered", "Outcome", "p50", "p95"], table)


def _server_lines(report):
    shared = [s for s in report.servers if s.clients > 1]
    if not shared:
        return []
    table = [[s.protocol.upper(), s.label, s.clients, s.requests, s.unanswered, _tsecs(s.times.p50),
              _tsecs(s.times.p95)] for s in shared]
    return ["", "== Servers (all clients) =="] + _table(
        ["Proto", "Server", "Clients", "Requests", "No reply", "p50", "p95"], table)


def verdict_line(report):
    fails, warns = report.count(Status.FAIL), report.count(Status.WARN)
    counts = ", ".join(f"{report.count(s)} {s.value}" for s in STATUS_ORDER)
    if fails:
        verdict = plural(fails, "problem") + " to fix"
        if warns:
            verdict += ", " + plural(warns, "warning") + " to review"
    elif warns:
        verdict = "no failures, " + plural(warns, "warning") + " to review"
    elif report.nothing_to_analyse:
        verdict = "nothing to analyse"
    else:
        verdict = "no problems found"
    return f"Verdict: {verdict} ({counts})"


# --- JSON ----------------------------------------------------------------------------------

def _json_value(v):
    if isinstance(v, Status):
        return v.value
    if isinstance(v, dict):
        return {str(k): _json_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_json_value(x) for x in v]
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def _iso(ts):
    if ts is None:
        return None
    return dt.datetime.fromtimestamp(ts, dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def report_dict(report):
    """A stable, machine-readable form of the report for --json."""
    cap = report.capture
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "pcap-analyser",
        "version": __version__,
        "capture": {
            "name": cap.name, "format": cap.format, "size_bytes": cap.size, "link_types": link_names(cap),
            "packets": cap.frames, "first_packet": _iso(cap.first_ts), "last_packet": _iso(cap.last_ts),
            "skipped_damaged": sum(cap.malformed.values()), "ignored": sum(cap.ignored.values()),
            "stopped_early": cap.stopped_early, "notes": list(cap.notes),
        },
        "options": _json_value(report.options),
        "seen": seen_line(report),
        "findings": [{
            "check_id": f.check_id, "status": f.status.value, "protocol": _protocol(f), "title": f.title,
            "summary": f.summary, "next_step": f.next_step, "runbook": f.runbook,
            "runbook_url": runbooks.url(f.runbook) if f.runbook else None, "details": _json_value(f.details),
        } for f in report.findings],
        "likely_causes": [{
            "pattern": c.pattern, "label": c.label, "confirmed": c.confirmed, "client": c.client, "server": c.server,
            "summary": c.summary, "evidence": list(c.evidence), "first_step": c.first_step, "runbook": c.runbook,
            "runbook_url": runbooks.url(c.runbook) if c.runbook else None, "explains": list(c.explains),
        } for c in report.causes],
        "conversations": [_json_value(r) for r in conversation_rows(report)],
        "servers": [{
            "protocol": s.protocol, "server": s.server, "label": s.label, "clients": s.clients,
            "requests": s.requests, "unanswered": s.unanswered, "responses_timed": s.times.count,
            "p50": s.times.p50, "p95": s.times.p95, "p99": s.times.p99, "max": s.times.max, "slow": s.slow,
        } for s in report.servers],
        "summary": {
            **{s.value.lower(): report.count(s) for s in STATUS_ORDER},
            "verdict": verdict_line(report).removeprefix("Verdict: "),
            "exit_code": report.exit_code,
        },
    }


def render_json(report):
    return json.dumps(report_dict(report), indent=2, ensure_ascii=False) + "\n"
