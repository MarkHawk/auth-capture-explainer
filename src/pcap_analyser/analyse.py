"""Run every analysis over a capture and gather the results into a Report.

The order: read the capture, find and pair RADIUS and LDAP, turn each into
findings per client and server pair, add per-server and capture-level
findings, then name the likely causes. The Report holds everything the text
and JSON renderers need, and nothing secret: when a shared secret is given,
only where it came from is kept.
"""

from collections import Counter
from dataclasses import dataclass, field

from pcap_analyser import ldap_checks, ldap_exchange, radius, radius_checks, radius_exchange, servers
from pcap_analyser.causes import likely_causes
from pcap_analyser.findings import Finding, Status
from pcap_analyser.layers import LINKTYPE_NAMES
from pcap_analyser.wording import listing, plural

CUT_OR_DAMAGED = ("cut short", "damaged", "Stopped after", "interrupted")


@dataclass
class Options:
    radius_ports: radius.Ports = radius.DEFAULT_PORTS
    ldap_ports: ldap_exchange.Ports = ldap_exchange.DEFAULT_PORTS
    secret: object = None  # a secret.Secret; never stored on the Report
    captured_on: str = None  # "server" or "client"
    service_dns: tuple = ()
    user_dns: tuple = ()
    reply_window: float = radius_exchange.DEFAULT_REPLY_WINDOW


@dataclass
class Report:
    capture: object  # capture.Capture (its packets are dropped once analysed)
    options: dict  # what was asked for, with the secret reduced to where it came from
    radius: object = None  # radius_exchange.Result
    ldap: object = None  # ldap_exchange.Result
    servers: list = field(default_factory=list)  # servers.ServerSummary
    findings: list = field(default_factory=list)
    causes: list = field(default_factory=list)

    def count(self, status):
        return sum(1 for f in self.findings if f.status == status)

    @property
    def exit_code(self):
        return 1 if self.count(Status.FAIL) else 0


def analyse(cap, options=None):
    """A Report for a capture.Capture."""
    options = options or Options()
    rad = radius_exchange.analyse(cap.packets, options.radius_ports, cap.last_ts, options.reply_window)
    lda = ldap_exchange.analyse(cap.packets, options.ldap_ports)
    findings = _capture_findings(cap, rad, lda, options)
    findings += radius_checks.check(rad, options.secret, options.captured_on)
    findings += ldap_checks.check(lda, options.service_dns, options.user_dns, cap.last_ts)
    summaries = servers.summaries(rad, lda)
    findings += servers.check(summaries)
    report = Report(cap, _options_dict(options), rad, lda, summaries, findings, likely_causes(findings))
    cap.packets = []  # everything needed has been taken from them
    return report


def _options_dict(options):
    secret = options.secret
    return {
        "radius_ports": sorted(options.radius_ports.all),
        "ldap_ports": sorted(options.ldap_ports.all),
        "secret_given": secret is not None,
        "secret_source": secret.source if secret is not None else None,
        "captured_on": options.captured_on,
        "service_dns": list(options.service_dns),
        "user_dns": list(options.user_dns),
        "reply_window": options.reply_window,
    }


def _capture_findings(cap, rad, lda, options):
    out = []
    for note in cap.notes:
        damaged = any(word in note for word in CUT_OR_DAMAGED)
        out.append(Finding("capture.note", Status.WARN if damaged else Status.INFO, "Capture file", note))
    malformed = sum(cap.malformed.values())
    if malformed:
        reason, first = min(cap.first_malformed.items(), key=lambda kv: kv[1])
        out.append(Finding("capture.malformed", Status.WARN, "Damaged packets", (
            f"{plural(malformed, 'packet')} could not be decoded and {'was' if malformed == 1 else 'were'} skipped "
            f"(first at frame {first}: {reason})."), details={"count": malformed, "reasons": dict(cap.malformed)}))
    unsupported = {r: n for r, n in cap.ignored.items() if r.startswith("link type")}
    if unsupported:
        out.append(Finding("capture.link_type", Status.WARN, "Unsupported link type", (
            f"{plural(sum(unsupported.values()), 'packet')} use a link type this tool cannot read "
            f"({listing(unsupported, quote=False)}). Re-save the capture from Wireshark as pcapng, or capture on an "
            "Ethernet or 'any' interface."), details={"reasons": unsupported}))
    fragments = cap.ignored.get("IP fragment (fragments are not reassembled)", 0)
    if fragments:
        out.append(Finding("capture.fragments", Status.INFO, "IP fragments", (
            f"{plural(fragments, 'IP fragment')} {'was' if fragments == 1 else 'were'} not reassembled. A large "
            "RADIUS message (EAP carrying certificates, for example) may be among them and missing from the "
            "analysis."), details={"count": fragments}))
    if not rad.exchanges and not rad.orphan_replies and not rad.malformed and not lda.connections:
        out.append(_nothing_relevant(cap, options))
    return out


def _nothing_relevant(cap, options):
    ports = Counter()
    for p in cap.packets:
        if p.proto in ("tcp", "udp"):
            ports[(p.proto, min(p.sport, p.dport))] += 1
    busiest = [f"{proto.upper()} {port} ({n})" for (proto, port), n in ports.most_common(5)]
    s = (f"No RADIUS (UDP {', '.join(map(str, sorted(options.radius_ports.all)))}) or LDAP (TCP "
         f"{', '.join(map(str, sorted(options.ldap_ports.all)))}) traffic is in this capture.")
    if busiest:
        s += (f" The busiest ports are {', '.join(busiest)}. If RADIUS or LDAP runs on one of those, add "
              "--radius-port or --ldap-port.")
    else:
        s += " It holds no TCP or UDP traffic at all."
    return Finding("capture.nothing", Status.INFO, "Nothing to analyse", s,
                   details={"busiest": [{"proto": proto, "port": port, "packets": n}
                                        for (proto, port), n in ports.most_common(5)]})


def link_names(cap):
    return [LINKTYPE_NAMES.get(t, f"link type {t}") for t in cap.linktypes]
