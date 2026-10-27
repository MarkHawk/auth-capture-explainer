"""Per-server summaries across all clients, for both protocols.

The findings are per client and server pair. A server can still be slow or
unresponsive for everyone, so this sums each server up across its clients:
requests, how many got no reply, and response-time percentiles. The report's
table and --json are built from these. When a server with more than one
client is slow overall, a finding says so; with one client the pair's own
response-time finding already does.

RADIUS Access-Rejects are left out of the times, as everywhere: servers
delay them on purpose.
"""

from dataclasses import dataclass

from pcap_analyser import radius_checks
from pcap_analyser import radius_exchange as rx
from pcap_analyser.findings import Finding, Status
from pcap_analyser.latency import Summary
from pcap_analyser.radius_dict import ACCESS_REJECT
from pcap_analyser.wording import plural, secs

SLOW = 1.0  # seconds at p95, as for the pair findings


@dataclass(frozen=True)
class ServerSummary:
    protocol: str  # "radius" or "ldap"
    server: str  # address:port
    label: str
    clients: int
    requests: int
    unanswered: int
    times: Summary  # response times, Access-Rejects left out

    @property
    def slow(self):
        return self.times.count > 0 and self.times.p95 >= SLOW


def summaries(radius_result=None, ldap_result=None):
    out = []
    if radius_result is not None:
        for conv in radius_result.servers():
            exchanges = conv.exchanges
            out.append(ServerSummary(
                "radius", radius_checks.server_key(conv.server, conv.server_port),
                radius_checks.server_label(conv.server, conv.server_port, radius_result.ports),
                len({e.client for e in exchanges}), len(exchanges),
                sum(1 for e in exchanges if e.outcome == rx.NO_REPLY),
                Summary.of(e.response_time for e in exchanges if e.answered and e.reply.code != ACCESS_REJECT)))
    if ldap_result is not None:
        groups = {}
        for conn in ldap_result.connections:
            groups.setdefault((conn.server, conn.server_port), []).append(conn)
        for (server, port), conns in groups.items():
            ops = [op for c in conns for op in c.operations if op.expects_response]
            host = f"[{server}]" if ":" in server else server
            out.append(ServerSummary(
                "ldap", radius_checks.server_key(server, port), f"{host}:{ldap_result.ports.label(port)}",
                len({c.client for c in conns}), len(ops), sum(1 for op in ops if not op.answered and not op.abandoned),
                Summary.of(op.response_time for op in ops if op.answered)))
    return out


def check(summaries_list):
    """A finding for each server that is slow across more than one client."""
    out = []
    for s in summaries_list:
        if not s.slow or s.clients < 2:
            continue
        out.append(Finding("server.slow", Status.WARN, "Slow server", (
            f"{s.label} ({s.protocol.upper()}) is slow for all its {s.clients} clients: "
            f"{plural(s.times.count, 'response')}, p50 {secs(s.times.p50)}, p95 {secs(s.times.p95)}, slowest "
            f"{secs(s.times.max)}."), details={"server": s.server, "server_label": s.label, "protocol": s.protocol,
                                               "p50": s.times.p50, "p95": s.times.p95, "clients": s.clients}))
    return out
