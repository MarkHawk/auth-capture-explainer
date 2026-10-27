"""The text report's layout and the analysis's capture-level findings."""

import io

import ldap_build as lb
import pcapbuild as pb
from ldap_build import Conversation
from pcap_analyser import render
from pcap_analyser.analyse import Options, analyse
from pcap_analyser.capture import read_capture
from pcap_analyser.findings import Status
from radius_trace import OTHER_CLIENT, Trace


def report_for(tmp_path, *sources, name="c.pcap", options=None):
    return analyse(read_capture(pb.capture_file(tmp_path, name, *sources)), options or Options())


def text(report):
    return render.render_text(report)


def test_one_pair_has_no_group_headings(tmp_path):
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1, code=3)
    out = text(report_for(tmp_path, t))
    assert "  -- " not in out
    assert "  For 192.0.2.10 (NAS-Identifier \"nas\") to 192.0.2.2:1812: login rejected by the server" in out


def test_two_pairs_get_headings_and_a_cause_each(tmp_path):
    t = Trace()
    for i in range(3):
        t.request(1.0 + 2 * i, 16, secret=b"x-secret", password=b"pw")
    t.request(2.0, 1, client=OTHER_CLIENT, user="erin", nas="nas-b")
    t.reply(3.0, 1, client=OTHER_CLIENT, code=3)
    out = text(report_for(tmp_path, t))
    assert '  -- 192.0.2.10 (NAS-Identifier "nas") to 192.0.2.2:1812 (RADIUS) --' in out
    assert '  -- 198.51.100.20 (NAS-Identifier "nas-b") to 192.0.2.2:1812 (RADIUS) --' in out
    causes = out.split("== Likely cause ==")[1].split("== Conversations ==")[0]
    assert sum(1 for line in causes.splitlines() if line.startswith("  For ")) == 2
    assert "== Servers (all clients) ==" in out  # one server, two clients


def test_capture_findings_come_first_and_server_findings_last(tmp_path):
    t = Trace()
    t.request(1.0, 1)
    t.reply(1.01, 1)
    data = pb.pcap([(ts, ip) for ts, ip in t.ips] + [(2.0, b"\x45\x00")], linktype=101)
    report = analyse(read_capture(pb.write(tmp_path, "d.pcap", data)))
    ids = [f.check_id for f in report.findings]
    assert ids[0] == "capture.malformed" and ids[-1] == "radius.secret"
    assert "first at frame 3: IPv4 header cut short" in report.findings[0].summary


def test_capture_notes_and_fragments(tmp_path):
    t = Trace()
    t.request(1.0, 1)
    frames = [(ts, ip) for ts, ip in t.ips] + [(2.0, pb.ipv4_fragment(pb.CLIENT, pb.SERVER, b"x" * 40))]
    data = pb.pcap(frames, linktype=101)
    report = analyse(read_capture(pb.write(tmp_path, "cut.pcap", data[:-5])))
    statuses = {f.check_id: f.status for f in report.findings}
    assert statuses["capture.note"] == Status.WARN  # cut short
    full = analyse(read_capture(pb.write(tmp_path, "frag.pcap", data)))
    assert {f.check_id: f.status for f in full.findings}["capture.fragments"] == Status.INFO


def test_unsupported_link_types_are_a_warning(tmp_path):
    report = analyse(read_capture(pb.write(tmp_path, "x.pcap", pb.pcap([(1.0, b"\x00" * 40)], linktype=147))))
    f = next(f for f in report.findings if f.check_id == "capture.link_type")
    assert f.status == Status.WARN and "link type 147" in f.summary


def test_nothing_relevant(tmp_path):
    t = Trace()
    t.raw(1.0, pb.udp(pb.CLIENT, pb.SERVER, 40000, 53, b"q"))
    t.raw(1.1, pb.udp(pb.SERVER, pb.CLIENT, 53, 40000, b"a"))
    report = report_for(tmp_path, t)
    out = text(report)
    assert "INFO  Nothing to analyse" in out and "The busiest ports are UDP 53 (2)" in out
    assert render.verdict_line(report) == "Verdict: nothing to analyse (0 FAIL, 0 WARN, 0 PASS, 1 INFO, 0 SKIP)"
    assert report.exit_code == 3  # not the same as a clean capture


def test_ldap_conversation_row(tmp_path):
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, "cn=svc,ou=services,dc=example", "x"))
    c.server_says(1.2, lb.bind_response(1, 49))
    c.client_says(1.3, lb.unbind(2))
    (row,) = render.conversation_rows(report_for(tmp_path, c))
    assert (row["protocol"], row["requests"], row["resent"], row["answered"], row["outcome"]) == (
        "LDAP", 1, None, 1, "bind 49, unbind")


def test_verdicts():
    class R:
        def __init__(self, counts):
            self.counts = counts
            self.nothing_to_analyse = False

        def count(self, s):
            return self.counts.get(s, 0)

    assert render.verdict_line(R({Status.FAIL: 2, Status.WARN: 1})).startswith(
        "Verdict: 2 problems to fix, 1 warning to review")
    assert render.verdict_line(R({Status.WARN: 1})).startswith("Verdict: no failures, 1 warning to review")
    assert render.verdict_line(R({Status.PASS: 3})).startswith("Verdict: no problems found")


def test_colour_only_on_a_terminal_and_never_with_no_color(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert render.use_colour(Tty()) and not render.use_colour(io.StringIO())
    monkeypatch.setenv("NO_COLOR", "1")
    assert not render.use_colour(Tty())


def test_lines_fit_the_width_except_urls_and_tables(tmp_path):
    t = Trace()
    for i in range(3):
        t.request(1.0 + 2 * i, 16, secret=b"x-secret", password=b"pw")
    out = text(report_for(tmp_path, t, options=Options(captured_on="server")))
    body = out.split("== Conversations ==")[0]
    long = [line for line in body.splitlines() if len(line) > render.WIDTH and "https://" not in line]
    assert long == []
