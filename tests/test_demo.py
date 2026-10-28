"""`auth-capture-explainer demo`: the bundled captures, their one-line summaries and full reports."""

import io
import json

import pytest

from conftest import ROOT
from auth_capture_explainer import demo
from auth_capture_explainer.cli import EXIT_ERROR, EXIT_FAIL, EXIT_OK, main

DEMO = ROOT / "src" / "auth_capture_explainer" / "demo_samples"
EXPECTED = {
    "radius-ok": ("PASS", "no problems found"),
    "radius-reject": ("FAIL", "login rejected by the server"),
    "radius-secret": ("FAIL", "shared secret mismatch, most likely"),
    "ldap-service": ("FAIL", "the service account cannot bind"),
    "ldaps": ("INFO", "encrypted: no claim about what is inside"),
    "ad-locked": ("FAIL", "the service account cannot bind (likely)"),
}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(["demo", *argv], stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_the_list():
    code, out, err = run()
    assert code == EXIT_OK and err == ""
    lines = out.splitlines()
    assert lines[0] == "auth-capture-explainer demo: 6 bundled captures, analysed offline"
    rows = [line.split() for line in lines[2:8]]
    assert [r[0] for r in rows] == list(EXPECTED)
    for line, (name, (status, text)) in zip(lines[2:8], EXPECTED.items()):
        assert f"  {status}  " in line + "  " and line.rstrip().endswith(text), name
    assert lines[-2].startswith("Full report for one capture:  auth-capture-explainer demo <name>")


@pytest.mark.parametrize("name", list(EXPECTED))
def test_each_full_report(name):
    code, out, _ = run(name)
    assert out.startswith(f"$ auth-capture-explainer {name}.pcap")
    assert code == (EXIT_OK if EXPECTED[name][0] in ("PASS", "INFO") else EXIT_FAIL)
    assert "\nVerdict: " in out


def test_the_reject_sample_checks_the_secret_and_shows_how():
    _, out, _ = run("radius-reject")
    assert out.startswith("$ auth-capture-explainer radius-reject.pcap --secret-file sample.secret\n")
    assert "Secret:   given from file sample.secret (never shown)" in out
    assert "How sure:  confirmed by the capture" in out


def test_health_checks_are_folded_in_the_demo_unless_verbose():
    _, out, _ = run("radius-secret")
    assert "INFO  Health checks" in out and "-- 127.0.0.1" not in out
    _, out, _ = run("radius-secret", "--verbose")
    assert "-- 127.0.0.1 to 127.0.0.1:1812 (RADIUS) --" in out


def test_json_for_one_capture():
    code, out, _ = run("ad-locked", "--json")
    data = json.loads(out)
    assert code == EXIT_FAIL and data["capture"]["name"] == "ad-locked.pcap"
    failed = next(f for f in data["findings"] if f["code"] == "ldap.bind_failed")
    assert failed["details"]["ad_data"] == "775"


def test_errors():
    code, _, err = run("nonesuch")
    assert code == EXIT_ERROR and "no capture 'nonesuch'; choose from radius-ok" in err
    with pytest.raises(SystemExit) as e:
        main(["demo", "--json"], stdout=io.StringIO(), stderr=io.StringIO())
    assert e.value.code == 2


def test_the_samples_are_the_lab_captures_and_one_labelled_synthetic():
    samples = demo.load_samples(DEMO)
    assert [s["name"] for s in samples] == list(EXPECTED)
    for s in samples:
        meta = json.loads((DEMO / f"{s['file']}.meta.json").read_text())
        if meta["made"] == "synthetic":
            assert s["name"] == "ad-locked" and "(synthetic)" in s["title"]
        else:
            lab = ROOT / meta["copied_from"]
            assert (DEMO / s["file"]).read_bytes() == lab.read_bytes(), s["name"]
    assert (DEMO / "sample.secret").read_bytes() == (ROOT / "samples" / "lab" / "sample.secret").read_bytes()


def test_one_line_wording():
    def report(causes, verdict, fail=0, warn=0):
        return {"likely_causes": causes, "summary": {"fail": fail, "warn": warn, "verdict": verdict}}

    two = [{"label": "a", "confirmed": True}, {"label": "b", "confirmed": False}]
    assert demo.one_line(report(two, "x", fail=1)) == ("FAIL", "a (+1 more)")
    assert demo.one_line(report([], "no failures, 1 warning to review (...)", warn=1)) == (
        "WARN", "no failures, 1 warning to review")
