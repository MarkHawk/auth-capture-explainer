"""The machine-readable codes are stable: every code the source can emit is
registered in codes.py, and the registry matches the snapshot below. To add a
code, add it to both. Renaming or removing one breaks consumers of --json, so
it needs a new major version and a CHANGELOG entry as well as this edit."""

import io
import json
import re

import pcapbuild as pb
from conftest import ROOT
from pcap_analyser import codes
from pcap_analyser.cli import main
from radius_trace import Trace

SRC = ROOT / "src" / "pcap_analyser"

FINDINGS_SNAPSHOT = {
    "capture.fragments", "capture.link_type", "capture.malformed", "capture.note", "capture.nothing",
    "ldap.bind_failed", "ldap.binds", "ldap.damaged", "ldap.empty", "ldap.notice", "ldap.operation_failed",
    "ldap.orphan_responses", "ldap.pending", "ldap.referrals", "ldap.refused", "ldap.response_time",
    "ldap.sasl_layer", "ldap.search_empty", "ldap.search_failed", "ldap.search_limited", "ldap.searches",
    "ldap.starttls_refused", "ldap.tls", "ldap.unanswered", "ldap.unauthenticated_bind", "ldap.unreadable",
    "radius.answering", "radius.capture_ended", "radius.capture_point", "radius.challenges", "radius.icmp",
    "radius.legacy_port", "radius.malformed", "radius.message_authenticator",
    "radius.message_authenticator_position", "radius.orphan_replies", "radius.rejects",
    "radius.reply_from_elsewhere", "radius.reply_message_authenticator", "radius.response_time",
    "radius.reused_ids", "radius.secret", "radius.secret_shape", "radius.unanswered", "server.slow",
}
CAUSES_SNAPSHOT = {
    "ldap-bind-failed", "ldap-bind-needed", "ldap-channel-binding", "ldap-connection-refused",
    "ldap-dn-not-found", "ldap-insufficient-access", "ldap-no-response", "ldap-service-bind-failed",
    "ldap-signing-required", "ldap-slow", "ldap-starttls-refused", "ldap-tls-failed", "ldap-tls-required",
    "ldap-unauthenticated-bind", "ldap-user-bind-failed", "ldap-user-not-found", "radius-firewall",
    "radius-no-message-authenticator", "radius-no-reply", "radius-port-closed", "radius-reply-wrong-address",
    "radius-secret-mismatch", "radius-secret-unknown", "radius-slow", "radius-unanswered-secret-ok",
    "radius-unreachable", "radius-user-rejected",
}


def source():
    return "\n".join(p.read_text() for p in SRC.glob("*.py"))


def test_every_finding_code_in_the_source_is_registered():
    emitted = set(re.findall(r'Finding\(\s*"([a-z_.]+)"', source()))
    assert emitted == set(codes.FINDINGS)


def test_every_cause_code_in_the_source_is_registered():
    emitted = set(re.findall(r'Cause\(\s*"([a-z0-9-]+)"', source()))
    assert emitted == set(codes.CAUSES)


def test_the_registry_matches_the_snapshot():
    assert set(codes.FINDINGS) == FINDINGS_SNAPSHOT
    assert set(codes.CAUSES) == CAUSES_SNAPSHOT


def test_codes_are_well_formed_and_described():
    assert all(re.fullmatch(r"(capture|radius|ldap|server)\.[a-z_]+", c) for c in codes.FINDINGS)
    assert all(re.fullmatch(r"(radius|ldap)-[a-z-]+", c) for c in codes.CAUSES)
    assert all(meaning and "—" not in meaning for meaning in [*codes.FINDINGS.values(), *codes.CAUSES.values()])


def test_json_carries_the_codes(tmp_path):
    t = Trace()
    t.request(1.0, 1)
    t.reply(2.0, 1, code=3)
    out = io.StringIO()
    main([str(pb.capture_file(tmp_path, "r.pcap", t)), "--json"], stdout=out, stderr=io.StringIO())
    data = json.loads(out.getvalue())
    assert all(f["code"] == f["check_id"] and f["code"] in codes.FINDINGS for f in data["findings"])
    assert [c["code"] for c in data["likely_causes"]] == ["radius-user-rejected"]
