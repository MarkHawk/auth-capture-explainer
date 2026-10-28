"""Each capture taken from identity-lab gives the answer the scenario calls for,
with and without the sample secret."""

import io
import json

import pytest

from conftest import ROOT
from auth_capture_explainer.cli import main

LAB = ROOT / "samples" / "lab"
SECRET = ["--secret-file", str(LAB / "sample.secret")]

# label: (exit status, likely causes as (code, confirmed)), without and with the sample secret
EXPECTED = {
    "radius-accept": ((0, []), (0, [])),
    "radius-reject": ((1, [("radius-user-rejected", False)]), (1, [("radius-user-rejected", True)])),
    "radius-05-broken": ((1, [("radius-secret-mismatch", False)]), (1, [("radius-secret-mismatch", False)])),
    "radius-05-fixed": ((0, []), (0, [])),
    "ldap-good": ((0, []), None),
    "ldap-04-broken": ((1, [("ldap-service-bind-failed", True)]), None),
    "ldap-04-fixed": ((0, []), None),
    "ldaps-04-encrypted": ((0, []), None),
}


def run(label, *extra):
    meta = json.loads((LAB / f"{label}.pcap.meta.json").read_text())
    out = io.StringIO()
    code = main([str(LAB / f"{label}.pcap"), *meta["args"], "--json", *extra], stdout=out, stderr=io.StringIO())
    return code, json.loads(out.getvalue())


def causes(data):
    return [(c["code"], c["confirmed"]) for c in data["likely_causes"]]


@pytest.mark.parametrize("label", sorted(EXPECTED))
def test_without_a_secret(label):
    code, data = run(label)
    assert (code, causes(data)) == EXPECTED[label][0]


@pytest.mark.parametrize("label", sorted(k for k, v in EXPECTED.items() if v[1] is not None))
def test_with_the_sample_secret(label):
    code, data = run(label, *SECRET)
    assert (code, causes(data)) == EXPECTED[label][1]
    nas = [f for f in data["findings"] if f["code"] == "radius.secret" and not f["details"]["loopback"]]
    if label == "radius-05-broken":
        assert nas[0]["details"]["client_match"] is False  # the NAS uses another secret
    else:
        assert all(f["status"] == "PASS" for f in nas)


def test_05_broken_cites_the_servers_own_traffic():
    _, data = run("radius-05-broken", *SECRET)
    (cause,) = data["likely_causes"]
    assert any("loopback address verifies with the secret you gave" in e for e in cause["evidence"])


def test_04_broken_is_the_service_account_by_behaviour():
    _, data = run("ldap-04-broken")
    failed = next(f for f in data["findings"] if f["code"] == "ldap.bind_failed")
    assert failed["details"]["dn"] == "cn=keycloak-svc,ou=services,dc=idlab,dc=example"
    assert "followed by searches on the same connection" in failed["details"]["role_reason"]
    assert data["likely_causes"][0]["runbook"] == "04-ldap-bind-failure"


def test_the_encrypted_capture_claims_nothing_about_its_contents():
    _, data = run("ldaps-04-encrypted")
    tls = next(f for f in data["findings"] if f["code"] == "ldap.tls")
    assert tls["status"] == "INFO" and "makes no claim" in tls["summary"] and tls["next_step"]
    assert data["summary"]["verdict"].startswith("no problems visible, but 1 connection is encrypted")
