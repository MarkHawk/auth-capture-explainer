"""identity-lab runbooks that a finding can point to.

https://github.com/MarkHawk/identity-lab reproduces these failures on
purpose; each runbook explains symptom, diagnosis, fix and prevention.
"""

LAB_URL = "https://github.com/MarkHawk/identity-lab"

RUNBOOKS = {
    "04-ldap-bind-failure": "LDAP bind failure (user federation)",
    "05-radius-shared-secret-mismatch": "RADIUS shared secret mismatch",
}

LDAP_BIND_FAILURE = "04-ldap-bind-failure"
RADIUS_SECRET_MISMATCH = "05-radius-shared-secret-mismatch"


def url(name):
    return f"{LAB_URL}/blob/main/runbooks/{name}.md"
