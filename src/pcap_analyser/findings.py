"""Check results.

Each finding is one statement about the capture, with a status:

- FAIL: a problem that stops logins (no reply, a rejected bind, a secret
  that does not match);
- WARN: something that may cause trouble or deserves a look;
- PASS: a check that came out well, shown so the reader sees what was ruled out;
- INFO: context that is neither good nor bad, such as where the capture was taken;
- SKIP: not checked, with what to supply to check it.

Findings are per server where that matters, so check_id repeats across
servers and details["server"] tells them apart.
"""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    FAIL = "FAIL"
    WARN = "WARN"
    PASS = "PASS"
    INFO = "INFO"
    SKIP = "SKIP"


@dataclass
class Finding:
    check_id: str  # stable, e.g. "radius.unanswered"
    status: Status
    title: str  # short label, e.g. "Requests unanswered"
    summary: str  # plain English, one or more sentences
    next_step: str = None
    runbook: str = None
    details: dict = field(default_factory=dict)  # machine-readable facts, for causes and --json


def worst(findings):
    """The most serious status present, FAIL first."""
    for status in (Status.FAIL, Status.WARN, Status.PASS, Status.INFO, Status.SKIP):
        if any(f.status == status for f in findings):
            return status
    return None
