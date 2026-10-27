"""The workflow keeps its promises: least privilege and actions pinned to SHAs."""

import re

from conftest import ROOT

WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def test_actions_are_pinned_to_full_shas():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_read_only_token_and_ubuntu():
    assert "permissions:\n  contents: read" in WORKFLOW
    assert "runs-on: ubuntu-latest" in WORKFLOW
