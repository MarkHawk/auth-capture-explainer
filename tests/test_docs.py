"""The README's examples are the tool's real output, and the docs cover every
option, demo capture and code, in UK English without em dashes."""

import io
import re

from conftest import ROOT
from auth_capture_explainer import codes, demo
from auth_capture_explainer.cli import build_parser, main

README = (ROOT / "README.md").read_text()
USAGE = (ROOT / "docs" / "usage.md").read_text()
CAUSES = (ROOT / "docs" / "causes.md").read_text()
DOCS = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "samples" / "lab" / "README.md",
        *(ROOT / "docs").glob("*.md")]


def section(text, heading):
    return text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


def code_blocks(text):
    return re.findall(r"```\n(.*?)```", text, re.S)


def output(*argv):
    out = io.StringIO()
    main(list(argv), stdout=out, stderr=io.StringIO())
    return out.getvalue()


def test_the_problem_comes_first_then_the_quick_start():
    assert README.startswith("# auth-capture-explainer\n\n**auth-capture-explainer reads a packet capture and explains")
    assert re.findall(r"^## .*", README, re.M)[0] == "## Try it in 1 minute"


def test_quick_start_install_is_three_commands():
    install = code_blocks(section(README, "Try it in 1 minute"))[0]
    assert install.splitlines() == ["python3 -m venv venv", "source venv/bin/activate", "pip install -e ."]


def test_quick_start_shows_the_demo_with_its_real_output():
    blocks = code_blocks(section(README, "Try it in 1 minute"))
    assert blocks[1] == "auth-capture-explainer demo\n"
    assert blocks[2] == output("demo")


def test_the_full_report_is_real_output():
    blocks = code_blocks(section(README, "Try it in 1 minute").split("### One full report\n", 1)[1])
    assert blocks[0] == "auth-capture-explainer demo radius-secret\n"
    assert blocks[1] == output("demo", "radius-secret")


def test_usage_lists_every_option():
    options = [o for a in build_parser()._actions for o in a.option_strings if o.startswith("--")]
    options += [o for a in demo.build_parser()._actions for o in a.option_strings if o.startswith("--")]
    missing = [o for o in options if o != "--help" and f"`{o}" not in USAGE]
    assert not missing


def test_usage_lists_every_demo_capture():
    for s in demo.load_samples(ROOT / "src" / "auth_capture_explainer" / "demo_samples"):
        assert f"| `{s['name']}` |" in USAGE


def test_usage_lists_every_code_and_causes_describes_every_cause():
    for code in codes.FINDINGS:
        assert f"| `{code}` |" in USAGE, code
    for code in codes.CAUSES:
        assert f"| `{code}` |" in USAGE and f"`{code}`" in CAUSES, code


def test_usage_gives_every_exit_status():
    for status in ("| 0 |", "| 1 |", "| 2 |", "| 3 |", "| 130 |"):
        assert status in USAGE


def test_readme_links_the_runbooks_and_the_related_tool():
    assert "runbooks/04-ldap-bind-failure.md" in README and "runbooks/05-radius-shared-secret-mismatch.md" in README
    assert "github.com/MarkHawk/token-inspector" in README


def test_readme_says_how_it_was_built():
    assert "written with AI-assisted tooling (Claude Code)" in README


def test_no_em_dashes_in_docs():
    for path in DOCS:
        assert "—" not in path.read_text(), path.name


def test_uk_spelling_in_docs():
    american = re.compile(r"\b(analyze|analyzed|analyzing|color|behavior|license file|sanitize|sanitized|"
                          r"recognize|organization)\b", re.I)  # "Global Catalog" is a product name
    for path in DOCS:
        found = american.findall(path.read_text())
        assert not found, (path.name, found)
