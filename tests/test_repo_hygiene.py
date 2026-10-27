"""Nothing private is committed: no private IPv4 addresses, no home
directories other than /home/pi, no private keys, no personal strings from
the local .personal-patterns file (absent in CI), and no raw captures outside
the sanitised samples. Checks tracked files and new files git would add."""

import re
import subprocess

import pytest

from conftest import ROOT, load_script

sanitise = load_script("sanitise")

# Public GitHub URLs name the account that hosts the repo; that is expected.
GITHUB_ACCOUNT = re.compile(r"github\.com/[A-Za-z0-9-]+")
# The licence names its copyright holder by design.
PERSONAL_EXEMPT = {"LICENSE"}
# The only places a capture may be committed: sanitised lab samples and the demo.
CAPTURE_DIRS = ("samples/lab/", "src/pcap_analyser/demo_samples/")


def repo_files():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / line for line in out.splitlines() if line and (ROOT / line).is_file()]


def test_no_private_addresses_paths_or_keys():
    problems = []
    for path in repo_files():
        text = path.read_bytes().decode("utf-8", errors="replace")
        problems += [f"{path.relative_to(ROOT)}: {kind}" for kind in sanitise.find_problems(text)]
    assert not sorted(set(problems))


def test_no_personal_patterns():
    personal = sanitise.load_personal_patterns(ROOT / ".personal-patterns")
    if not personal:
        return  # no local file, as in CI: nothing extra to check
    problems = []
    for path in repo_files():
        if path.name in PERSONAL_EXEMPT:
            continue
        text = GITHUB_ACCOUNT.sub("github.com/ACCOUNT", path.read_bytes().decode("utf-8", errors="replace"))
        if any(p.search(text) for p in personal):
            problems.append(str(path.relative_to(ROOT)))
    assert not problems, f"personal patterns found in: {problems}"


def test_no_captures_outside_the_sanitised_folders():
    for path in repo_files():
        rel = path.relative_to(ROOT).as_posix()
        if path.suffix in (".pcap", ".pcapng", ".cap"):
            assert rel.startswith(CAPTURE_DIRS), rel


def test_scratch_captures_are_ignored():
    for name in ("scratch/spike/radius.pcap", "raw.pcapng", "samples/raw.pcap"):
        ignored = subprocess.run(["git", "check-ignore", "-q", name], cwd=ROOT, check=False)
        assert ignored.returncode == 0, name


def test_personal_patterns_file_is_ignored_and_example_is_empty():
    ignored = subprocess.run(["git", "check-ignore", "-q", ".personal-patterns"], cwd=ROOT, check=False)
    assert ignored.returncode == 0
    assert (ROOT / ".personal-patterns.example").read_text() == ""
