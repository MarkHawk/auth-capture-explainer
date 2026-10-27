#!/usr/bin/env python3
"""Check that files are safe to commit.

Generic patterns only: private (RFC 1918) IPv4 addresses, home directory
paths other than /home/pi, and private key blocks. Extra personal strings
(a name, a hostname) come from a local, gitignored .personal-patterns file:
one string per line, matched as a whole word and case-sensitively (so a first
name does not match ordinary words that contain it); lines starting with
"re:" are regular expressions, so "re:(?i)..." ignores case; "#" starts a
comment. The committed .personal-patterns.example is deliberately empty.

This scans text. Packet captures carry addresses and passwords in binary
fields, which the capture sanitiser (added with the lab captures) checks.

    python scripts/sanitise.py --check samples/lab        # exit 1 if anything is found
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PERSONAL_FILE = ROOT / ".personal-patterns"

RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.])"
)
HOME_DIR = re.compile(r"/home/(?!pi(?![A-Za-z0-9_.-]))[A-Za-z_][A-Za-z0-9_.-]*")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")


def load_personal_patterns(path=PERSONAL_FILE):
    """Compiled patterns from the local file; an absent file means none."""
    path = pathlib.Path(path)
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            patterns.append(re.compile(line[3:]))
        else:
            patterns.append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(line) + r"(?![A-Za-z0-9])"))
    return patterns


def find_problems(text, personal=()):
    """Names of the pattern kinds found; never the matched values themselves."""
    found = []
    if RFC1918.search(text):
        found.append("private IPv4 address")
    if HOME_DIR.search(text):
        found.append("home directory path")
    if PRIVATE_KEY.search(text):
        found.append("private key")
    if any(p.search(text) for p in personal):
        found.append("personal pattern from .personal-patterns")
    return found


def check_paths(paths, personal=None):
    """Return a list of (file, problem kind) for everything under paths."""
    personal = load_personal_patterns() if personal is None else personal
    problems = []
    for root in paths:
        root = pathlib.Path(root)
        files = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
        for f in files:
            text = f.read_bytes().decode("utf-8", errors="replace")
            problems += [(str(f), k) for k in find_problems(text, personal)]
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check files contain nothing private before committing them.")
    parser.add_argument("--check", nargs="+", metavar="PATH", required=True, help="files or directories to scan")
    args = parser.parse_args(argv)
    problems = check_paths(args.check)
    for path, kind in problems:
        print(f"sanitise: {path}: contains a {kind}", file=sys.stderr)
    if problems:
        print("sanitise: refusing: fix or delete the files above before committing", file=sys.stderr)
        return 1
    print(f"sanitise: clean ({', '.join(args.check)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
