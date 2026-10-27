"""`pcap-analyser demo`: run the bundled captures and summarise each in a line.

The captures live in demo_samples/ (built by scripts/build_demo_samples.py):
sanitised captures from identity-lab, and one synthetic Active Directory
capture the lab cannot produce. Nothing here touches the network: it is the
normal command line run over packaged files.
"""

import argparse
import contextlib
import importlib.resources
import io
import json

from pcap_analyser.wording import plural

INTRO = "pcap-analyser demo: {n} bundled captures, analysed offline"


def build_parser():
    p = argparse.ArgumentParser(
        prog="pcap-analyser demo",
        description="Run pcap-analyser on bundled captures. No network, no flags needed.",
    )
    p.add_argument("name", nargs="?", help="show the full report for one capture (see the list without a name)")
    p.add_argument("--json", action="store_true", help="with a name, print its report as JSON")
    p.add_argument("--verbose", action="store_true", help="with a name, show the capturing host's health checks in full")
    return p


@contextlib.contextmanager
def sample_dir():
    with importlib.resources.as_file(importlib.resources.files("pcap_analyser") / "demo_samples") as path:
        yield path


def load_samples(folder):
    return json.loads((folder / "demo.json").read_text())["samples"]


def sample_argv(folder, sample):
    return [str(folder / sample["file"]), *(a.replace("{dir}", str(folder)) for a in sample["args"])]


def shown_command(sample):
    """The command as a user would type it in the samples folder: file names, not install paths."""
    args = [a.replace("{dir}/", "") for a in sample["args"]]
    return " ".join(["pcap-analyser", sample["file"], *args])


def one_line(data):
    """(status, text) summarising a JSON report: its likely cause, or else its verdict."""
    causes = data["likely_causes"]
    summary = data["summary"]
    status = "FAIL" if summary["fail"] else "WARN" if summary["warn"] else "PASS"
    if causes:
        more = f" (+{plural(len(causes) - 1, 'more')})" if len(causes) > 1 else ""
        label = causes[0]["label"]
        sure = "" if causes[0]["confirmed"] or "likely" in label else " (likely)"
        return status, f"{label}{sure}{more}"
    if summary["verdict"].startswith("no problems visible"):
        return "INFO", "encrypted: no claim about what is inside"
    return status, summary["verdict"].split(" (")[0]


def run_demo(argv, stdout, stderr, cli):
    """cli is the pcap_analyser.cli module, passed in to avoid an import cycle."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.json or args.verbose) and not args.name:
        parser.error("--json and --verbose need a capture name, for example: pcap-analyser demo radius-secret --json")
    with sample_dir() as folder:
        samples = load_samples(folder)
        names = [s["name"] for s in samples]
        if args.name:
            if args.name not in names:
                print(f"pcap-analyser demo: no capture {args.name!r}; choose from {', '.join(names)}", file=stderr)
                return cli.EXIT_ERROR
            sample = samples[names.index(args.name)]
            extra = (["--json"] if args.json else []) + (["--verbose"] if args.verbose else [])
            if not args.json:
                print(f"$ {shown_command(sample)}", file=stdout)
            return cli.main(sample_argv(folder, sample) + extra, stdout=stdout, stderr=stderr)
        print(INTRO.format(n=len(samples)), file=stdout)
        print(file=stdout)
        name_width = max(len(n) for n in names)
        title_width = max(len(s["title"]) for s in samples)
        for sample in samples:
            out = io.StringIO()
            cli.main(sample_argv(folder, sample) + ["--json"], stdout=out, stderr=io.StringIO())
            status, text = one_line(json.loads(out.getvalue()))
            print(f"  {sample['name']:<{name_width}}  {sample['title']:<{title_width}}  {status:<4}  {text}",
                  file=stdout)
        print(file=stdout)
        print("Full report for one capture:  pcap-analyser demo <name>   e.g. pcap-analyser demo radius-secret",
              file=stdout)
        print("Try your own capture:         pcap-analyser <file.pcap>", file=stdout)
    return cli.EXIT_OK
