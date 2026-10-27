"""Command-line entry point."""

import argparse
import sys

from pcap_analyser import __version__, ldap_exchange, radius, radius_exchange
from pcap_analyser import secret as secrets
from pcap_analyser.analyse import Options, analyse
from pcap_analyser.capture import CaptureError, Limits, MiB, read_capture, read_stream
from pcap_analyser.render import render_json, render_text, use_colour

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def port(value):
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a port number") from None
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"{n} is not a port number (1 to 65535)")
    return n


def positive(kind):
    def parse(value):
        try:
            n = kind(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
        if n <= 0:
            raise argparse.ArgumentTypeError(f"{value} must be more than 0")
        return n
    return parse


def build_parser():
    p = argparse.ArgumentParser(
        prog="pcap-analyser",
        description="Read a packet capture and explain RADIUS and LDAP authentication failures in plain English. "
                    "Fully offline: it reads the file and nothing else.",
        epilog="Exit status: 0 no failed checks, 1 at least one FAIL, 2 the capture or the secret could not be "
               "read.",
    )
    p.add_argument("capture", help="the .pcap or .pcapng file to read; '-' reads standard input")

    ports = p.add_argument_group("ports")
    ports.add_argument("--radius-port", action="append", type=port, default=[], metavar="PORT",
                       help="also read UDP PORT as RADIUS (1812, 1813, 1645 and 1646 always are); repeatable")
    ports.add_argument("--ldap-port", action="append", type=port, default=[], metavar="PORT",
                       help="also read TCP PORT as LDAP, clear or TLS (389, 636, 3268 and 3269 always are); repeatable")

    sec = p.add_argument_group("RADIUS shared secret (never shown, never on the command line)")
    how = sec.add_mutually_exclusive_group()
    how.add_argument("--secret", action="store_true", help="ask for the secret on the terminal, without echo")
    how.add_argument("--secret-file", metavar="FILE", help="read the secret from FILE (one trailing newline removed)")
    how.add_argument("--secret-env", metavar="NAME", help="read the secret from the environment variable NAME")

    ctx = p.add_argument_group("what you know about the capture")
    ctx.add_argument("--captured-on", choices=["server", "client"],
                     help="where the capture was taken, when the capture itself does not say")
    ctx.add_argument("--service-dn", action="append", default=[], metavar="DN",
                     help="an application's LDAP service account DN; repeatable")
    ctx.add_argument("--user-dn", action="append", default=[], metavar="DN",
                     help="an LDAP DN known to be a user; repeatable")
    ctx.add_argument("--reply-window", type=positive(float), default=radius_exchange.DEFAULT_REPLY_WINDOW,
                     metavar="SECONDS", help="how long a RADIUS client waits for a reply, when the capture shows no "
                                             "resends to measure it from (default 5)")

    lim = p.add_argument_group("limits (a capture is untrusted input)")
    lim.add_argument("--max-size", type=positive(int), default=Limits().max_bytes // MiB, metavar="MIB",
                     help="refuse captures bigger than this (default 256)")
    lim.add_argument("--max-packets", type=positive(int), default=Limits().max_packets, metavar="N",
                     help="stop reading after N packets (default 1000000)")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the report as JSON, for other tools")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def read_secret(args, stdin):
    if args.secret:
        return secrets.from_prompt(stdin)
    if args.secret_file:
        return secrets.from_file(args.secret_file)
    if args.secret_env:
        return secrets.from_env(args.secret_env)
    return None


def build_options(args, stdin=None):
    return Options(
        radius_ports=radius.DEFAULT_PORTS.with_extra(args.radius_port),
        ldap_ports=ldap_exchange.DEFAULT_PORTS.with_extra(args.ldap_port),
        secret=read_secret(args, stdin),
        captured_on=args.captured_on,
        service_dns=tuple(args.service_dn),
        user_dns=tuple(args.user_dn),
        reply_window=args.reply_window,
    )


def load(args, stdin=None):
    limits = Limits(max_bytes=args.max_size * MiB, max_packets=args.max_packets)
    if args.capture == "-":
        stream = stdin if stdin is not None else sys.stdin.buffer
        return read_stream(stream, limits=limits)
    return read_capture(args.capture, limits)


def main(argv=None, stdin=None, stdout=None, stderr=None, terminal=None):
    """stdin: the capture when it is '-'. terminal: stands in for the controlling terminal --secret asks on."""
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    argv = sys.argv[1:] if argv is None else list(argv)
    args = build_parser().parse_args(argv)
    try:
        options = build_options(args, terminal)
        cap = load(args, stdin)
    except (CaptureError, secrets.SecretError) as exc:
        print(f"pcap-analyser: {exc}", file=stderr)
        return EXIT_ERROR
    report = analyse(cap, options)
    if args.json:
        stdout.write(render_json(report))
    else:
        stdout.write(render_text(report, colour=use_colour(stdout)))
    return report.exit_code
