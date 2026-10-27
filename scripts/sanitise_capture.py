#!/usr/bin/env python3
"""Make a raw lab capture safe to commit, and check that committed ones are.

    python scripts/sanitise_capture.py <label> <raw.pcap> [--lab-env PATH]   # writes samples/lab/<label>.pcap
    python scripts/sanitise_capture.py --check samples/lab [--lab-env PATH]   # exit 1 if anything is found

Rewriting a capture, packet by packet:

- IP addresses move to the documentation range (192.0.2.0/24) by role, and
  link-layer addresses (Ethernet MACs, the Linux cooked header's address) to
  fixed made-up ones; checksums are recomputed. Loopback stays loopback,
  except in the relay captures, where the two ends become client and
  directory.
- RADIUS moves onto fixed fake secrets, so nothing committed is keyed with
  the lab's real secret. Nothing needs that secret to do it: User-Password is
  hidden afresh with a fixed sample password, and Message-Authenticator and
  the Response Authenticator are computed anew, all with the sample secret
  (or, for the NAS in scenario 05, a second, wrong sample secret).
  Calling-Station-Id, Called-Station-Id, Framed-IP-Address, NAS-IP-Address,
  NAS-IPv6-Address and Framed-IPv6-Prefix are rewritten too.
- LDAP simple bind passwords are overwritten byte for byte with "*", keeping
  the length so TCP sequence numbers stay valid. identity-lab's public wrong
  value for scenario 04 is kept, as it is what makes that sample real.
- In TCP payloads (DNs, filters, matchedDN, diagnosticMessage), anything
  matching a personal pattern, a private address or a home path is masked at
  the same length.
- As a last line of defence, any value from the lab's .env found anywhere in
  a frame is overwritten.

Checking reads each committed capture independently of the rewriting: it
reassembles TCP to find every bind, and with the lab's .env it checks that no
value from it appears and that no RADIUS message verifies with the real
secret. Problems are reported by file and kind, never by value.
"""

import argparse
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import pathlib
import re
import struct
import sys

import dpkt

from pcap_analyser import ber, ldap, radius_auth, tcpstream
from pcap_analyser.ber import BerError
from pcap_analyser.capture import read_capture
from pcap_analyser.radius_exchange import analyse as radius_analyse

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "lab"

_spec = importlib.util.spec_from_file_location("sanitise", ROOT / "scripts" / "sanitise.py")
text_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(text_checks)

SAMPLE_SECRET = b"pcap-analyser-sample-secret"  # in samples/lab/sample.secret
SAMPLE_WRONG_SECRET = b"pcap-analyser-sample-wrong-secret"  # the NAS's, in scenario 05
PUBLIC_BIND_VALUES = {b"not-the-bind-password"}  # published in identity-lab's scenario 04
MIN_ENV_VALUE = 6  # .env values shorter than this are ports, flags and names, not secrets

LINKTYPE_ETHERNET, LINKTYPE_SLL2 = 1, 276
RADIUS_PORTS = {1812, 1813, 1645, 1646}
DOC_NET = "192.0.2."

RECIPES = {
    "radius-accept": dict(kind="radius", nas_secret=SAMPLE_SECRET, password=b"sample-password",
                          made="real lab traffic", what="dave logs in through the lab NAS and is accepted"),
    "radius-reject": dict(kind="radius", nas_secret=SAMPLE_SECRET, password=b"wrong-password",
                          made="real lab traffic", what="dave logs in with a wrong password and is rejected"),
    "radius-05-broken": dict(kind="radius", nas_secret=SAMPLE_WRONG_SECRET, password=b"sample-password",
                             made="real lab traffic",
                             what="scenario 05 broken: the NAS's secret differs; dave's login goes unanswered"),
    "radius-05-fixed": dict(kind="radius", nas_secret=SAMPLE_SECRET, password=b"sample-password",
                            made="real lab traffic", what="scenario 05 fixed again: dave is accepted"),
    "ldap-good": dict(kind="ldap-relay", made="repeated through a relay",
                      what="Keycloak's login binds: the service account finds dave, then dave binds"),
    "ldap-04-broken": dict(kind="ldap-relay", made="repeated through a relay",
                           what="one good login, then the service account with scenario 04's wrong value"),
    "ldap-04-fixed": dict(kind="ldap-relay", made="repeated through a relay",
                          what="Keycloak's login binds after scenario 04 is fixed"),
    "ldaps-04-encrypted": dict(kind="ldaps", made="real lab traffic", args=["--ldap-port", "1636"],
                               what="Keycloak's own LDAPS bind while scenario 04 is broken, encrypted"),
}


class Unsafe(ValueError):
    """Something that must not be written could not be removed."""


# --- addresses ------------------------------------------------------------------------------

class Addresses:
    """Rewritten addresses, by role: what an address does in the capture, not what it was.

    RADIUS: the server (answering from a RADIUS port) becomes .2, NASes .10, .11 and on. LDAP: the directory
    becomes .20, clients .30 (the relay's loopback ends) or .40 and on. Anything else private gets the next
    free address from .50. Loopback stays loopback, except at the relay's two ends."""

    FIRST = {("radius", "server"): 2, ("radius", "client"): 10, ("ldap-relay", "server"): 20,
             ("ldap-relay", "client"): 30, ("ldaps", "server"): 20, ("ldaps", "client"): 40}

    def __init__(self, recipe):
        self.kind = recipe["kind"]
        self.map = {}
        self.next = {"server": self.FIRST.get((self.kind, "server"), 50),
                     "client": self.FIRST.get((self.kind, "client"), 50), None: 50}

    def ip(self, addr, role=None):
        """The rewritten address, given the address's role in this packet ("client", "server" or None)."""
        ip = ipaddress.ip_address(addr)
        relay_end = self.kind == "ldap-relay" and role and ip.is_loopback
        if not relay_end and (ip.is_loopback or not ip.is_private or str(ip).startswith(DOC_NET)):
            return addr
        key = (addr, role) if relay_end else addr
        if key not in self.map:
            self.map[key] = DOC_NET + str(self.next[role])
            self.next[role] += 1
        return self.map[key]

    @staticmethod
    def mac(ip):
        return bytes([2, 0, 0, 0, 0, int(ip.split(".")[-1]) if "." in ip else 1])


def _packed(addr):
    return ipaddress.ip_address(addr).packed


# --- RADIUS ---------------------------------------------------------------------------------

def _attrs(body):
    out, i = [], 0
    while i + 2 <= len(body):
        t, n = body[i], body[i + 1]
        if n < 2 or i + n > len(body):
            raise Unsafe("a RADIUS attribute does not fit; refusing to guess")
        out.append((t, body[i + 2:i + n]))
        i += n
    if i != len(body):
        raise Unsafe("a RADIUS message has trailing bytes")
    return out


def hide_password(password, authenticator, secret):
    padded = password + b"\x00" * (-len(password) % 16)
    out, previous = b"", authenticator
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i + 16], hashlib.md5(secret + previous).digest()))
        out += block
        previous = block
    return out


def _encode(code, ident, authenticator, attrs):
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + authenticator + body


def _with_message_authenticator(code, ident, auth_field, attrs, secret):
    """attrs with any Message-Authenticator value recomputed over the message (auth_field in its header)."""
    if not any(t == 80 for t, _ in attrs):
        return attrs
    zeroed = [(t, b"\x00" * 16 if t == 80 else v) for t, v in attrs]
    mac = hmac.new(secret, _encode(code, ident, auth_field, zeroed), hashlib.md5).digest()
    return [(t, mac if t == 80 else v) for t, v in zeroed]


def _rewrite_attrs(attrs, addresses):
    out = []
    for t, v in attrs:
        if t == 31:
            v = b"02-00-00-00-00-01"
        elif t == 30:
            v = b"02-00-00-00-00-02:sample-ssid"
        elif t in (4, 8) and len(v) == 4:
            v = _packed(addresses.ip(str(ipaddress.ip_address(v)), "client")) if t == 4 else _packed(DOC_NET + "100")
        elif t == 95 and len(v) == 16:
            v = _packed("2001:db8::1")
        elif t == 97 and len(v) >= 2:
            v = v[:2] + _packed("2001:db8::")[:len(v) - 2]
        out.append((t, v))
    return out


class RadiusRekeyer:
    """Rewrites RADIUS onto the sample secrets. Requests are remembered so their replies can be signed."""

    def __init__(self, recipe, addresses):
        self.recipe, self.addresses = recipe, addresses
        self.requests = {}  # (client ip, client port, id) -> (request authenticator, secret)

    def secret_for(self, client):
        return SAMPLE_SECRET if ipaddress.ip_address(client).is_loopback else self.recipe["nas_secret"]

    def rewrite(self, payload, src, sport, dst, dport):
        if len(payload) < 20:
            raise Unsafe("a RADIUS message too short to rewrite")
        code, ident, length = struct.unpack_from("!BBH", payload)
        auth = payload[4:20]
        attrs = _rewrite_attrs(_attrs(payload[20:length]), self.addresses)
        if code in (1, 4, 12, 40, 43):  # a request, from the client
            secret = self.secret_for(src)
            if code == 1:
                attrs = [(t, hide_password(self.recipe["password"], auth, secret) if t == 2 else v) for t, v in attrs]
            if code in (4, 40, 43):  # the authenticator is itself keyed: compute it after the MAC
                attrs = _with_message_authenticator(code, ident, b"\x00" * 16, attrs, secret)
                unsigned = _encode(code, ident, b"\x00" * 16, attrs)
                auth = hashlib.md5(unsigned + secret).digest()
            else:
                attrs = _with_message_authenticator(code, ident, auth, attrs, secret)
            self.requests[(src, sport, ident)] = (auth, secret)
            return _encode(code, ident, auth, attrs)
        request = self.requests.get((dst, dport, ident))
        if request is None:
            raise Unsafe("a RADIUS reply whose request is not in the capture cannot be re-signed")
        request_auth, secret = request
        attrs = _with_message_authenticator(code, ident, request_auth, attrs, secret)
        unsigned = _encode(code, ident, request_auth, attrs)
        return _encode(code, ident, hashlib.md5(unsigned + secret).digest(), attrs)


# --- LDAP -----------------------------------------------------------------------------------

def bind_password_spans(data):
    """(start, end) of every simple bind password in data, a run of LDAP messages (one segment, or one
    reassembled direction). Messages that do not decode are stepped over."""
    spans, pos = [], 0
    while pos < len(data):
        try:
            el = ber.read(data, pos)
        except BerError:
            pos += 1
            continue
        try:
            msg = ldap.decode(el, pos)
        except BerError:
            pos += 1
            continue
        if msg.op == ldap.BIND_REQUEST and msg.auth == "simple" and msg.password_length:
            spans.append((el.end - _trailing(el) - msg.password_length, el.end - _trailing(el)))
        pos = el.end
    return spans


def _trailing(el):
    """Bytes after the bind's authentication choice in its message: any controls."""
    parts = el.children()
    return sum(p.end - p.start for p in parts[2:])


def _mask(data, start, end):
    return data[:start] + b"*" * (end - start) + data[end:]


def mask_ldap(payload):
    for start, end in bind_password_spans(payload):
        if payload[start:end] not in PUBLIC_BIND_VALUES:
            payload = _mask(payload, start, end)
    return payload


def mask_text(payload, personal):
    """Same-length masking of personal patterns, private addresses and home paths in a payload."""
    text = payload.decode("latin-1")
    for pattern in (*personal, text_checks.RFC1918, text_checks.HOME_DIR):
        text = pattern.sub(lambda m: "x" * len(m.group(0)), text)
    return text.encode("latin-1")


# --- the .env --------------------------------------------------------------------------------

def env_values(path):
    """Secret-looking values from the lab's .env: long enough, not obviously a port, flag or host name."""
    if path is None or not pathlib.Path(path).is_file():
        return {}
    values = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        name, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if len(value) >= MIN_ENV_VALUE and not value.isdigit() and name.strip() != "LAB_HOST":
            values[name.strip()] = value.encode()
    return values


# --- whole frames --------------------------------------------------------------------------------

def _rebuild(ip, addresses, rekeyer, recipe, personal, ldap_ports):
    """The IP packet rewritten: addresses, then the transport payload, with lengths and checksums redone."""
    src, dst = str(ipaddress.ip_address(ip.src)), str(ipaddress.ip_address(ip.dst))
    t = ip.data
    roles = (None, None)
    if isinstance(t, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        server_ports = {"radius": RADIUS_PORTS, "ldap-relay": {389}, "ldaps": {1636}}[recipe["kind"]]
        if t.sport in server_ports:
            roles = ("server", "client")
        elif t.dport in server_ports:
            roles = ("client", "server")
    ip.src, ip.dst = _packed(addresses.ip(src, roles[0])), _packed(addresses.ip(dst, roles[1]))
    if isinstance(t, dpkt.udp.UDP) and (t.sport in RADIUS_PORTS or t.dport in RADIUS_PORTS) and recipe["kind"] == "radius":
        t.data = rekeyer.rewrite(bytes(t.data), src, t.sport, dst, t.dport)
        t.ulen = 8 + len(t.data)
        t.sum = 0
    elif isinstance(t, dpkt.tcp.TCP) and t.data:
        payload = bytes(t.data)
        if t.dport in ldap_ports:
            payload = mask_ldap(payload)
        payload = mask_text(payload, personal)
        t.data = payload
        t.sum = 0
    ip.sum = 0
    ip.len = len(bytes(ip.data)) + ip.hl * 4
    return bytes(ip)


def sanitise(label, raw_path, out_dir=SAMPLES, lab_env=None, personal=None):
    """Write out_dir/<label>.pcap and its .meta.json from a raw capture. Returns the output path."""
    recipe = RECIPES[label]
    personal = text_checks.load_personal_patterns() if personal is None else personal
    addresses = Addresses(recipe)
    rekeyer = RadiusRekeyer(recipe, addresses) if recipe["kind"] == "radius" else None
    secrets = env_values(lab_env)
    ldap_ports = {389, 1636}
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{label}.pcap"
    with open(raw_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        linktype = reader.datalink()
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_SLL2):
            raise Unsafe(f"link type {linktype} is not one this sanitiser rewrites")
        frames = []
        for ts, frame in reader:
            if linktype == LINKTYPE_SLL2:
                head, ip = bytearray(frame[:20]), dpkt.ip.IP(frame[20:])
                head[12:20] = b"\x02\x00\x00\x00\x00\x00\x00\x00"  # the link-layer address
                frame = bytes(head) + _rebuild(ip, addresses, rekeyer, recipe, personal, ldap_ports)
            else:
                eth = dpkt.ethernet.Ethernet(frame)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue  # nothing but IPv4 is expected from the lab; anything else is left out
                body = _rebuild(eth.data, addresses, rekeyer, recipe, personal, ldap_ports)
                src, dst = str(ipaddress.ip_address(body[12:16])), str(ipaddress.ip_address(body[16:20]))
                frame = Addresses.mac(dst) + Addresses.mac(src) + b"\x08\x00" + body
            for value in secrets.values():
                frame = frame.replace(value, b"*" * len(value))
            frames.append((ts, frame))
    with open(out_path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=linktype)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)
    meta = {"label": label, "made": recipe["made"], "what": recipe["what"], "args": recipe.get("args", []),
            "rewritten": _rewritten(recipe)}
    if recipe["kind"] == "radius":
        meta["secret"] = ("sample.secret holds the server's secret; the NAS used another"
                          if recipe["nas_secret"] != SAMPLE_SECRET else "sample.secret holds the secret both sides use")
    (out_dir / f"{label}.pcap.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    problems = check_file(out_path, lab_env, personal)
    if problems:
        out_path.unlink()
        raise Unsafe(f"{out_path.name} still has: {', '.join(sorted(set(problems)))}; nothing was written")
    return out_path


def _rewritten(recipe):
    out = ["IP and link-layer addresses moved to documentation values, checksums recomputed"]
    if recipe["kind"] == "radius":
        out.append("RADIUS re-signed with sample secrets: User-Password hidden afresh with a sample password, "
                   "Message-Authenticator and Response Authenticator recomputed")
    if recipe["kind"].startswith("ldap"):
        out.append("LDAP simple bind passwords overwritten with '*' (scenario 04's public wrong value kept)")
    return out


# --- checking ---------------------------------------------------------------------------------------

def check_file(path, lab_env=None, personal=None):
    """Kinds of problem found in one capture; never the values."""
    personal = text_checks.load_personal_patterns() if personal is None else personal
    problems = []
    raw = pathlib.Path(path).read_bytes()
    secrets = env_values(lab_env)
    if any(v in raw for v in secrets.values()):
        problems.append("a value from the lab's .env")
    text = raw.decode("latin-1")
    problems += [k for k in text_checks.find_problems(text, personal) if k != "private IPv4 address"]
    if text_checks.RFC1918.search(text):
        problems.append("a private address written as text")
    cap = read_capture(path)
    for p in cap.packets:
        if any(ipaddress.ip_address(a).is_private and not ipaddress.ip_address(a).is_loopback
               and not a.startswith(DOC_NET) for a in (p.src, p.dst)):
            problems.append("a private address in an IP header")
            break
    real_secret = secrets.get("RADIUS_SECRET")
    if real_secret:
        result = radius_analyse(cap.packets)
        for e in result.exchanges:
            messages = [*e.attempts, *([e.reply] if e.reply else [])]
            checks = [c for m in e.attempts for c in radius_auth.check_request(m, real_secret)]
            if e.reply:
                checks += radius_auth.check_reply(e.reply, e.request, real_secret)
            if any(c.ok for c in checks) and messages:
                problems.append("a RADIUS message keyed with the lab's real secret")
                break
    for stream in tcpstream.streams(cap.packets, {389, 636, 1636, 3268, 3269}):
        for chunk in stream.to_server.chunks:
            for start, end in bind_password_spans(chunk.data):
                value = chunk.data[start:end]
                if value not in PUBLIC_BIND_VALUES and set(value) != {ord("*")}:
                    problems.append("a clear-text LDAP bind password")
    return problems


def check_paths(paths, lab_env=None):
    problems = []
    for root in paths:
        root = pathlib.Path(root)
        files = [root] if root.is_file() else sorted(root.rglob("*.pcap")) + sorted(root.rglob("*.pcapng"))
        for f in files:
            problems += [(f.name, kind) for kind in sorted(set(check_file(f, lab_env)))]
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description="Sanitise a raw lab capture, or check committed ones.")
    p.add_argument("label", nargs="?", choices=sorted(RECIPES))
    p.add_argument("raw", nargs="?", help="the raw capture to sanitise")
    p.add_argument("--check", nargs="+", metavar="PATH", help="check captures instead of writing one")
    p.add_argument("--lab-env", metavar="PATH", help="identity-lab's .env, to mask and check for its values")
    args = p.parse_args(argv)
    if args.check:
        problems = check_paths(args.check, args.lab_env)
        for name, kind in problems:
            print(f"sanitise_capture: {name}: contains {kind}", file=sys.stderr)
        if problems:
            return 1
        print(f"sanitise_capture: clean ({', '.join(args.check)})")
        return 0
    if not args.label or not args.raw:
        p.error("give a label and a raw capture, or --check")
    try:
        out = sanitise(args.label, args.raw, lab_env=args.lab_env)
    except (Unsafe, dpkt.UnpackError, ValueError) as e:
        print(f"sanitise_capture: {args.label}: {e}", file=sys.stderr)
        return 1
    print(f"sanitise_capture: wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
