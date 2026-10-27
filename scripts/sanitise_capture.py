#!/usr/bin/env python3
"""Make a raw lab capture safe to commit, and check that committed ones are.

    python scripts/sanitise_capture.py <label> <raw.pcap> [--lab-env PATH]   # writes samples/lab/<label>.pcap
    python scripts/sanitise_capture.py --check samples/lab [--lab-env PATH]   # exit 1 if anything is found

Rewriting a capture, packet by packet:

- IP addresses move to the documentation range (192.0.2.0/24) by role, and
  MAC addresses (Ethernet, the Linux cooked header's address, and RADIUS
  Calling-Station-Id and Called-Station-Id) to the documentation range
  00-00-5E-00-53-xx (RFC 7042), also by role; checksums are recomputed.
  Loopback stays loopback, except in the relay captures, where the two ends
  become client and directory.
- RADIUS moves onto fixed fake secrets, so nothing committed is keyed with
  the lab's real secret. Nothing needs that secret to do it: User-Password is
  hidden afresh with a fixed sample password, and Message-Authenticator and
  the Response Authenticator are computed anew, all with the sample secret
  (or, for the NAS in scenario 05, a second, wrong sample secret).
  Calling-Station-Id, Called-Station-Id, Framed-IP-Address, NAS-IP-Address,
  NAS-IPv6-Address and Framed-IPv6-Prefix are rewritten too.
- LDAP simple bind passwords all become one fixed value, so not even their
  length is left. The bind is re-encoded with its new lengths, and every later
  TCP sequence number in that direction (and acknowledgement in the other) is
  moved to match. identity-lab's public wrong value for scenario 04 is kept,
  as it is what makes that sample real.
- A TLS ClientHello's server name (SNI) is replaced with a neutral name of the
  same shape and length ("xxx.xxxx.example" style), so the handshake still
  parses.
- In TCP payloads (DNs, filters, matchedDN, diagnosticMessage), anything
  matching a personal pattern, a private address or a home path is masked at
  the same length.
- As a last line of defence, any value from the lab's .env found in a payload
  is overwritten.
- The output is always classic pcap, whatever the input: it has no section,
  interface or comment metadata to carry (pcapng's hardware, OS and
  application options, interface names and descriptions, comments, name
  resolution and decryption secrets blocks are all left behind).

Checking reads each committed capture independently of the rewriting: it
reassembles TCP to find every bind and every ClientHello, checks every MAC
address and any pcapng metadata, and with the lab's .env checks that no value
from it appears and that no RADIUS message verifies with the real secret.
Problems are reported by file and kind, never by value.
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

from pcap_analyser import ber, ldap, radius_auth, tcpstream, tls
from pcap_analyser.ber import BerError
from pcap_analyser.capture import CaptureError, frames, read_capture
from pcap_analyser.radius_exchange import analyse as radius_analyse

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "lab"

_spec = importlib.util.spec_from_file_location("sanitise", ROOT / "scripts" / "sanitise.py")
text_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(text_checks)

SAMPLE_SECRET = b"pcap-analyser-sample-secret"  # in samples/lab/sample.secret
SAMPLE_WRONG_SECRET = b"pcap-analyser-sample-wrong-secret"  # the NAS's, in scenario 05
PUBLIC_BIND_VALUES = {b"not-the-bind-password"}  # published in identity-lab's scenario 04
FIXED_BIND_PASSWORD = b"sanitised"  # every other bind password becomes this, whatever its length was
DOC_MAC = bytes.fromhex("00005e0053")  # RFC 7042: 00-00-5E-00-53-00 to -FF are for documentation
DEVICE_MAC, ACCESS_POINT_MAC = "00-00-5E-00-53-AA", "00-00-5E-00-53-AB"  # Calling- and Called-Station-Id
MAC_TEXT = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
TCP_OPT_SACK = 5
MOD = 1 << 32
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
        """A documentation-range MAC for an address, by role: its last byte is that of the (already
        rewritten) documentation address, 00 for loopback."""
        addr = ipaddress.ip_address(ip)
        last = 0 if addr.is_loopback or addr.version != 4 else int(ip.split(".")[-1])
        return DOC_MAC + bytes([last])


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
            v = DEVICE_MAC.encode()
        elif t == 30:
            v = f"{ACCESS_POINT_MAC}:sample-ssid".encode()
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


def _ber_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(identifier, content):
    return identifier + _ber_length(len(content)) + content


def _identifier(raw):
    if raw[0] & 0x1F == 0x1F:
        raise Unsafe("an LDAP element with a long-form tag; refusing to re-encode it")
    return raw[:1]


def _rebind(data, el):
    """The BindRequest message el (in data) with its password replaced by the fixed value, re-encoded."""
    parts = el.children()
    op = parts[1]
    fields = op.children()
    outer, inner = el.value, op.value
    ident = outer[parts[0].start:parts[0].end]
    controls = b"".join(outer[p.start:p.end] for p in parts[2:])
    version, name = inner[fields[0].start:fields[0].end], inner[fields[1].start:fields[1].end]
    auth = _tlv(_identifier(inner[fields[2].start:fields[2].end]), FIXED_BIND_PASSWORD)
    new_op = _tlv(_identifier(outer[op.start:op.end]), version + name + auth)
    return _tlv(_identifier(data[el.start:el.end]), ident + new_op + controls)


def mask_ldap(payload):
    """payload with every simple bind password replaced by the fixed value (the public 04 value kept).
    The result may be longer or shorter than payload."""
    out, pos, copied = [], 0, 0
    while pos < len(payload):
        try:
            el = ber.read(payload, pos)
            msg = ldap.decode(el, pos)
        except BerError:
            pos += 1
            continue
        if msg.op == ldap.BIND_REQUEST and msg.auth == "simple" and msg.password_length:
            end = el.end - _trailing(el)
            value = payload[end - msg.password_length:end]
            if value not in PUBLIC_BIND_VALUES and value != FIXED_BIND_PASSWORD:
                out += [payload[copied:el.start], _rebind(payload, el)]
                copied = el.end
        pos = el.end
    out.append(payload[copied:])
    return b"".join(out)


def neutral_name(name):
    """A host name of the same shape: letters and digits become x, dots and hyphens stay."""
    return bytes(c if c in b".-" else ord("x") for c in name)


def neutral_sni(payload):
    """payload with the server name in a TLS ClientHello at its start made neutral, at the same length."""
    if len(payload) < 9 or payload[0] != 22 or payload[1] != 3 or payload[5] != 1:
        return payload
    data = bytearray(payload)
    try:
        pos = 5 + 4 + 2 + 32
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression methods
        end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(end, len(data)):
            ext, n = struct.unpack_from("!HH", data, pos)
            if ext == 0:
                i, stop = pos + 6, min(pos + 4 + n, len(data))
                while i + 3 <= stop:
                    kind, length = data[i], int.from_bytes(data[i + 1:i + 3], "big")
                    if kind == 0 and i + 3 + length <= len(data):
                        data[i + 3:i + 3 + length] = neutral_name(bytes(data[i + 3:i + 3 + length]))
                    i += 3 + length
            pos += 4 + n
    except IndexError:
        pass
    return bytes(data)


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

def _mask_env(payload, secrets):
    for value in secrets.values():
        payload = payload.replace(value, b"*" * len(value))
    return payload


def _rebuild(ip, addresses, rekeyer, recipe, personal, secrets):
    """The IP packet rewritten: addresses, then the transport payload, with lengths and checksums redone.
    (LDAP bind passwords, which change lengths, were rewritten before this, with the TCP numbers.)"""
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
        t.data = _mask_env(rekeyer.rewrite(bytes(t.data), src, t.sport, dst, t.dport), secrets)
        t.ulen = 8 + len(t.data)
        t.sum = 0
    elif isinstance(t, dpkt.tcp.TCP) and t.data:
        t.data = _mask_env(mask_text(neutral_sni(bytes(t.data)), personal), secrets)
        t.sum = 0
    ip.sum = 0
    ip.len = len(bytes(ip.data)) + ip.hl * 4
    return bytes(ip)


def _parse(linktype, frame):
    """(link header to keep, dpkt IP) for a frame, or None for a frame that is not IPv4."""
    if linktype == LINKTYPE_SLL2:
        ip = dpkt.ip.IP(frame[20:]) if len(frame) > 20 and frame[20] >> 4 == 4 else None
        return (frame[:20], ip) if ip is not None else None
    eth = dpkt.ethernet.Ethernet(frame)
    return (None, eth.data) if isinstance(eth.data, dpkt.ip.IP) else None


def _before(changes, number):
    """The total length change from rewritten segments that start before this sequence number."""
    return sum(delta for start, delta in changes if 0 < (number - start) % MOD < MOD // 2)


def _rewrite_binds(packets, ldap_ports):
    """Replace bind passwords in every TCP segment to an LDAP port, then move sequence and acknowledgement
    numbers to match the new lengths. packets: [(ts, head, ip)], changed in place."""
    changes = {}  # (src, sport, dst, dport) -> [(sequence number of a rewritten segment, length change)]
    for _, _, ip in packets:
        t = ip.data
        if isinstance(t, dpkt.tcp.TCP) and t.data and t.dport in ldap_ports:
            old = bytes(t.data)
            t.data = mask_ldap(old)
            delta = len(t.data) - len(old)
            key = (ip.src, t.sport, ip.dst, t.dport)
            if delta and (t.seq, delta) not in changes.get(key, []):
                changes.setdefault(key, []).append((t.seq, delta))
    if not changes:
        return
    for _, _, ip in packets:
        t = ip.data
        if not isinstance(t, dpkt.tcp.TCP):
            continue
        mine, theirs = changes.get((ip.src, t.sport, ip.dst, t.dport), []), changes.get(
            (ip.dst, t.dport, ip.src, t.sport), [])
        if (mine or theirs) and any(o == TCP_OPT_SACK for o, _ in dpkt.tcp.parse_opts(t.opts)):
            raise Unsafe("SACK blocks on a connection whose lengths change; refusing to guess their numbers")
        new_seq = (t.seq + _before(mine, t.seq)) % MOD
        if t.flags & dpkt.tcp.TH_ACK:
            t.ack = (t.ack + _before(theirs, t.ack)) % MOD
        t.seq = new_seq


def sanitise(label, raw_path, out_dir=SAMPLES, lab_env=None, personal=None):
    """Write out_dir/<label>.pcap and its .meta.json from a raw capture (pcap or pcapng). Returns the path."""
    recipe = RECIPES[label]
    personal = text_checks.load_personal_patterns() if personal is None else personal
    addresses = Addresses(recipe)
    rekeyer = RadiusRekeyer(recipe, addresses) if recipe["kind"] == "radius" else None
    secrets = env_values(lab_env)
    try:
        records = list(frames(raw_path))
    except CaptureError as e:
        raise Unsafe(str(e)) from None
    linktypes = {lt for _, lt, _ in records}
    if len(linktypes) > 1:
        raise Unsafe(f"the capture mixes link types {sorted(linktypes)}; split it by interface first")
    linktype = linktypes.pop() if linktypes else LINKTYPE_ETHERNET
    if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_SLL2):
        raise Unsafe(f"link type {linktype} is not one this sanitiser rewrites")
    packets = []
    for ts, _, frame in records:
        parsed = _parse(linktype, frame)
        if parsed is not None:  # nothing but IPv4 is expected from the lab; anything else is left out
            packets.append((ts, *parsed))
    _rewrite_binds(packets, {389, 636, 1636, 3268, 3269})
    rewritten = []
    for ts, head, ip in packets:
        body = _rebuild(ip, addresses, rekeyer, recipe, personal, secrets)
        src = str(ipaddress.ip_address(body[12:16]))
        dst = str(ipaddress.ip_address(body[16:20]))
        if linktype == LINKTYPE_SLL2:
            head = bytearray(head)
            halen = head[11]
            head[12:20] = (Addresses.mac(src) + b"\x00\x00")[:8] if halen == 6 else b"\x00" * 8
            frame = bytes(head) + body
        else:
            frame = Addresses.mac(dst) + Addresses.mac(src) + b"\x08\x00" + body
        rewritten.append((ts, frame))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{label}.pcap"
    with open(out_path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=linktype)
        for ts, frame in rewritten:
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
    out = ["IP addresses moved to 192.0.2.0/24 and MAC addresses to 00-00-5E-00-53-xx, by role; checksums "
           "recomputed", "written as classic pcap, with no capture metadata"]
    if recipe["kind"] == "radius":
        out.append("RADIUS re-signed with sample secrets: User-Password hidden afresh with a sample password, "
                   "Message-Authenticator and Response Authenticator recomputed; station IDs rewritten")
    if recipe["kind"] == "ldap-relay":
        out.append("LDAP simple bind passwords replaced by a fixed value, re-encoded with TCP numbers moved to "
                   "match (scenario 04's public wrong value kept)")
    if recipe["kind"] == "ldaps":
        out.append("any TLS server name (SNI) replaced by a neutral name of the same length")
    return out


# --- checking ---------------------------------------------------------------------------------------

IDB_TIMING_OPTIONS = {9, 14}  # if_tsresol, if_tsoffset: how to read timestamps, nothing about the machine
EPB_OPTIONS = {2}  # epb_flags: the packet's direction
PCAPNG_BLOCK_KINDS = {4: "a pcapng name resolution block", 0x0A: "a pcapng decryption secrets block",
                      0x0BAD: "a pcapng custom block", 0x40000BAD: "a pcapng custom block"}


def pcapng_metadata(raw):
    """Kinds of metadata in a pcapng file: section options (hardware, OS, application), interface options
    other than timing (names, descriptions, addresses), comments, and blocks that carry names or keys."""
    if raw[:4] != b"\x0a\x0d\x0d\x0a":
        return []
    found, pos, endian = [], 0, "<"
    while pos + 12 <= len(raw):
        if raw[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            endian = "<" if raw[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        btype, length = struct.unpack_from(endian + "II", raw, pos)
        if length < 12 or pos + length > len(raw):
            found.append("a damaged pcapng block")
            break
        body = raw[pos + 8:pos + length - 4]
        if btype == 0x0A0D0D0A:
            options, allowed = body[16:], set()
            kind = "pcapng section metadata (hardware, OS, application or comment)"
        elif btype == 1:
            options, allowed = body[8:], IDB_TIMING_OPTIONS
            kind = "pcapng interface metadata (a name, description, address or comment)"
        elif btype == 6 and len(body) >= 20:
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            options, allowed = body[20 + ((caplen + 3) & ~3):], EPB_OPTIONS
            kind = "a pcapng packet comment or other packet option"
        else:
            options, allowed, kind = b"", set(), None
            if btype in PCAPNG_BLOCK_KINDS:
                found.append(PCAPNG_BLOCK_KINDS[btype])
        i = 0
        while i + 4 <= len(options):
            code, n = struct.unpack_from(endian + "HH", options, i)
            if code == 0:
                break
            if code not in allowed:
                found.append(kind)
                break
            i += 4 + ((n + 3) & ~3)
        pos += length
    return found


def _mac_ok(mac):
    return mac.startswith(DOC_MAC)


def _mac_text_ok(text):
    return bytes.fromhex(re.sub(rb"[-:]", b"", text).decode()).startswith(DOC_MAC)


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
    if any(not _mac_text_ok(m) for m in MAC_TEXT.findall(raw)):
        problems.append("a MAC address outside the documentation range, written as text")
    problems += pcapng_metadata(raw)
    for _, linktype, frame in frames(path):
        if linktype == LINKTYPE_ETHERNET and len(frame) >= 12 and not (_mac_ok(frame[:6]) and _mac_ok(frame[6:12])):
            problems.append("an Ethernet MAC address outside the documentation range")
            break
        if linktype == LINKTYPE_SLL2 and len(frame) >= 20 and frame[11] == 6 and not _mac_ok(frame[12:18]):
            problems.append("a link-layer address outside the documentation range")
            break
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
            checks = [c for m in e.attempts for c in radius_auth.check_request(m, real_secret)]
            if e.reply:
                checks += radius_auth.check_reply(e.reply, e.request, real_secret)
            if any(c.ok for c in checks):
                problems.append("a RADIUS message keyed with the lab's real secret")
                break
    tcp_ports = {p.dport for p in cap.packets if p.proto == "tcp"} | {p.sport for p in cap.packets if p.proto == "tcp"}
    for stream in tcpstream.streams(cap.packets, tcp_ports):
        for chunk in stream.to_server.chunks:
            for start, end in bind_password_spans(chunk.data):
                value = chunk.data[start:end]
                if value not in PUBLIC_BIND_VALUES and value != FIXED_BIND_PASSWORD:
                    problems.append("an LDAP bind password not replaced by the fixed value")
            hello = _client_hello_at(chunk)
            if hello is not None:
                name = tls.inspect(chunk.data[hello:], b"").server_name
                if name and neutral_name(name.encode()) != name.encode():
                    problems.append("a TLS server name (SNI) that is not neutral")
    return problems


def _client_hello_at(chunk):
    """Where TLS starts in a client's stream chunk (at its start, as for LDAPS, or after a StartTLS), or
    None. LDAP's own reader finds the second, so binary data is never mistaken for a TLS record."""
    if chunk.start == 0 and ldap.looks_like_tls(chunk.data[:3]):
        return 0
    parsed = ldap.parse_direction([chunk], starttls_seen=True)
    return None if parsed.tls_from is None else parsed.tls_from - chunk.start


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
