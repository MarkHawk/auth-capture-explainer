#!/usr/bin/env python3
"""Build the captures bundled with the package for `pcap-analyser demo`.

    python scripts/build_demo_samples.py

Most are copies of the sanitised lab captures in samples/lab. One is
synthetic, because identity-lab's directory is OpenLDAP and cannot produce
it: an Active Directory service account that is locked out, with AD's
"data 775" in the bind's diagnosticMessage. It is built here byte by byte,
with documentation addresses, documentation MAC addresses and the same
fixed bind password as the lab captures, and its .meta.json says it is
synthetic. Every capture written is run through the capture checker.
"""

import importlib.util
import ipaddress
import json
import pathlib
import shutil
import sys

import dpkt

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = ROOT / "samples" / "lab"
OUT = ROOT / "src" / "pcap_analyser" / "demo_samples"

_spec = importlib.util.spec_from_file_location("sanitise_capture", ROOT / "scripts" / "sanitise_capture.py")
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

# name: (lab capture, one-line description, arguments; {dir} is the demo samples folder)
FROM_LAB = {
    "radius-ok": ("radius-accept", "RADIUS login accepted", []),
    "radius-reject": ("radius-reject", "RADIUS wrong password, secret checked", ["--secret-file", "{dir}/sample.secret"]),
    "radius-secret": ("radius-05-broken", "RADIUS shared secret mismatch", []),
    "ldap-service": ("ldap-04-broken", "LDAP service account password wrong", []),
    "ldaps": ("ldaps-04-encrypted", "LDAPS, encrypted end to end", ["--ldap-port", "1636"]),
}
SYNTHETIC = ("ad-locked", "AD service account locked out (synthetic)", [])

APP, DC = "192.0.2.30", "192.0.2.20"
SVC_DN = "CN=svc-portal,OU=Service Accounts,DC=corp,DC=example"
DIAGNOSTIC = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563"


# --- a small BER encoder, for the one synthetic capture -------------------------------------------

def _length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(identifier, content):
    return bytes([identifier]) + _length(len(content)) + content


def _int(n, identifier=0x02):
    return _tlv(identifier, n.to_bytes((n.bit_length() // 8) + 1, "big", signed=True))


def _str(value, identifier=0x04):
    return _tlv(identifier, value.encode() if isinstance(value, str) else value)


def _message(ident, op):
    return _tlv(0x30, _int(ident) + op)


def bind_request(ident, dn, password):
    return _message(ident, _tlv(0x60, _int(3) + _str(dn) + _str(password, 0x80)))


def bind_response(ident, code, diagnostic=""):
    return _message(ident, _tlv(0x61, _int(code, 0x0A) + _str("") + _str(diagnostic)))


def unbind(ident):
    return _message(ident, _tlv(0x42, b""))


# --- packets ---------------------------------------------------------------------------------------

class Connection:
    """One TCP connection from the application to the domain controller, written as Ethernet frames."""

    def __init__(self, cport, start):
        self.frames, self.cport, self.ts = [], cport, start
        self.seq = {True: 7000 + cport, False: 90000 + cport}

    def _send(self, from_app, payload=b"", flags=dpkt.tcp.TH_ACK, gap=0.0005):
        src, dst = (APP, DC) if from_app else (DC, APP)
        tcp = dpkt.tcp.TCP(sport=self.cport if from_app else 389, dport=389 if from_app else self.cport,
                           seq=self.seq[from_app], ack=self.seq[not from_app], flags=flags, win=65535, data=payload)
        ip = dpkt.ip.IP(src=ipaddress.ip_address(src).packed, dst=ipaddress.ip_address(dst).packed, p=6, ttl=128,
                        data=tcp)
        ip.len = len(ip)
        mac = sc.Addresses.mac
        frame = mac(dst) + mac(src) + b"\x08\x00" + bytes(dpkt.ip.IP(bytes(ip)))
        self.ts += gap
        self.frames.append((self.ts, frame))
        self.seq[from_app] += len(payload) + (1 if flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN) else 0)

    def open(self):
        self._send(True, flags=dpkt.tcp.TH_SYN)
        self._send(False, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        self._send(True)
        return self

    def say(self, from_app, payload, gap=0.004):
        self._send(from_app, payload, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, gap)

    def close(self):
        self._send(True, flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
        self._send(False, flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)


def ad_locked():
    """The portal's service account, locked out after the portal kept trying an old password: three logins
    in a minute, each refused with 49 and AD's data 775."""
    frames = []
    for i, start in enumerate((1_800_000_000.0, 1_800_000_020.0, 1_800_000_041.0)):
        c = Connection(51000 + i, start).open()
        c.say(True, bind_request(1, SVC_DN, sc.FIXED_BIND_PASSWORD))
        c.say(False, bind_response(1, 49, DIAGNOSTIC))
        c.say(True, unbind(2))
        c.close()
        frames += c.frames
    return frames


def write_pcap(path, frames):
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=1)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    samples = []
    for name, (lab, title, args) in FROM_LAB.items():
        shutil.copyfile(LAB / f"{lab}.pcap", OUT / f"{name}.pcap")
        meta = json.loads((LAB / f"{lab}.pcap.meta.json").read_text())
        meta.update(label=name, copied_from=f"samples/lab/{lab}.pcap")
        (OUT / f"{name}.pcap.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        samples.append({"name": name, "file": f"{name}.pcap", "title": title, "args": args})
    name, title, args = SYNTHETIC
    write_pcap(OUT / f"{name}.pcap", ad_locked())
    (OUT / f"{name}.pcap.meta.json").write_text(json.dumps({
        "label": name, "made": "synthetic", "args": args,
        "what": "an Active Directory service account locked out (data 775); built by scripts/build_demo_samples.py, "
                "as identity-lab's OpenLDAP cannot produce Active Directory's reason codes",
        "rewritten": ["nothing: built with documentation addresses and MACs and the fixed bind password"],
    }, indent=2) + "\n")
    samples.append({"name": name, "file": f"{name}.pcap", "title": title, "args": args})
    shutil.copyfile(LAB / "sample.secret", OUT / "sample.secret")
    (OUT / "demo.json").write_text(json.dumps({"samples": samples}, indent=2) + "\n")
    problems = sc.check_paths([OUT])
    for file, kind in problems:
        print(f"build_demo_samples: {file}: {kind}", file=sys.stderr)
    print(f"build_demo_samples: wrote {len(samples)} samples to {OUT.relative_to(ROOT)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
