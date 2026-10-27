# pcap-analyser

**pcap-analyser reads a packet capture and explains, in plain English, why
RADIUS or LDAP logins are failing.** Given a `.pcap` or `.pcapng` from
Wireshark or tcpdump, it pairs every request with its reply, says what each
side did, and names the likely cause with the evidence for and against it: a
shared secret that differs between a NAS and its RADIUS server, a directory
service account whose password has changed, a user locked out on Active
Directory, LDAP signing enforcement, a TLS handshake that stops short. It is
pure Python, so there is nothing else to install (no Wireshark or tshark), and
it runs fully offline: it reads the file and nothing else.

## Try it in 1 minute

From a clone, with Python 3.12 or newer:

```
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Then see what it makes of six bundled captures:

```
pcap-analyser demo
```

```
pcap-analyser demo: 6 bundled captures, analysed offline

  radius-ok      RADIUS login accepted                      PASS  no problems found
  radius-reject  RADIUS wrong password, secret checked      FAIL  login rejected by the server
  radius-secret  RADIUS shared secret mismatch              FAIL  shared secret mismatch, most likely
  ldap-service   LDAP service account password wrong        FAIL  the service account cannot bind
  ldaps          LDAPS, encrypted end to end                INFO  encrypted: no claim about what is inside
  ad-locked      AD service account locked out (synthetic)  FAIL  the service account cannot bind (likely)

Full report for one capture:  pcap-analyser demo <name>   e.g. pcap-analyser demo radius-secret
Try your own capture:         pcap-analyser <file.pcap>
```

### One full report

```
pcap-analyser demo radius-secret
```

```
$ pcap-analyser radius-secret.pcap
pcap-analyser 0.1.0
Capture:  radius-secret.pcap (pcap, Linux cooked v2, 11 packets over 15.2 s, from 2026-10-27 14:59:06 UTC)
Seen:     RADIUS 5 requests from 2 clients to 2 servers; LDAP none

== Findings ==
  FAIL  Requests unanswered    192.0.2.10 (NAS-Identifier "nas") sent an Access-Request for "dave"
                               to 192.0.2.2:1812, then resent it twice over 4.0 s (ID 71, same
                               authenticator). None of the 3 attempts got a reply. No ICMP error
                               came back.
  INFO  Capture point          The requests are marked as arriving at this host, and none was passed
                               on, so the capture was taken on the server: they reached it, and a
                               firewall in between is ruled out. This host also answers RADIUS on
                               its loopback address.
  PASS  Message-Authenticator  Present on every Access-Request and Status-Server from 192.0.2.10
                               (NAS-Identifier "nas") (value hidden).
  INFO  Health checks          The server answered 4 of 4 health checks on its loopback address
                               (Status-Server, p95 under 1 ms). These are the capturing host
                               checking itself; --verbose shows them in full.
  SKIP  Shared secret          Not checked. Add --secret (prompts), --secret-file or --secret-env to
                               check the shared secret against these packets.

== Likely cause ==
  For 192.0.2.10 (NAS-Identifier "nas") to 192.0.2.2:1812: shared secret mismatch, most likely
  The server receives the requests from 192.0.2.10 and stays silent, while it answers others, which
  is how a RADIUS server treats requests it cannot authenticate: the NAS's shared secret most likely
  differs from the server's client entry for it. An unknown client looks the same on the wire; the
  server's log tells them apart.
  How sure:  likely: the evidence points to it, but does not settle it
  Evidence:  For a secret mismatch: the request was resent twice and never answered; no ICMP error
             came back; this host answers RADIUS on its loopback address meanwhile.
  Evidence:  Against a firewall: the requests were seen arriving at the server.
  Evidence:  Looks the same on the wire: an unknown client (the NAS's address missing from the
             server's client list); the server's log tells them apart.
  First:     Look in the server's log for "Shared secret is incorrect" or "unknown client" for
             192.0.2.10, then set the secret again on both sides from one source. To confirm from
             this capture, run it again with --secret (prompts), --secret-file or --secret-env and
             the server's secret.
  Runbook:   identity-lab 05-radius-shared-secret-mismatch
             https://github.com/MarkHawk/identity-lab/blob/main/runbooks/05-radius-shared-secret-mismatch.md
  Explains:  Requests unanswered, Capture point

== Conversations ==
  Proto   Client      Server          Requests  Resent  Answered  Outcome              p50    p95
  RADIUS  127.0.0.1   127.0.0.1:1812         4       0         4  Status-Server OK x4  <1 ms  <1 ms
  RADIUS  192.0.2.10  192.0.2.2:1812         1       2         0  no reply             -      -

Verdict: 1 problem to fix (1 FAIL, 0 WARN, 5 PASS, 1 INFO, 1 SKIP)
```

This is identity-lab's scenario 05, captured on the RADIUS server: the NAS
resends a login three times and the server, which answers its own health
checks throughout, never replies. Run it again with
`pcap-analyser demo radius-reject` to see a reject that the shared secret
proves genuine.

## Reading your own capture

```
# the capture, as a file
pcap-analyser auth.pcapng

# with the RADIUS shared secret, to check it against both sides (it asks; the secret never goes on the
# command line, and is never shown)
pcap-analyser auth.pcap --secret
pcap-analyser auth.pcap --secret-file radius.secret

# straight from tcpdump, until Ctrl-C (what arrived is then analysed)
sudo tcpdump -i any -w - udp port 1812 or udp port 1813 | pcap-analyser -

# telling it what the capture cannot: whose bind DN it is, and where the capture was taken
pcap-analyser ldap.pcap --service-dn "cn=portal,ou=services,dc=example,dc=com"
pcap-analyser radius.pcap --captured-on server

# RADIUS or LDAP on other ports, and JSON for another tool
pcap-analyser odd.pcap --radius-port 11812 --ldap-port 10389 --json
```

RADIUS is read on UDP 1812 and 1813 and the legacy 1645 and 1646; LDAP on TCP
389, 636 and Active Directory's Global Catalog ports 3268 and 3269. Exit status
is 0 when nothing failed, 1 when something did, 2 when the capture or the
secret could not be read, and 3 when the capture holds no RADIUS or LDAP at
all. Every option, and the JSON format with its stable codes, is in
[`docs/usage.md`](docs/usage.md).

## Likely causes

Findings say what the capture shows; for each client and server pair whose
findings match a known failure, a **Likely cause** section names it, says
whether the capture confirms it or only points to it, lists the evidence each
way, and says what to do first. It recognises:

RADIUS
- **Shared secret mismatch**, confirmed when you give the secret (one side's
  messages verify, the other's do not), and otherwise inferred from a NAS
  resending into silence while the server answers others (identity-lab
  runbook 05).
- **A legacy server with the wrong secret**, which rejects every password, so
  it looks like users typing them wrong (runbook 05).
- **No Message-Authenticator**: an old NAS whose requests a server hardened
  against BlastRADIUS drops without a word.
- **Nothing listening, a firewall, or no route**, from ICMP errors.
- **Replies from the wrong address**, which a NAS discards.
- **No reply, and no way to tell why** from where the capture was taken.
- **The user's login rejected**, genuine when the reject verifies.
- **A slow server.**

LDAP
- **The application's service account cannot bind**, so every directory login
  fails (runbook 04), told apart from **one user's own bind failing**.
- **Active Directory's reasons**: wrong password, no such user, password
  expired or must change, account disabled, expired or locked out.
- **LDAP signing or channel binding enforcement**, and **TLS required**.
- **An empty-password bind accepted** as an unauthenticated bind.
- **A DN that does not exist**, **missing permission**, **a search without a
  bind**, **the user not found**.
- **A TLS handshake that failed or stopped short**, never read as "no trust
  problem", **StartTLS refused**, **connections refused**, **no response**, and
  **a slow directory**.

Each is described, with what it is based on, in
[`docs/causes.md`](docs/causes.md).

## Taking a good capture

**RADIUS: on the server, if you can.** A capture on the RADIUS server shows
whether the requests arrive, which rules a firewall in or out:

```
sudo tcpdump -i any -w radius.pcap 'udp port 1812 or udp port 1813 or udp port 1645 or udp port 1646 or icmp'
```

`-i any` on Linux also records which way each packet went, which the tool uses
to say where the capture was taken. Start it before the login, try the login,
and stop it ten seconds after it fails, so the NAS's resends are in. If you
can only capture on the NAS (most switches, wireless controllers and VPN
gateways can export a capture), say so with `--captured-on client`. Capture
whole packets (tcpdump's default): a short snapshot length cuts off the
attributes.

**LDAP: on the application's host, towards the directory:**

```
sudo tcpdump -i any -w ldap.pcap 'tcp port 389 or tcp port 636 or tcp port 3268 or tcp port 3269'
```

LDAPS (636) and StartTLS are encrypted, and so is Active Directory's default
SASL signing and sealing: the tool says so, reads what the TLS handshake shows
in clear, and makes no claim about the rest. To see the LDAP itself, capture
where it is in clear (between a TLS-terminating load balancer and the
directory), or have the application log its LDAP result codes.

**Treat captures as sensitive.** A simple bind carries the password in clear,
and a capture holds user names and addresses. Do not attach one to a ticket as
it is.

## Design decisions

- **Pure Python, offline.** A support engineer, or someone reviewing this
  repository, should not need Wireshark, tshark or a network connection. The
  test suite fails any test that opens a socket or looks up a name.
- **Its own readers where it matters.** dpkt reads IP, TCP, UDP and ICMP. The
  pcap and pcapng file formats, RADIUS and LDAP's BER are read by small, strict
  readers here, because a capture is untrusted input: every length is checked
  before use, sizes and nesting are capped, and a damaged packet is reported
  and skipped, never fatal. Fuzz tests cut and mutate captures to keep it so.
- **Say how sure it is.** A cause is "confirmed" only when the capture settles
  it, and the evidence against is listed alongside the evidence for.
- **Never show a secret.** The shared secret is checked, never printed or
  logged; passwords are hidden; only their length is ever kept.

What it deliberately does not do: decrypt TLS (even given keys), reassemble IP
fragments, or read RADIUS over TLS (RadSec), Diameter, Kerberos or LDAP over
UDP. [`docs/design.md`](docs/design.md) says more.

## Lab captures

The captures in [`samples/lab/`](samples/lab) come from a running
[identity-lab](https://github.com/MarkHawk/identity-lab), a self-contained lab
that breaks identity systems on purpose, with each scenario broken and fixed;
[`samples/lab/README.md`](samples/lab/README.md) says exactly how each was
made and what sanitising changed. The likely causes link the lab's runbooks:

- [04: LDAP bind failure](https://github.com/MarkHawk/identity-lab/blob/main/runbooks/04-ldap-bind-failure.md)
- [05: RADIUS shared secret mismatch](https://github.com/MarkHawk/identity-lab/blob/main/runbooks/05-radius-shared-secret-mismatch.md)

## Related tools

- [token-inspector](https://github.com/MarkHawk/token-inspector) does the same
  for single sign-on: it decodes a SAML response or a JWT and explains why a
  login is failing.
- [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe) explains
  why an integration keeps getting HTTP 429.

## Documentation

- [`docs/usage.md`](docs/usage.md) every option, exit status, the demo
  captures, and the JSON format with its codes.
- [`docs/causes.md`](docs/causes.md) every likely cause, and what it rests on.
- [`docs/design.md`](docs/design.md) why the tool is built the way it is, and
  what it does not do.

## Development

```
python3 -m venv venv
venv/bin/pip install -r requirements-dev.txt
venv/bin/pip install -e . --no-deps
venv/bin/pytest
```

The test suite is offline: a fixture fails any test that opens a socket.

## A note on how this was built

pcap-analyser was written with AI-assisted tooling (Claude Code). The design
decisions, the checks and this documentation were reviewed by a person.

## Licence

MIT. See [LICENSE](LICENSE).
