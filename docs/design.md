# Design

## What it is for

A support engineer handed "nobody can log in to the Wi-Fi" or "SSO says our
passwords are wrong" often gets a packet capture with the ticket, and no
quick way to read it. The answer is in RADIUS attributes and authenticators,
LDAP result codes and diagnostic messages, and what did or did not come back,
split between two systems owned by different teams. pcap-analyser reads the
capture and says, in plain English, what each side did and what is most
likely wrong.

## Principles

**Offline, and pure Python.** The tool reads the file it is given and nothing
else: no DNS lookups, no connections, no Wireshark or tshark. A reviewer can
run it from a clone in a minute, and a capture from a hostile network cannot
make it reach anywhere. The test suite enforces this: a fixture fails any
test that opens a socket or resolves a name.

**One finding, one statement; one cause per pair.** Each finding says one thing
the capture shows, with a status, so the whole picture is visible at once. A
likely cause groups the findings that one failure explains, for each client
and server pair, because each NAS has its own client entry and secret, and a
failure for one says nothing about another.

**Say how sure.** A cause is confirmed only when the capture settles it. When it
does not, the evidence each way is listed, including what looks the same on
the wire (an unknown client and a secret mismatch; a firewall and a stopped
server), and the cause says what would tell them apart.

**Never show a secret.** A RADIUS shared secret is taken from a prompt, a file
or an environment variable, never the command line; it is held in an object
that never prints it, and every check on it answers only matches, does not
match, or cannot tell. User-Password, Message-Authenticator and MS-CHAP values
are hidden. An LDAP simple bind's password is never kept, only its length.

**Encrypted means unknown.** LDAPS, StartTLS and a SASL security layer are
reported as such, with what the TLS handshake shows in clear (versions, the
server name, alerts sent before encryption), and no claim about the rest. In
TLS 1.3 a client rejecting the server's certificate sends its alert encrypted,
so a handshake that stops after the ServerHello is reported as consistent with
a trust problem, never as having none.

## Parsing untrusted input

A capture handed over in a ticket may be cut short, damaged or crafted, so:

- the pcap and pcapng formats are read by a small reader here rather than a
  general one: every block and record length is checked before it is used,
  the file size and packet count are capped, and a damaged file keeps
  everything before the damage, with a note;
- dpkt decodes IP, TCP, UDP and ICMP, but its results are checked against the
  headers' own length fields, IP fragments are refused rather than misread,
  and any exception it raises on damaged input becomes a skipped packet;
- RADIUS and LDAP's BER are read by strict decoders of their own, with lengths,
  nesting and message sizes capped; a message that cannot be read is
  reported with where it was, and the rest of the connection is still read;
- TCP is reassembled by sequence number, retransmissions and overlaps are
  resolved, and gaps are reported rather than guessed across.

Fuzz tests cut captures at every byte and mutate them, with a fixed seed, from
the file format through to both renderers.

## What it does not do

- Decrypt TLS, even when given keys (a pcapng with embedded TLS keys is noted,
  and the keys are ignored).
- Reassemble IP fragments. A RADIUS message large enough to be fragmented (EAP
  carrying certificates) is counted as missing.
- Read RADIUS over TLS (RadSec), Diameter, Kerberos, DNS, or LDAP over UDP
  (Active Directory's CLDAP domain controller locator).
- Contact any server, or check anything the capture does not contain.

## Lab captures

The captures in `samples/lab/` come from
[identity-lab](https://github.com/MarkHawk/identity-lab). Its directory speaks
LDAPS only, so the readable LDAP captures repeat Keycloak's binds through a
relay that records the plain side; the RADIUS captures and one encrypted LDAPS
capture are real lab traffic. Each is sanitised before it is committed:
addresses and MAC addresses move to documentation ranges, RADIUS is re-signed
with a fixed sample secret, bind passwords become one fixed value, any TLS
server name is made neutral, and the output is classic pcap with no capture
metadata. A test checks every committed capture for each of these, and, on the
machine the captures were taken on, for every value in the lab's own secrets.
`samples/lab/README.md` gives the details.

## Testing

The suite runs offline and fast. Synthetic captures are built byte by byte in
the tests (RADIUS signed with known secrets, LDAP conversations over TCP with
real sequence numbers, TLS records), and checked against outside references
where there are any: RFC 2865's worked example, and a pcapng file written by
dpkt's own writer read the same as pcap. The lab captures are checked to give
the answer their scenario calls for, and the README's examples are checked to
be the tool's real output.
