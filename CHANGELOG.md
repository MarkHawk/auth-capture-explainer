# Changelog

## 0.1.0 (2026-10-27)

First release.

### Added

- Reads `.pcap` and `.pcapng` files (several interfaces, mixed link types and
  clocks), or standard input, with caps on size and packet count; damaged or
  cut-short captures keep everything before the damage.
- RADIUS on 1812, 1813 and the legacy 1645 and 1646, and any port given:
  requests paired with replies, retransmissions, retries under a new ID,
  duplicate and out-of-place replies, ICMP errors, response times (rejects
  apart), and where the capture was taken.
- The RADIUS shared secret, given by prompt, file or environment variable and
  never shown: Message-Authenticator, Response and Request Authenticators, and
  User-Password checked against it, for each NAS separately.
- LDAP on 389, 636, 3268 and 3269, and any port given: TCP reassembled, binds,
  searches and other operations paired with their results, result codes by
  name, Active Directory's reason codes, service account or user, StartTLS,
  LDAPS and SASL security layers reported as encrypted with what the TLS
  handshake shows in clear.
- Likely causes, per client and server pair, for RADIUS (secret mismatch,
  old NAS without Message-Authenticator, ICMP, wrong reply address, rejects,
  slow server) and LDAP (service account or user bind failure, signing and
  channel binding enforcement, TLS required, unauthenticated binds, missing
  DNs and permissions, TLS handshake failures, slow directory), each saying
  how sure it is and the evidence each way, linking identity-lab runbooks 04
  and 05.
- Text report and `--json` with stable codes for every finding and cause.
  Exit status 0, 1, 2, 3 (nothing to analyse) or 130.
- `auth-capture-explainer demo` on six bundled captures, five from identity-lab and one
  synthetic Active Directory capture.
- Eight sanitised identity-lab captures in `samples/lab`, with a capture
  script, a sanitiser and a test that checks every committed capture.
