# Usage reference

Every option auth-capture-explainer accepts. The [README](../README.md) covers the
common cases; this page is the full list. `auth-capture-explainer --help` prints the
same options in short form.

```
auth-capture-explainer [options] <capture>
auth-capture-explainer demo [name] [--json] [--verbose]
```

## Input

| Option | What it does |
|---|---|
| `capture` | The `.pcap` or `.pcapng` file to read. `-` reads standard input, for example `tcpdump -w - ... \| auth-capture-explainer -`. |
| `--max-size MIB` | Refuse a capture bigger than this many MiB (default 256). Standard input is read up to the limit and refused beyond it. |
| `--max-packets N` | Stop reading after N packets (default 1000000); the report says it stopped early. |

pcap and pcapng are both read, including pcapng files with several interfaces
of different link types and clocks, as Wireshark writes when it captures on
more than one interface. The link types read are Ethernet (with VLAN tags),
Linux cooked captures (v1 and v2, as `tcpdump -i any` writes), BSD loopback
and raw IP. A file that is not a capture at all (a gzip, a zip, a text export)
is refused with a hint about what to do instead.

Ctrl-C while the capture is being read stops the reading, not the program:
what was read is analysed and the report says the capture stopped early. A
file that ends part-way through a packet is treated the same way.

## Ports

| Option | What it does |
|---|---|
| `--radius-port PORT` | Also read UDP `PORT` as RADIUS. 1812 and 1813, and the legacy 1645 and 1646, always are. Repeatable. |
| `--ldap-port PORT` | Also read TCP `PORT` as LDAP. 389, 636 (LDAPS) and Active Directory's Global Catalog ports 3268 and 3269 always are. Whether a connection is clear or TLS is told from its bytes, not its port. Repeatable. |

## The RADIUS shared secret

Give the secret to check every message against it: Message-Authenticator on
requests and replies, the Response Authenticator, the Request Authenticator of
accounting, CoA and Disconnect requests, and whether User-Password decodes to
text with the zero padding RFC 2865 adds. The report then says whether the
secret you gave matches the server's replies and the NAS's requests, separately
for each NAS.

| Option | What it does |
|---|---|
| `--secret` | Ask for the secret on the terminal, without echo. It takes no value, so a secret can never end up on a command line. It asks on the controlling terminal, so it works while the capture comes in on standard input; with no terminal at all it refuses. |
| `--secret-file FILE` | Read the secret from `FILE`. One trailing newline is removed; anything else, spaces included, is part of the secret. |
| `--secret-env NAME` | Read the secret from the environment variable `NAME`. |

The secret is never printed, logged or written into the JSON; the report says
only where it came from, and, if it starts or ends with whitespace, that it
does.

## What you know about the capture

| Option | What it does |
|---|---|
| `--captured-on server` or `client` | Where the capture was taken, when the capture itself does not record which way packets went (Linux cooked captures and pcapng packet flags do). A capture on the RADIUS server rules a firewall in between in or out. |
| `--service-dn DN` | An application's LDAP service account DN, so a failed bind as it is called a service account failure for certain. Repeatable. |
| `--user-dn DN` | An LDAP DN known to be a user. Repeatable. |
| `--reply-window SECONDS` | How long a RADIUS client waits for a reply before giving up, used only when the capture shows no resends to measure it from (default 5). A request sent within this of the capture's end is "no reply before the capture ended", not "no reply". |

Without `--service-dn`, whether a bind DN is a service account or a user is
judged from the capture: a bind followed by searches on the same connection is
an application's own account, and a DN that a search returned is a user being
checked. Failing both, the DN's wording is used and the report says it is only
a hint.

## Output

| Option | What it does |
|---|---|
| `--json` | Print the report as JSON instead of text. |
| `--verbose` | Show everything in the text report. Without it, the capturing host's own RADIUS health checks (Status-Server on its loopback address) are one line while they are all well; any failure among them shows them in full anyway. |
| `--version` | Print the version. |

## Exit status

| Status | Meaning |
|---|---|
| 0 | Nothing failed. |
| 1 | At least one finding is a FAIL. |
| 2 | The capture or the secret could not be read, or the command line was wrong. |
| 3 | The capture holds no RADIUS or LDAP to analyse. |
| 130 | Interrupted during the analysis. |

## The demo

`auth-capture-explainer demo` runs the bundled captures and gives each one line;
`auth-capture-explainer demo <name>` prints its full report, with `--json` and
`--verbose` as above. The captures are copies of the sanitised identity-lab
captures in [`samples/lab`](../samples/lab), and one synthetic Active
Directory capture, which the lab (an OpenLDAP directory) cannot produce.

| Name | What it shows | The command it runs, in the samples folder |
|---|---|---|
| `radius-ok` | RADIUS login accepted | `auth-capture-explainer radius-ok.pcap` |
| `radius-reject` | RADIUS wrong password, secret checked | `auth-capture-explainer radius-reject.pcap --secret-file sample.secret` |
| `radius-secret` | RADIUS shared secret mismatch | `auth-capture-explainer radius-secret.pcap` |
| `ldap-service` | LDAP service account password wrong | `auth-capture-explainer ldap-service.pcap` |
| `ldaps` | LDAPS, encrypted end to end | `auth-capture-explainer ldaps.pcap --ldap-port 1636` |
| `ad-locked` | AD service account locked out (synthetic) | `auth-capture-explainer ad-locked.pcap` |

## JSON

`--json` prints one object with these keys:

| Key | What it holds |
|---|---|
| `schema_version` | 1. It changes only if the shape changes in a way that breaks a reader. |
| `tool`, `version` | `auth-capture-explainer` and its version. |
| `capture` | The file's name (never its folder), format, link types, packet count, first and last packet times, and how many packets were skipped or ignored. |
| `options` | What was asked for. For the secret, only whether one was given and where from. |
| `seen` | One line on what the capture holds. |
| `findings` | Every finding: `code`, `status` (FAIL, WARN, PASS, INFO or SKIP), `protocol`, `title`, `summary`, `next_step`, `runbook` and `runbook_url`, and `details`, the facts behind it. Per-pair findings carry `details.pair`, `details.client` and `details.server`. |
| `likely_causes` | Every likely cause: `code`, `label`, `confirmed`, `client`, `server`, `summary`, `evidence`, `first_step`, `runbook`, `runbook_url` and `explains` (the finding codes it accounts for). |
| `conversations` | One row per client and server pair: requests, resends, answered, outcome, p50 and p95. |
| `servers` | Each server across its clients: requests, unanswered, and response-time percentiles. |
| `summary` | Counts by status, the verdict, and the exit status. |

### Codes

The `code` of every finding and likely cause is stable: another tool can act on
it. Codes are added over time; one is renamed or removed only with a new major
version and a note in the [CHANGELOG](../CHANGELOG.md). A finding's `status`,
and a likely cause's `confirmed`, say how serious or how certain each one is;
its code says what it is about.

Findings:

| Code | What it is about |
|---|---|
| `capture.note` | a remark about the file itself: cut short, damaged, interrupted, or carrying TLS keys |
| `capture.malformed` | packets that could not be decoded and were skipped |
| `capture.link_type` | packets with a link type this tool cannot read |
| `capture.fragments` | IP fragments that were not reassembled |
| `capture.nothing` | no RADIUS or LDAP traffic in the capture |
| `radius.unanswered` | requests that got no reply |
| `radius.capture_ended` | requests sent too close to the end of the capture to tell |
| `radius.capture_point` | where the capture was taken, and how that was told |
| `radius.answering` | the server answered this client |
| `radius.icmp` | ICMP errors about requests or replies |
| `radius.message_authenticator` | Message-Authenticator on requests: present, or absent |
| `radius.reply_message_authenticator` | Message-Authenticator on replies: present, or absent |
| `radius.message_authenticator_position` | Message-Authenticator present but not the first attribute |
| `radius.rejects` | Access-Rejects, with any Reply-Message |
| `radius.challenges` | Access-Challenges: a multi-step login in progress |
| `radius.response_time` | response times, Access-Rejects apart |
| `radius.reply_from_elsewhere` | replies from a different address or port than the request went to |
| `radius.reused_ids` | a request ID reused while an earlier request with it was pending |
| `radius.legacy_port` | the pre-standard ports 1645 or 1646 in use |
| `radius.secret` | the shared secret checked against both sides, or not checked |
| `radius.secret_shape` | the secret given starts or ends with whitespace |
| `radius.malformed` | packets on RADIUS ports that are not RADIUS |
| `radius.orphan_replies` | replies whose request is not in the capture |
| `ldap.bind_failed` | a rejected bind, with result code, diagnostic, Active Directory reason and role |
| `ldap.binds` | binds that succeeded |
| `ldap.unauthenticated_bind` | a simple bind with a DN and an empty password |
| `ldap.search_failed` | a search that failed |
| `ldap.search_limited` | searches that hit the size limit |
| `ldap.search_empty` | searches that found nothing |
| `ldap.searches` | searches that succeeded |
| `ldap.referrals` | searches answered with referrals |
| `ldap.operation_failed` | another operation that failed |
| `ldap.starttls_refused` | StartTLS refused |
| `ldap.unanswered` | requests with no response, and how the wait ended |
| `ldap.pending` | requests still waiting when the capture ended |
| `ldap.notice` | a Notice of Disconnection from the server |
| `ldap.tls` | connections using TLS, and what their handshakes show |
| `ldap.sasl_layer` | connections signed or sealed after a SASL bind |
| `ldap.unreadable` | connections that are neither LDAP nor the start of TLS |
| `ldap.refused` | connections reset before any data |
| `ldap.empty` | connections that carried no data |
| `ldap.damaged` | messages that could not be read, or gaps in the capture |
| `ldap.response_time` | response times |
| `ldap.orphan_responses` | responses whose request is not in the capture |
| `server.slow` | a server slow for all its clients |

Likely causes:

| Code | What it means |
|---|---|
| `radius-secret-mismatch` | the NAS and the server's client entry hold different shared secrets |
| `radius-secret-unknown` | the secret given matches neither side, or not the server |
| `radius-port-closed` | nothing listening on the RADIUS port (ICMP port unreachable) |
| `radius-firewall` | a firewall refuses RADIUS (ICMP administratively prohibited) |
| `radius-unreachable` | the server cannot be reached (ICMP host or network unreachable) |
| `radius-reply-wrong-address` | the server replies from an address the NAS did not send to |
| `radius-no-message-authenticator` | an old NAS sends no Message-Authenticator to a server that requires it |
| `radius-unanswered-secret-ok` | no reply, though the NAS's requests verify with the secret given |
| `radius-no-reply` | no reply at all, and no way to tell why from where the capture was taken |
| `radius-user-rejected` | the server rejected the user's login |
| `radius-slow` | the RADIUS server is slow to reply |
| `ldap-signing-required` | LDAP signing or channel binding enforcement refused a simple bind |
| `ldap-channel-binding` | LDAP channel binding rejected the bind |
| `ldap-tls-required` | the directory requires TLS for binds |
| `ldap-service-bind-failed` | the application's service account cannot bind |
| `ldap-user-bind-failed` | one user's own bind failed |
| `ldap-bind-failed` | a bind failed, of unknown role |
| `ldap-unauthenticated-bind` | an empty-password bind was accepted |
| `ldap-dn-not-found` | a bind DN or search base that does not exist |
| `ldap-insufficient-access` | the account lacks permission |
| `ldap-bind-needed` | a search without a bind, refused |
| `ldap-user-not-found` | the user lookup found nothing |
| `ldap-tls-failed` | the TLS handshake to the directory failed |
| `ldap-starttls-refused` | the directory refused StartTLS |
| `ldap-connection-refused` | the directory resets connections |
| `ldap-no-response` | the directory did not respond |
| `ldap-slow` | the directory is slow to respond |
