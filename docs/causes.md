# Likely causes

Findings say what a capture shows, one statement each. A likely cause names
the failure behind a set of findings, for patterns the tool knows. This page
lists every one, what it rests on, and how sure it can be.

## How causes are chosen

Causes are per pair: one client and one server port. For RADIUS the client is
a NAS, which has its own client entry and shared secret on the server, so one
NAS with a secret mismatch and another whose users are rejected are two
causes, side by side. For LDAP the client is usually an application or an
identity provider, and the server its directory.

Within a pair, patterns are tried in the order below and the first that fits
is the cause: a secret checked against the packets beats an inference from
silence, and an ICMP error beats a guess. When nothing fits, there is no
likely cause and the report shows only the findings.

A cause is **confirmed** when the capture settles it: keyed checks that verify
on one side and not the other, an ICMP error that says why, a result code that
names the problem. Otherwise it is **likely**, and the report lists the
evidence each way, including what looks the same on the wire.

Two rules hold throughout. The capturing host's own RADIUS health checks (on
its loopback address) get a cause only when the capture holds nothing else;
what they show about the secret may support a mismatch on a real NAS, and is
never used against one. And nothing a TLS handshake leaves unsaid is read as
good news: in TLS 1.3 a certificate or trust alert is encrypted, so not seeing
one never rules a trust problem out.

## RADIUS

In the order they are tried.

**`radius-secret-mismatch`** (identity-lab runbook 05). The NAS and the server's
client entry for it hold different shared secrets. Confirmed when you give a
secret and one side's messages verify with it while the other's do not; a
match on User-Password confirms only when its zero padding is there too. A
server with a different secret that does not require Message-Authenticator
rejects every password, and the cause then says the rejects are not about
passwords. Without the secret, it is inferred from a NAS that resends a
request and gets no reply, with no ICMP error, while the server answers other
clients or the capture shows the requests arriving at the server; an unknown
client (the NAS's address missing from the server's client list) looks the
same on the wire, and the cause says so.

**`radius-secret-unknown`**. The secret you gave matches neither side, or does
not match the server's replies: get the current value before drawing
conclusions.

**`radius-port-closed`**, **`radius-firewall`**, **`radius-unreachable`**. ICMP
port unreachable (nothing listening), administratively prohibited (a firewall,
named), or host or network unreachable. Confirmed: the ICMP says so.

**`radius-reply-wrong-address`**. The server replies from an address or port
the NAS did not send to, so the NAS discards the reply and logs a timeout.

**`radius-no-message-authenticator`**. Every unanswered Access-Request lacks
Message-Authenticator: an old NAS, which a server hardened against BlastRADIUS
(CVE-2024-3596) drops without a word.

**`radius-unanswered-secret-ok`**. No reply, though the NAS's requests verify
with the secret you gave: if that is the server's secret, look at the server's
client list or a firewall instead.

**`radius-no-reply`**. No reply at all, and seen from the client or a device on
the path, there is no telling a firewall, a stopped server and a secret
mismatch apart. The cause says what capture would tell them apart.

**`radius-user-rejected`**. The server rejected the login. Confirmed genuine
when the reject verifies with the secret you gave. Without the secret, it is
likely, and when every login through one NAS is rejected and none accepted,
the cause raises the secret as the other explanation.

**`radius-slow`**. Replies at a p95 of a second or more, or only after the NAS
has resent. Access-Rejects are left out of response times everywhere, because
servers delay them on purpose.

## LDAP

In the order they are tried.

**`ldap-signing-required`**. A simple bind refused with 8 strongerAuthRequired
(or Active Directory's 00002028): the directory requires binds on an
unprotected connection to be signed. Likely, as the capture cannot say which
policy applies; the cause names the Active Directory events that do, and the
logging they need.

**`ldap-channel-binding`**. Active Directory's 80090346: LDAP channel binding is
enforced and the client's binding to its TLS connection is missing or wrong,
as when a TLS-inspecting device sits in between.

**`ldap-tls-required`**. 13 confidentialityRequired: binds only over TLS.

**`ldap-service-bind-failed`** (runbook 04). The application's own service
account cannot bind, so it cannot look up any user and every directory login
fails. Confirmed when you name the DN with `--service-dn`, or the capture shows
it binding and then searching; otherwise its wording is a hint and the cause
is likely. Active Directory's data code shapes the wording and the first step
(a locked-out account is unlocked only after the stored password is fixed).

**`ldap-user-bind-failed`** (runbook 04). One user's own bind failed, after the
application found them: one person's problem, not an outage.

**`ldap-bind-failed`**. A bind failed and the capture does not say whose it is;
the cause suggests `--service-dn`.

**`ldap-unauthenticated-bind`**. A simple bind with a DN and an empty password
was accepted: RFC 4513's unauthenticated bind, which proves nothing about the
password. It is ranked above the causes it can explain: an unauthenticated
bind carries only anonymous rights, so failures that follow it on the same
connection (insufficient access, a user not found) are cited as its result.

**`ldap-dn-not-found`**. 32 noSuchObject for a bind DN or a search base, with
the closest existing entry when the directory gives it.

**`ldap-insufficient-access`**. 50 insufficientAccessRights.

**`ldap-bind-needed`**. A search refused because no bind succeeded first (Active
Directory's 000004DC).

**`ldap-user-not-found`**. A user lookup (a filter on uid, sAMAccountName,
userPrincipalName, mail or cn) found nothing.

**`ldap-tls-failed`**. The TLS handshake to the directory failed: confirmed by a
fatal alert sent in clear (such as unknown_ca), or likely when a TLS 1.3
handshake stops after the ServerHello, which is how an encrypted trust alert
looks.

**`ldap-starttls-refused`**, **`ldap-connection-refused`**, **`ldap-no-response`**,
**`ldap-slow`**. StartTLS refused; connections reset before any data; requests
with no response until the client gave up or the server closed the
connection (a request still pending when the capture ended is reported, with
how long it had waited, but is not a cause); and a directory slow to respond.
