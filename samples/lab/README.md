# Lab captures

Captures taken from a running [identity-lab](https://github.com/MarkHawk/identity-lab),
a self-contained lab that breaks identity systems on purpose, by
`scripts/capture_from_lab.sh`. Each is checked by `tests/test_lab_samples.py`
to give the answer its scenario calls for.

## How each one was made

Three kinds of traffic are involved, and each capture says which in its
`.meta.json` (`"made"`):

- **Real lab traffic**: recorded as it happened between lab containers, by
  tcpdump in a throwaway container sharing a lab container's network.
- **Repeated through a relay**: the lab's directory speaks LDAPS only, so its
  real traffic cannot be read. These captures repeat the binds Keycloak makes,
  with the same DNs and the same values, against the real lab directory,
  through a relay that accepts plain LDAP on its own loopback and forwards it
  over LDAPS. The capture is of the plain side. The directory's answers are its
  real answers; the response times include the relay's TLS hop, so they are
  not the directory's own.
- **Synthetic**: built byte by byte, for cases the lab cannot produce (for
  example Active Directory's sub-codes). There are none in this folder; the
  tests build theirs as they run.

| Capture | Made | What happens |
|---|---|---|
| `radius-accept.pcap` | real lab traffic | dave logs in through the lab NAS and is accepted |
| `radius-reject.pcap` | real lab traffic | dave logs in with a wrong password and is rejected |
| `radius-05-broken.pcap` | real lab traffic | scenario 05 broken: the NAS's secret differs, dave's login goes unanswered |
| `radius-05-fixed.pcap` | real lab traffic | scenario 05 fixed again: dave is accepted |
| `ldap-good.pcap` | repeated through a relay | Keycloak's login: the service account finds dave, then dave binds |
| `ldap-04-broken.pcap` | repeated through a relay | one good login, then the service account with scenario 04's wrong value |
| `ldap-04-fixed.pcap` | repeated through a relay | Keycloak's login after scenario 04 is fixed |
| `ldaps-04-encrypted.pcap` | real lab traffic | Keycloak's own LDAPS bind while scenario 04 is broken, as anyone capturing it would see it |

The RADIUS captures were taken on the RADIUS server's own interface, so they
also hold the server's health checks (Status-Server on its loopback address
every five seconds).

`ldap-04-broken.pcap` starts with a login that works, as on the morning
before a password rotation. That is what lets the tool tell from the traffic,
not just from the DN's wording, that the failing DN is a service account.

The encrypted capture needs `--ldap-port 1636`, the lab directory's port; its
`.meta.json` lists the arguments each capture needs.

## What sanitising changed

Nothing is committed until `scripts/sanitise_capture.py` has rewritten it and
checked the result:

- IP addresses moved to the documentation range 192.0.2.0/24 by role (the
  RADIUS server is .2, the NAS .10, the directory .20, LDAP clients .30 and
  .40 on), and MAC addresses to the documentation range 00-00-5E-00-53-xx
  (RFC 7042) by the same roles: Ethernet and Linux cooked headers end in the
  same number as the address, and RADIUS Calling-Station-Id and
  Called-Station-Id become 00-00-5E-00-53-AA and -AB. Checksums recomputed.
- RADIUS no longer uses the lab's secret. Every message was signed again with
  fixed sample secrets: User-Password hidden afresh with a sample password
  (`sample-password`, or `wrong-password` in the reject), and
  Message-Authenticator and the Response Authenticator recomputed. Nothing
  needed the real secret to do this.
- LDAP simple bind passwords replaced by one fixed value, `sanitised`, so not
  even their length is left. The binds were re-encoded and the TCP sequence and
  acknowledgement numbers after them moved to match, so the streams still read
  cleanly. identity-lab's published wrong value for scenario 04
  (`not-the-bind-password`) is kept, as it is what makes that sample real.
- Any TLS server name (SNI) in a ClientHello replaced by a neutral name of the
  same length. (Keycloak sends none to the lab's single-label host name `ldap`,
  so `ldaps-04-encrypted.pcap` has none to replace; the checker confirms it.)
- Written as classic pcap, which carries no capture metadata: no hardware, OS
  or application, interface names or descriptions, or comments.

## The sample secret

`sample.secret` holds `pcap-analyser-sample-secret`, a fixed fake value that
the sanitiser signed these captures with. It is not, and never was, the lab's
secret. Use it to see the secret checks work:

```
pcap-analyser samples/lab/radius-05-broken.pcap --secret-file samples/lab/sample.secret
```

In `radius-05-broken.pcap` the NAS signs with a second, different sample
secret, so the check shows the server's own traffic matching and the NAS's
requests not, as in scenario 05.

## Checks on every capture

`tests/test_capture_safety.py` checks each committed capture with the same
checker the capture script runs: no private addresses, home paths or private
keys; every MAC address in the documentation range; no pcapng metadata; every
TLS server name neutral; and every bind password the fixed value (or the
published 04 value). On the machine the captures were taken on,
it also checks against identity-lab's `.env`: none of its values anywhere, and
no RADIUS message that verifies with the lab's real secret.
