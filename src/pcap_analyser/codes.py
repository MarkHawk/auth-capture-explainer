"""Every machine-readable code pcap-analyser can emit, with what each means.

Findings are identified by their check_id and likely causes by their pattern;
--json gives both as "code". These codes are part of the interface: another
tool (such as a triage assistant) may act on them, so they do not change
meaning or disappear without a new major version and a CHANGELOG entry. New
codes may be added. tests/test_codes.py fails if the source emits a code not
listed here, or if a listed code is renamed or removed.

A finding's status (FAIL, WARN, PASS, INFO, SKIP) and a cause's "confirmed"
flag say how serious or how certain each instance is; the code says what it
is about.
"""

FINDINGS = {
    # the capture file
    "capture.note": "a remark about the file itself: cut short, damaged, interrupted, or carrying TLS keys",
    "capture.malformed": "packets that could not be decoded and were skipped",
    "capture.link_type": "packets with a link type this tool cannot read",
    "capture.fragments": "IP fragments that were not reassembled",
    "capture.nothing": "no RADIUS or LDAP traffic in the capture",
    # RADIUS, per client (NAS) and server pair
    "radius.unanswered": "requests that got no reply",
    "radius.capture_ended": "requests sent too close to the end of the capture to tell",
    "radius.capture_point": "where the capture was taken, and how that was told",
    "radius.answering": "the server answered this client",
    "radius.icmp": "ICMP errors about requests or replies",
    "radius.message_authenticator": "Message-Authenticator on requests: present, or absent",
    "radius.reply_message_authenticator": "Message-Authenticator on replies: present, or absent",
    "radius.message_authenticator_position": "Message-Authenticator present but not the first attribute",
    "radius.rejects": "Access-Rejects, with any Reply-Message",
    "radius.challenges": "Access-Challenges: a multi-step login in progress",
    "radius.response_time": "response times, Access-Rejects apart",
    "radius.reply_from_elsewhere": "replies from a different address or port than the request went to",
    "radius.reused_ids": "a request ID reused while an earlier request with it was pending",
    "radius.legacy_port": "the pre-standard ports 1645 or 1646 in use",
    "radius.secret": "the shared secret checked against both sides, or not checked",
    # RADIUS, across the capture
    "radius.secret_shape": "the secret given starts or ends with whitespace",
    "radius.malformed": "packets on RADIUS ports that are not RADIUS",
    "radius.orphan_replies": "replies whose request is not in the capture",
    # LDAP, per client and directory pair
    "ldap.bind_failed": "a rejected bind, with result code, diagnostic, Active Directory reason and role",
    "ldap.binds": "binds that succeeded",
    "ldap.unauthenticated_bind": "a simple bind with a DN and an empty password",
    "ldap.search_failed": "a search that failed",
    "ldap.search_limited": "searches that hit the size limit",
    "ldap.search_empty": "searches that found nothing",
    "ldap.searches": "searches that succeeded",
    "ldap.referrals": "searches answered with referrals",
    "ldap.operation_failed": "another operation that failed",
    "ldap.starttls_refused": "StartTLS refused",
    "ldap.unanswered": "requests with no response, and how the wait ended",
    "ldap.pending": "requests still waiting when the capture ended",
    "ldap.notice": "a Notice of Disconnection from the server",
    "ldap.tls": "connections using TLS, and what their handshakes show",
    "ldap.sasl_layer": "connections signed or sealed after a SASL bind",
    "ldap.unreadable": "connections that are neither LDAP nor the start of TLS",
    "ldap.refused": "connections reset before any data",
    "ldap.empty": "connections that carried no data",
    "ldap.damaged": "messages that could not be read, or gaps in the capture",
    "ldap.response_time": "response times",
    # LDAP, across the capture
    "ldap.orphan_responses": "responses whose request is not in the capture",
    # per server, across clients
    "server.slow": "a server slow for all its clients",
}

CAUSES = {
    "radius-secret-mismatch": "the NAS and the server's client entry hold different shared secrets",
    "radius-secret-unknown": "the secret given matches neither side, or not the server",
    "radius-port-closed": "nothing listening on the RADIUS port (ICMP port unreachable)",
    "radius-firewall": "a firewall refuses RADIUS (ICMP administratively prohibited)",
    "radius-unreachable": "the server cannot be reached (ICMP host or network unreachable)",
    "radius-reply-wrong-address": "the server replies from an address the NAS did not send to",
    "radius-no-message-authenticator": "an old NAS sends no Message-Authenticator to a server that requires it",
    "radius-unanswered-secret-ok": "no reply, though the NAS's requests verify with the secret given",
    "radius-no-reply": "no reply at all, and no way to tell why from where the capture was taken",
    "radius-user-rejected": "the server rejected the user's login",
    "radius-slow": "the RADIUS server is slow to reply",
    "ldap-signing-required": "LDAP signing or channel binding enforcement refused a simple bind",
    "ldap-channel-binding": "LDAP channel binding rejected the bind",
    "ldap-tls-required": "the directory requires TLS for binds",
    "ldap-service-bind-failed": "the application's service account cannot bind",
    "ldap-user-bind-failed": "one user's own bind failed",
    "ldap-bind-failed": "a bind failed, of unknown role",
    "ldap-unauthenticated-bind": "an empty-password bind was accepted",
    "ldap-dn-not-found": "a bind DN or search base that does not exist",
    "ldap-insufficient-access": "the account lacks permission",
    "ldap-bind-needed": "a search without a bind, refused",
    "ldap-user-not-found": "the user lookup found nothing",
    "ldap-tls-failed": "the TLS handshake to the directory failed",
    "ldap-starttls-refused": "the directory refused StartTLS",
    "ldap-connection-refused": "the directory resets connections",
    "ldap-no-response": "the directory did not respond",
    "ldap-slow": "the directory is slow to respond",
}
