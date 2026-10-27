"""RADIUS packet codes, attribute names and how each value may be shown.

Every attribute value reaches a report through display(), so this is where
masking happens. A value is shown in one of three ways:

- in full, for identifiers a support engineer needs (User-Name, NAS-Identifier,
  Reply-Message, addresses, counters, enumerations);
- as its length only, for opaque values (State, Class, CHAP-Challenge) that
  mean nothing to a reader and may carry session details;
- as "hidden", for anything secret or derived from the shared secret
  (User-Password, CHAP-Password, Tunnel-Password, Message-Authenticator,
  MS-CHAP responses and MPPE keys). Never even a prefix of these is printed.

Unknown attributes are shown by length only: an attribute this dictionary
does not know could be anything, including a secret.
"""

import datetime as dt
import ipaddress
import struct
from dataclasses import dataclass

# Codes (RFC 2865, 2866, 5997, 5176).
CODES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
    12: "Status-Server",
    13: "Status-Client",
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
}
ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE = 4, 5
ACCESS_CHALLENGE, STATUS_SERVER = 11, 12
DISCONNECT_REQUEST, COA_REQUEST = 40, 43

# Which replies answer which request.
REPLIES = {
    ACCESS_REQUEST: {ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE},
    ACCOUNTING_REQUEST: {ACCOUNTING_RESPONSE},
    STATUS_SERVER: {ACCESS_ACCEPT, ACCOUNTING_RESPONSE},  # Accept on an auth port, Response on accounting
    DISCONNECT_REQUEST: {41, 42},
    COA_REQUEST: {44, 45},
}
REQUESTS = set(REPLIES)
ALL_REPLIES = set().union(*REPLIES.values())


def code_name(code):
    return CODES.get(code, f"code {code}")


# Value kinds.
TEXT, INTEGER, IPADDR, IPV6ADDR, IPV6PREFIX, DATE = "text", "integer", "ipaddr", "ipv6addr", "ipv6prefix", "date"
OPAQUE = "opaque"  # shown by length only
SECRET = "secret"  # never shown
PRESENT = "present"  # never shown, but its presence matters (Message-Authenticator)
EAP = "eap"
TAGGED_INTEGER, TAGGED_TEXT = "tagged-integer", "tagged-text"
VSA = "vsa"


@dataclass(frozen=True)
class AttrDef:
    name: str
    kind: str
    values: dict = None  # enumeration names for integer kinds


SERVICE_TYPE = {1: "Login-User", 2: "Framed-User", 3: "Callback-Login-User", 4: "Callback-Framed-User",
                5: "Outbound-User", 6: "Administrative-User", 7: "NAS-Prompt-User", 8: "Authenticate-Only",
                10: "Call-Check", 17: "Authorize-Only"}
FRAMED_PROTOCOL = {1: "PPP", 2: "SLIP", 3: "ARAP", 4: "Gandalf-SLML", 5: "Xylogics-IPX-SLIP", 6: "X.75-Synchronous"}
ACCT_STATUS_TYPE = {1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}
ACCT_AUTHENTIC = {1: "RADIUS", 2: "Local", 3: "Remote", 4: "Diameter"}
ACCT_TERMINATE_CAUSE = {
    1: "User-Request", 2: "Lost-Carrier", 3: "Lost-Service", 4: "Idle-Timeout", 5: "Session-Timeout",
    6: "Admin-Reset", 7: "Admin-Reboot", 8: "Port-Error", 9: "NAS-Error", 10: "NAS-Request", 11: "NAS-Reboot",
    12: "Port-Unneeded", 13: "Port-Preempted", 14: "Port-Suspended", 15: "Service-Unavailable", 16: "Callback",
    17: "User-Error", 18: "Host-Request",
}
NAS_PORT_TYPE = {0: "Async", 1: "Sync", 2: "ISDN", 3: "ISDN-V120", 4: "ISDN-V110", 5: "Virtual", 15: "Ethernet",
                 18: "Wireless-Other", 19: "Wireless-802.11"}
TUNNEL_TYPE = {1: "PPTP", 3: "L2TP", 9: "GRE", 13: "VLAN"}
TUNNEL_MEDIUM_TYPE = {1: "IPv4", 2: "IPv6", 6: "802"}
ERROR_CAUSE = {201: "Residual-Session-Context-Removed", 202: "Invalid-EAP-Packet", 401: "Unsupported-Attribute",
               402: "Missing-Attribute", 403: "NAS-Identification-Mismatch", 404: "Invalid-Request",
               405: "Unsupported-Service", 406: "Unsupported-Extension", 407: "Invalid-Attribute-Value",
               501: "Administratively-Prohibited", 502: "Request-Not-Routable", 503: "Session-Context-Not-Found",
               504: "Session-Context-Not-Removable", 505: "Other-Proxy-Processing-Error",
               506: "Resources-Unavailable", 507: "Request-Initiated", 508: "Multiple-Session-Selection-Unsupported"}

USER_NAME, USER_PASSWORD, CHAP_PASSWORD, NAS_IP_ADDRESS = 1, 2, 3, 4
REPLY_MESSAGE, STATE, VENDOR_SPECIFIC = 18, 24, 26
CALLED_STATION_ID, CALLING_STATION_ID, NAS_IDENTIFIER = 30, 31, 32
ACCT_STATUS_TYPE_ATTR, ACCT_SESSION_ID = 40, 44
EAP_MESSAGE, MESSAGE_AUTHENTICATOR, NAS_IPV6_ADDRESS, ERROR_CAUSE_ATTR = 79, 80, 95, 101

ATTRIBUTES = {
    1: AttrDef("User-Name", TEXT),
    2: AttrDef("User-Password", SECRET),
    3: AttrDef("CHAP-Password", SECRET),
    4: AttrDef("NAS-IP-Address", IPADDR),
    5: AttrDef("NAS-Port", INTEGER),
    6: AttrDef("Service-Type", INTEGER, SERVICE_TYPE),
    7: AttrDef("Framed-Protocol", INTEGER, FRAMED_PROTOCOL),
    8: AttrDef("Framed-IP-Address", IPADDR),
    9: AttrDef("Framed-IP-Netmask", IPADDR),
    11: AttrDef("Filter-Id", TEXT),
    12: AttrDef("Framed-MTU", INTEGER),
    14: AttrDef("Login-IP-Host", IPADDR),
    18: AttrDef("Reply-Message", TEXT),
    22: AttrDef("Framed-Route", TEXT),
    24: AttrDef("State", OPAQUE),
    25: AttrDef("Class", OPAQUE),
    26: AttrDef("Vendor-Specific", VSA),
    27: AttrDef("Session-Timeout", INTEGER),
    28: AttrDef("Idle-Timeout", INTEGER),
    30: AttrDef("Called-Station-Id", TEXT),
    31: AttrDef("Calling-Station-Id", TEXT),
    32: AttrDef("NAS-Identifier", TEXT),
    33: AttrDef("Proxy-State", OPAQUE),
    40: AttrDef("Acct-Status-Type", INTEGER, ACCT_STATUS_TYPE),
    41: AttrDef("Acct-Delay-Time", INTEGER),
    42: AttrDef("Acct-Input-Octets", INTEGER),
    43: AttrDef("Acct-Output-Octets", INTEGER),
    44: AttrDef("Acct-Session-Id", TEXT),
    45: AttrDef("Acct-Authentic", INTEGER, ACCT_AUTHENTIC),
    46: AttrDef("Acct-Session-Time", INTEGER),
    47: AttrDef("Acct-Input-Packets", INTEGER),
    48: AttrDef("Acct-Output-Packets", INTEGER),
    49: AttrDef("Acct-Terminate-Cause", INTEGER, ACCT_TERMINATE_CAUSE),
    50: AttrDef("Acct-Multi-Session-Id", TEXT),
    52: AttrDef("Acct-Input-Gigawords", INTEGER),
    53: AttrDef("Acct-Output-Gigawords", INTEGER),
    55: AttrDef("Event-Timestamp", DATE),
    60: AttrDef("CHAP-Challenge", OPAQUE),
    61: AttrDef("NAS-Port-Type", INTEGER, NAS_PORT_TYPE),
    64: AttrDef("Tunnel-Type", TAGGED_INTEGER, TUNNEL_TYPE),
    65: AttrDef("Tunnel-Medium-Type", TAGGED_INTEGER, TUNNEL_MEDIUM_TYPE),
    69: AttrDef("Tunnel-Password", SECRET),
    77: AttrDef("Connect-Info", TEXT),
    79: AttrDef("EAP-Message", EAP),
    80: AttrDef("Message-Authenticator", PRESENT),
    81: AttrDef("Tunnel-Private-Group-Id", TAGGED_TEXT),
    85: AttrDef("Acct-Interim-Interval", INTEGER),
    87: AttrDef("NAS-Port-Id", TEXT),
    88: AttrDef("Framed-Pool", TEXT),
    95: AttrDef("NAS-IPv6-Address", IPV6ADDR),
    97: AttrDef("Framed-IPv6-Prefix", IPV6PREFIX),
    101: AttrDef("Error-Cause", INTEGER, ERROR_CAUSE),
}

# Vendor-specific attributes are labelled by number ("VSA vendor 9, type 1"), never by vendor
# name, so the tool stays vendor-neutral. The RFC 2548 attributes keep their standard MS- names
# because several carry secrets that must be hidden. Any other sub-attribute is shown by length,
# except the free-text one below, which is widely used for policy strings worth reading.
VENDOR_MICROSOFT = 311


def vsa_label(vendor, vendor_type=None):
    return f"VSA vendor {vendor}" + (f", type {vendor_type}" if vendor_type is not None else "")


VENDOR_ATTRIBUTES = {
    (9, 1): AttrDef(vsa_label(9, 1), TEXT),
    (VENDOR_MICROSOFT, 1): AttrDef("MS-CHAP-Response", SECRET),
    (VENDOR_MICROSOFT, 2): AttrDef("MS-CHAP-Error", TEXT),
    (VENDOR_MICROSOFT, 7): AttrDef("MS-MPPE-Encryption-Policy", INTEGER),
    (VENDOR_MICROSOFT, 8): AttrDef("MS-MPPE-Encryption-Types", INTEGER),
    (VENDOR_MICROSOFT, 11): AttrDef("MS-CHAP-Challenge", SECRET),
    (VENDOR_MICROSOFT, 16): AttrDef("MS-MPPE-Send-Key", SECRET),
    (VENDOR_MICROSOFT, 17): AttrDef("MS-MPPE-Recv-Key", SECRET),
    (VENDOR_MICROSOFT, 25): AttrDef("MS-CHAP2-Response", SECRET),
    (VENDOR_MICROSOFT, 26): AttrDef("MS-CHAP2-Success", SECRET),
}

EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPES = {1: "Identity", 2: "Notification", 3: "NAK", 4: "MD5-Challenge", 6: "GTC", 13: "TLS", 21: "TTLS",
             25: "PEAP", 26: "MSCHAPv2", 43: "FAST", 52: "PWD"}

MAX_SHOWN = 120  # characters of a text value


@dataclass(frozen=True)
class Attribute:
    type: int
    value: bytes
    vendor: int = None  # set for a sub-attribute of Vendor-Specific
    vendor_type: int = None

    @property
    def definition(self):
        if self.vendor is not None:
            return VENDOR_ATTRIBUTES.get((self.vendor, self.vendor_type))
        return ATTRIBUTES.get(self.type)

    @property
    def name(self):
        d = self.definition
        if d:
            return d.name
        if self.vendor is not None:
            return vsa_label(self.vendor, self.vendor_type)
        return f"Attribute {self.type}"

    def display(self):
        """The value as it may appear in a report: in full, as a length, or hidden."""
        return display(self)


def display(attr):
    d = attr.definition
    v = attr.value
    if d is None:
        return _length(v)
    if d.kind == SECRET:
        return f"(hidden, {len(v)} bytes)"
    if d.kind == PRESENT:
        return "(present, value hidden)"
    if d.kind == OPAQUE:
        return _length(v)
    if d.kind == TEXT:
        return text(v)
    if d.kind == INTEGER:
        if len(v) != 4:
            return f"(invalid: {len(v)} bytes, expected 4)"
        n = struct.unpack("!I", v)[0]
        return _enum(n, d.values)
    if d.kind == TAGGED_INTEGER:
        if len(v) != 4:
            return f"(invalid: {len(v)} bytes, expected 4)"
        tag, n = v[0], int.from_bytes(v[1:], "big")
        return _enum(n, d.values) + (f" (tag {tag})" if tag else "")
    if d.kind == TAGGED_TEXT:
        if v and v[0] < 0x20:
            return text(v[1:]) + (f" (tag {v[0]})" if v[0] else "")
        return text(v)
    if d.kind == IPADDR:
        return str(ipaddress.IPv4Address(v)) if len(v) == 4 else f"(invalid: {len(v)} bytes, expected 4)"
    if d.kind == IPV6ADDR:
        return str(ipaddress.IPv6Address(v)) if len(v) == 16 else f"(invalid: {len(v)} bytes, expected 16)"
    if d.kind == IPV6PREFIX:
        if len(v) < 2 or v[1] > 128 or len(v) - 2 > 16:
            return _length(v)
        prefix = ipaddress.IPv6Address(v[2:].ljust(16, b"\x00"))
        return f"{prefix}/{v[1]}"
    if d.kind == DATE:
        if len(v) != 4:
            return f"(invalid: {len(v)} bytes, expected 4)"
        when = dt.datetime.fromtimestamp(struct.unpack("!I", v)[0], dt.UTC)
        return when.strftime("%Y-%m-%d %H:%M:%S UTC")
    if d.kind == EAP:
        return eap_summary(v)
    return _length(v)


def _length(v):
    return f"({len(v)} bytes)"


def _enum(n, values):
    if values and n in values:
        return f"{values[n]} ({n})"
    return str(n)


def text(v):
    """A text value, with anything unprintable escaped so it cannot disturb a terminal."""
    s = v.decode("utf-8", errors="backslashreplace")
    s = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in s)
    return s if len(s) <= MAX_SHOWN else s[:MAX_SHOWN] + f"... ({len(v)} bytes)"


def eap_summary(v):
    """The EAP header only: code, and the method for a request or response. Never the contents."""
    if len(v) < 4:
        return _length(v)
    code, ident = v[0], v[1]
    name = EAP_CODES.get(code, f"code {code}")
    if code in (1, 2) and len(v) >= 5:
        name += "/" + EAP_TYPES.get(v[4], f"type {v[4]}")
    return f"EAP-{name} (id {ident}, {len(v)} bytes)"
