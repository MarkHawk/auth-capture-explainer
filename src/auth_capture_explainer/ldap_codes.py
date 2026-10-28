"""LDAP result codes, and the Active Directory codes inside diagnosticMessage.

Result codes are from RFC 4511 (and RFC 3909 and 4528 for the last few).
Active Directory puts more detail in the diagnosticMessage of a failed bind:

    80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563

The "data" value says why the bind failed (wrong password, locked out,
expired...), which matters because the result code is 49 for all of them.
The leading code says which kind of failure it is; a few of those are
worth naming on their own (signing required, a bind needed first, channel
binding rejected). Codes are matched as whole hex words, case-insensitively.
"""

import re
from dataclasses import dataclass

RESULT_CODES = {
    0: "success", 1: "operationsError", 2: "protocolError", 3: "timeLimitExceeded", 4: "sizeLimitExceeded",
    5: "compareFalse", 6: "compareTrue", 7: "authMethodNotSupported", 8: "strongerAuthRequired", 10: "referral",
    11: "adminLimitExceeded", 12: "unavailableCriticalExtension", 13: "confidentialityRequired",
    14: "saslBindInProgress", 16: "noSuchAttribute", 17: "undefinedAttributeType", 18: "inappropriateMatching",
    19: "constraintViolation", 20: "attributeOrValueExists", 21: "invalidAttributeSyntax", 32: "noSuchObject",
    33: "aliasProblem", 34: "invalidDNSyntax", 36: "aliasDereferencingProblem", 48: "inappropriateAuthentication",
    49: "invalidCredentials", 50: "insufficientAccessRights", 51: "busy", 52: "unavailable",
    53: "unwillingToPerform", 54: "loopDetect", 64: "namingViolation", 65: "objectClassViolation",
    66: "notAllowedOnNonLeaf", 67: "notAllowedOnRDN", 68: "entryAlreadyExists", 69: "objectClassModsProhibited",
    71: "affectsMultipleDSAs", 80: "other", 118: "canceled", 119: "noSuchOperation", 120: "tooLate",
    121: "cannotCancel", 122: "assertionFailed", 123: "authorizationDenied",
}

# What the common failures mean, in a phrase.
MEANINGS = {
    1: "the server could not carry out the operation in this state",
    2: "the server could not understand the request",
    3: "the search took longer than the time limit",
    4: "more entries matched than the size limit allows",
    7: "the server does not support this kind of bind",
    8: "the server requires a stronger (signed or encrypted) bind",
    10: "the entry is held by another server (a referral)",
    11: "an administrative limit was exceeded",
    13: "the server requires an encrypted connection (TLS) for this",
    32: "the DN does not exist",
    34: "the DN is not valid syntax",
    48: "this kind of bind is not allowed for this account",
    49: "wrong password, or a DN that does not exist or cannot bind",
    50: "the account is not allowed to do this",
    51: "the server is too busy",
    52: "the server is unavailable (shutting down or not ready)",
    53: "the server refuses to do this",
}

SUCCESS, OPERATIONS_ERROR, STRONGER_AUTH_REQUIRED, REFERRAL = 0, 1, 8, 10
CONFIDENTIALITY_REQUIRED, SASL_BIND_IN_PROGRESS = 13, 14
NO_SUCH_OBJECT, INVALID_CREDENTIALS, INSUFFICIENT_ACCESS, UNWILLING = 32, 49, 50, 53


def name(code):
    return RESULT_CODES.get(code, f"code {code}")


def describe(code):
    """e.g. "49 invalidCredentials"."""
    return f"{code} {name(code)}"


@dataclass(frozen=True)
class AdCode:
    code: str  # lower-case hex, as Active Directory prints it
    name: str
    meaning: str


AD_DATA = {c.code: c for c in (
    AdCode("525", "user not found", "the bind DN or user name does not exist in the directory"),
    AdCode("52e", "invalid credentials", "the password is wrong (the account exists)"),
    AdCode("530", "not permitted at this time", "the account's logon hours do not allow a logon now"),
    AdCode("531", "not permitted at this workstation", "the account may only log on from certain computers"),
    AdCode("532", "password expired", "the account's password has expired"),
    AdCode("533", "account disabled", "the account is disabled"),
    AdCode("534", "logon type not granted", "the account is not granted this type of logon"),
    AdCode("568", "too many security IDs", "the account is in too many groups"),
    AdCode("701", "account expired", "the account itself has expired"),
    AdCode("773", "must change password", "the password must be changed before the account can log on"),
    AdCode("775", "account locked out", "the account is locked out, often after repeated wrong passwords"),
    AdCode("80090346", "channel binding rejected",
           "the bind's channel binding token is missing or does not match the TLS channel"),
)}

# Leading codes of an AD diagnosticMessage that name the problem on their own.
AD_LEADING = {
    "00002028": "the server requires binds to be signed (integrity) unless the connection uses TLS",
    "000004dc": "a successful bind is needed before this operation",
    "80090346": "the bind's channel binding token is missing or does not match the TLS channel",
    "8009030c": "the logon was denied",
}

_DATA = re.compile(r"\bdata\s+([0-9a-f]+)\b", re.IGNORECASE)
_LEADING = re.compile(r"^\s*([0-9a-f]{8})\s*:", re.IGNORECASE)


def ad_data(diagnostic):
    """The AdCode for the "data" value in an Active Directory diagnosticMessage, or None."""
    if not diagnostic:
        return None
    m = _DATA.search(diagnostic)
    if not m:
        return None
    value = m.group(1).lower()
    return AD_DATA.get(value) or AdCode(value, f"data {value}", "an Active Directory reason code not in this list")


def ad_leading(diagnostic):
    """(code, meaning) for a recognised leading code of an Active Directory diagnosticMessage, or None."""
    if not diagnostic:
        return None
    m = _LEADING.match(diagnostic)
    if not m:
        return None
    code = m.group(1).lower()
    return (code, AD_LEADING[code]) if code in AD_LEADING else None


def signing_required(code, diagnostic):
    """A bind refused because it must be signed: strongerAuthRequired, or AD's 00002028."""
    lead = ad_leading(diagnostic)
    return code == STRONGER_AUTH_REQUIRED or (lead is not None and lead[0] == "00002028")


def channel_binding_rejected(diagnostic):
    lead = ad_leading(diagnostic)
    data = ad_data(diagnostic)
    return (lead is not None and lead[0] == "80090346") or (data is not None and data.code == "80090346")
