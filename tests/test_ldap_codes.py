"""LDAP result code names, and Active Directory's codes inside diagnosticMessage."""

import pytest

from pcap_analyser import ldap_codes as lc

AD_52E = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"


def test_names():
    assert lc.describe(49) == "49 invalidCredentials" and lc.describe(8) == "8 strongerAuthRequired"
    assert lc.name(999) == "code 999"


@pytest.mark.parametrize("diagnostic,code,name", [
    (AD_52E, "52e", "invalid credentials"),
    (AD_52E.replace("52e", "775"), "775", "account locked out"),
    (AD_52E.replace("52e", "525"), "525", "user not found"),
    ("... data 52E, v2580", "52e", "invalid credentials"),  # older servers, upper case
    ("80090346: LdapErr: DSID-0C09058A, comment: AcceptSecurityContext error, data 80090346, v4563",
     "80090346", "channel binding rejected"),
    ("... data 123abc, v1", "123abc", "data 123abc"),
])
def test_ad_data(diagnostic, code, name):
    ad = lc.ad_data(diagnostic)
    assert (ad.code, ad.name) == (code, name)


@pytest.mark.parametrize("diagnostic", [None, "", "invalid credentials", "metadata 52e"])
def test_no_ad_data(diagnostic):
    assert lc.ad_data(diagnostic) is None


def test_leading_codes():
    signing = ("00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking "
               "if SSL\\TLS are not already active on the connection, data 0, v4563")
    assert lc.ad_leading(signing)[0] == "00002028"
    assert lc.ad_leading("000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a "
                         "successful bind must be completed on the connection., data 0, v4563")[0] == "000004dc"
    assert lc.ad_leading("12345678: something else") is None
    assert lc.signing_required(8, "") and lc.signing_required(53, signing) and not lc.signing_required(49, AD_52E)


def test_channel_binding():
    assert lc.channel_binding_rejected("80090346: LdapErr: DSID-0C09058A, data 80090346, v4563")
    assert not lc.channel_binding_rejected(AD_52E)
