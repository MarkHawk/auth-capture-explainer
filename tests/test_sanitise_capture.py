"""The capture sanitiser, on raw captures shaped like the lab's: RADIUS on
the server's own interface signed with a stand-in for the lab's real secret,
LDAP through the loopback relay with clear-text passwords, and a .env with
the values that must never be committed.

Every "real" value here is a test stand-in built at run time; none is the
lab's.
"""

import re
import struct

import dpkt
import pytest

import ldap_build as lb
import pcapbuild as pb
import radius_sign as sign
from conftest import load_script
from ldap_build import Conversation
from pcap_analyser import layers, ldap_exchange, radius_auth
from pcap_analyser.capture import read_capture
from pcap_analyser.radius_exchange import analyse as radius_analyse
from radius_trace import auth_for

sc = load_script("sanitise_capture")

REAL_SECRET = b"stand-in-" + b"real-radius-secret"
REAL_BIND = "stand-in-" + "real-bind-password"
REAL_DEMO = "stand-in-" + "real-demo-password"
# Private addresses like the lab's, assembled at run time so no source file contains one.
LAB_NAS, LAB_SERVER = ".".join(("172", "30", "181", "10")), ".".join(("172", "30", "181", "2"))


@pytest.fixture
def lab_env(tmp_path):
    path = tmp_path / "lab.env"
    path.write_text(f"LAB_HOST=idlab.home\nKC_PORT=8180\nRADIUS_SECRET={REAL_SECRET.decode()}\n"
                    f"LDAP_BIND_PASSWORD={REAL_BIND}\nDEMO_PASSWORD=\"{REAL_DEMO}\"\n")
    return path


def raw_radius(tmp_path, nas_secret=REAL_SECRET, reply=True, extra=()):
    """What tcpdump -i any records on the lab RADIUS server: a health check on loopback, and dave's login."""
    frames = []

    def add(ts, ip, pkttype=0):
        frames.append((ts, pb.sll2(ip, pkttype)))

    add(0.5, pb.udp("127.0.0.1", "127.0.0.1", 50001, 1812, sign.status_server(9, auth_for(9), REAL_SECRET)))
    add(0.5001, pb.udp("127.0.0.1", "127.0.0.1", 1812, 50001, sign.reply(2, 9, auth_for(9), [], REAL_SECRET)))
    request = sign.access_request(16, auth_for(16), [(1, b"dave"), (32, b"nas"), *extra], nas_secret,
                                  password=REAL_DEMO.encode())
    for i in range(1 if reply else 3):
        add(1.0 + 2 * i, pb.udp(LAB_NAS, LAB_SERVER, 40000, 1812, request))
    if reply:
        add(2.0, pb.udp(LAB_SERVER, LAB_NAS, 1812, 40000,
                        sign.reply(3, 16, auth_for(16), [(18, b"Login incorrect")], REAL_SECRET)), pkttype=4)
    return pb.write(tmp_path, "raw-radius.pcap", pb.pcap(frames, linktype=layers.LINKTYPE_LINUX_SLL2))


def raw_relay(tmp_path, binds):
    """What the relay container records on its loopback: plain LDAP, both ends 127.0.0.1."""
    c = Conversation(client="127.0.0.1", server="127.0.0.1", cport=52534, sport=389).handshake(1.0)
    for i, (dn, password, code) in enumerate(binds, 1):
        c.client_says(1.0 + i, lb.bind_request(i, dn, password))
        c.server_says(1.0 + i + 0.01, lb.bind_response(i, code))
    frames = [(ts, b"\x00" * 12 + b"\x08\x00" + ip) for ts, ip in c.ips]
    return pb.write(tmp_path, "raw-ldap.pcap", pb.pcap(frames, linktype=layers.LINKTYPE_ETHERNET))


def radius_messages(path):
    return radius_analyse(read_capture(path).packets).exchanges


# --- RADIUS --------------------------------------------------------------------------------------

def test_radius_moves_onto_the_sample_secret(tmp_path, lab_env):
    out = sc.sanitise("radius-reject", raw_radius(tmp_path), tmp_path / "out", lab_env, personal=[])
    raw = out.read_bytes()
    assert REAL_SECRET not in raw and REAL_DEMO.encode() not in raw
    health, login = radius_messages(out)
    for e in (health, login):
        checks = radius_auth.check_request(e.request, sc.SAMPLE_SECRET) + \
            radius_auth.check_reply(e.reply, e.request, sc.SAMPLE_SECRET)
        assert checks and all(c.ok and c.strong for c in checks)
        old = radius_auth.check_request(e.request, REAL_SECRET) + radius_auth.check_reply(e.reply, e.request,
                                                                                          REAL_SECRET)
        assert not any(c.ok for c in old)
    assert (login.client, login.server, health.client) == ("192.0.2.10", "192.0.2.2", "127.0.0.1")
    assert [a.display() for a in login.reply.attributes if a.name == "Reply-Message"] == ["Login incorrect"]
    assert sc.check_file(out, lab_env, []) == []


def test_the_sample_password_is_what_user_password_now_hides(tmp_path, lab_env):
    out = sc.sanitise("radius-reject", raw_radius(tmp_path), tmp_path / "out", lab_env, personal=[])
    login = radius_messages(out)[1]
    hidden = next(a.value for a in login.request.attributes if a.name == "User-Password")
    assert hidden == sc.hide_password(b"wrong-password", login.request.authenticator, sc.SAMPLE_SECRET)


def test_scenario_05_keeps_the_nas_on_a_different_secret(tmp_path, lab_env):
    raw = raw_radius(tmp_path, nas_secret=b"not-the-radius-secret", reply=False)
    out = sc.sanitise("radius-05-broken", raw, tmp_path / "out", lab_env, personal=[])
    health, login = radius_messages(out)
    assert login.retransmissions == 2 and all(a.raw == login.request.raw for a in login.attempts)
    assert all(c.ok for c in radius_auth.check_request(login.request, sc.SAMPLE_WRONG_SECRET))
    assert not any(c.ok for c in radius_auth.check_request(login.request, sc.SAMPLE_SECRET))
    assert all(c.ok for c in radius_auth.check_request(health.request, sc.SAMPLE_SECRET))


def test_device_and_network_identifiers_are_rewritten(tmp_path, lab_env):
    extra = [(31, b"aa-bb-cc-dd-ee-ff"), (30, b"11-22-33-44-55-66:CorpWiFi"), (8, bytes([10, 1, 2, 3])),
             (4, bytes(int(o) for o in LAB_NAS.split(".")))]
    out = sc.sanitise("radius-accept", raw_radius(tmp_path, extra=extra), tmp_path / "out", lab_env, personal=[])
    shown = {a.name: a.display() for a in radius_messages(out)[1].request.attributes}
    assert shown["Calling-Station-Id"] == "00-00-5E-00-53-AA"
    assert shown["Called-Station-Id"] == "00-00-5E-00-53-AB:sample-ssid"
    assert shown["Framed-IP-Address"] == "192.0.2.100" and shown["NAS-IP-Address"] == "192.0.2.10"
    raw = out.read_bytes()
    assert b"CorpWiFi" not in raw and b"aa-bb-cc" not in raw


def test_link_addresses_and_checksums(tmp_path, lab_env):
    out = sc.sanitise("radius-accept", raw_radius(tmp_path), tmp_path / "out", lab_env, personal=[])
    with open(out, "rb") as f:
        for _, frame in dpkt.pcap.Reader(f):
            # The cooked header's link address: the documentation range, by the sender's role.
            assert frame[12:17] == bytes.fromhex("00005e0053") and frame[17] in (0x00, 0x02, 0x0A)
            ip = frame[20:]
            assert dpkt.in_cksum(ip[:20]) == 0
            udp = ip[20:]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(udp))
            assert dpkt.in_cksum(pseudo + udp) == 0


def test_a_reply_without_its_request_is_refused(tmp_path, lab_env):
    frames = [(1.0, pb.sll2(pb.udp(LAB_SERVER, LAB_NAS, 1812, 40000, sign.reply(2, 1, auth_for(1), [], REAL_SECRET))))]
    raw = pb.write(tmp_path, "orphan.pcap", pb.pcap(frames, linktype=layers.LINKTYPE_LINUX_SLL2))
    with pytest.raises(sc.Unsafe, match="cannot be re-signed"):
        sc.sanitise("radius-accept", raw, tmp_path / "out", lab_env, personal=[])


# --- LDAP ---------------------------------------------------------------------------------------

SVC = "cn=keycloak-svc,ou=services,dc=idlab,dc=example"


def test_bind_passwords_are_overwritten_and_the_public_value_kept(tmp_path, lab_env):
    raw = raw_relay(tmp_path, [(SVC, REAL_BIND, 0), ("uid=dave,ou=people,dc=idlab,dc=example", REAL_DEMO, 0),
                               (SVC, "not-the-bind-password", 49), (SVC, "some-other-password", 49)])
    out = sc.sanitise("ldap-04-broken", raw, tmp_path / "out", lab_env, personal=[])
    data = out.read_bytes()
    assert REAL_BIND.encode() not in data and REAL_DEMO.encode() not in data
    assert b"some-other-password" not in data and b"not-the-bind-password" in data
    assert b"*" not in data and data.count(sc.FIXED_BIND_PASSWORD) == 3  # the same value, whatever the length
    assert sc.check_file(out, lab_env, []) == []
    cap = read_capture(out)
    assert {p.src for p in cap.packets} == {"192.0.2.30", "192.0.2.20"}
    assert all((p.src == "192.0.2.20") == (p.sport == 389) for p in cap.packets)


def test_personal_patterns_and_private_addresses_in_ldap_text_are_masked_in_place(tmp_path, lab_env):
    private = ".".join(("10", "20", "30", "40"))
    dn = f"cn=Smithers,ou={private},dc=example"
    raw = raw_relay(tmp_path, [(dn, "", 0)])
    out = sc.sanitise("ldap-good", raw, tmp_path / "out", lab_env, personal=[re.compile("Smithers")])
    data = out.read_bytes()
    assert b"Smithers" not in data and private.encode() not in data
    assert b"cn=xxxxxxxx,ou=xxxxxxxxxxx,dc=example" in data  # same length, so the TCP stream stays intact


def test_lab_env_values_are_masked_wherever_they_appear(tmp_path, lab_env):
    raw = raw_relay(tmp_path, [(f"cn={REAL_DEMO},dc=example", "", 0)])  # a secret somewhere unexpected
    out = sc.sanitise("ldap-good", raw, tmp_path / "out", lab_env, personal=[])
    assert REAL_DEMO.encode() not in out.read_bytes()


# --- checking -------------------------------------------------------------------------------------

def test_check_finds_what_must_not_be_committed(tmp_path, lab_env):
    raw_ldap = raw_relay(tmp_path, [(SVC, REAL_BIND, 0)])
    kinds = sc.check_file(raw_ldap, lab_env, [])
    assert "an LDAP bind password not replaced by the fixed value" in kinds
    assert "a value from the lab's .env" in kinds
    raw_rad = raw_radius(tmp_path)
    kinds = sc.check_file(raw_rad, lab_env, [])
    assert "a private address in an IP header" in kinds
    assert "a RADIUS message keyed with the lab's real secret" in kinds


def test_check_messages_name_the_kind_never_the_value(tmp_path, lab_env):
    raw = raw_relay(tmp_path, [(SVC, REAL_BIND, 0)])
    for name, kind in sc.check_paths([raw], lab_env):
        assert REAL_BIND not in kind and REAL_BIND not in name


def test_env_values_skip_ports_and_host_names(lab_env):
    values = sc.env_values(lab_env)
    assert set(values) == {"RADIUS_SECRET", "LDAP_BIND_PASSWORD", "DEMO_PASSWORD"}
    assert values["DEMO_PASSWORD"] == REAL_DEMO.encode()  # quotes removed
    assert sc.env_values(None) == {} and sc.env_values(lab_env.parent / "missing") == {}


def test_unsupported_link_types_are_refused(tmp_path, lab_env):
    raw = pb.write(tmp_path, "raw.pcap", pb.pcap([(1.0, pb.udp(LAB_NAS, LAB_SERVER, 1, 1812, b"x"))], linktype=101))
    with pytest.raises(sc.Unsafe, match="link type 101"):
        sc.sanitise("radius-accept", raw, tmp_path / "out", lab_env, personal=[])


# --- MAC addresses ----------------------------------------------------------------------------

def test_ethernet_macs_move_to_the_documentation_range_by_role(tmp_path, lab_env):
    out = sc.sanitise("ldap-good", raw_relay(tmp_path, [(SVC, REAL_BIND, 0)]), tmp_path / "out", lab_env, [])
    with open(out, "rb") as f:
        for _, frame in dpkt.pcap.Reader(f):
            ip = dpkt.ethernet.Ethernet(frame).data
            for mac, addr in ((frame[:6], ip.dst), (frame[6:12], ip.src)):
                assert mac == bytes.fromhex("00005e0053") + addr[-1:]  # directory ...:14, client ...:1e


def test_the_checker_finds_macs_outside_the_documentation_range(tmp_path, lab_env):
    frames = [(1.0, pb.ether(pb.udp("192.0.2.10", "192.0.2.2", 40000, 1812,
                                    pb.radius(1, 1, [(31, "aa-bb-cc-dd-ee-ff")]))))]
    path = pb.write(tmp_path, "macs.pcap", pb.pcap(frames))
    kinds = sc.check_file(path, lab_env, [])
    assert "an Ethernet MAC address outside the documentation range" in kinds
    assert "a MAC address outside the documentation range, written as text" in kinds


# --- pcapng metadata -------------------------------------------------------------------------------

def _option(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def pcapng_with_metadata(frame_bytes):
    """A pcapng as Wireshark writes it: hardware, OS and application, an interface name and description,
    a comment on a packet, and a name resolution block."""
    shb_opts = _option(2, b"ExampleCorp laptop") + _option(3, b"Linux 7.0") + _option(4, b"Dumpcap") + \
        _option(1, b"captured for ticket 4242") + _option(0, b"")
    shb = pb._block("<", 0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + shb_opts)
    idb_opts = _option(2, b"enp3s0") + _option(3, b"Office uplink") + _option(9, b"\x06") + _option(0, b"")
    idb = pb._block("<", 1, struct.pack("<HHI", layers.LINKTYPE_LINUX_SLL2, 0, 262144) + idb_opts)
    blocks = shb + idb
    for i, (ts, frame) in enumerate(frame_bytes):
        body = struct.pack("<IIIII", 0, 0, int(ts * 1e6), len(frame), len(frame)) + frame + \
            b"\x00" * (-len(frame) % 4)
        if i == 0:
            body += _option(1, b"the one that failed") + _option(0, b"")
        blocks += pb._block("<", 6, body)
    return blocks + pb.nrb()


def test_pcapng_input_is_written_as_pcap_with_no_metadata(tmp_path, lab_env):
    raw_pcap = raw_radius(tmp_path)
    with open(raw_pcap, "rb") as f:
        frames = [(ts, frame) for ts, frame in dpkt.pcap.Reader(f)]
    raw = pb.write(tmp_path, "raw.pcapng", pcapng_with_metadata(frames))
    kinds = sc.check_file(raw, lab_env, [])
    assert "pcapng section metadata (hardware, OS, application or comment)" in kinds
    assert "pcapng interface metadata (a name, description, address or comment)" in kinds
    assert "a pcapng packet comment or other packet option" in kinds
    assert "a pcapng name resolution block" in kinds
    out = sc.sanitise("radius-reject", raw, tmp_path / "out", lab_env, personal=[])
    data = out.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1"  # classic pcap
    for word in (b"ExampleCorp", b"Linux 7.0", b"Dumpcap", b"ticket", b"enp3s0", b"Office", b"failed"):
        assert word not in data
    assert sc.check_file(out, lab_env, []) == []


def test_a_capture_mixing_link_types_is_refused(tmp_path, lab_env):
    ip = pb.udp("192.0.2.10", "192.0.2.2", 1, 1812, b"x")
    data = pb.pcapng(pb.idb(1), pb.idb(layers.LINKTYPE_LINUX_SLL2), pb.epb(0, 1, pb.ether(ip)), pb.epb(1, 2, pb.sll2(ip)))
    with pytest.raises(sc.Unsafe, match="mixes link types"):
        sc.sanitise("radius-accept", pb.write(tmp_path, "mixed.pcapng", data), tmp_path / "out", lab_env, [])


# --- TLS server names ----------------------------------------------------------------------------

def raw_ldaps(tmp_path, sni):
    c = Conversation(client=LAB_NAS, server=LAB_SERVER, sport=1636).handshake(1.0)
    c.client_says(1.1, lb.client_hello(sni))
    c.server_says(1.2, lb.server_hello(tls13=True) + lb.app_data(900))
    c.client_says(1.3, lb.app_data(53) + lb.app_data(200))
    frames = [(ts, b"\x00" * 12 + b"\x08\x00" + ip) for ts, ip in c.ips]
    return pb.write(tmp_path, "raw-ldaps.pcap", pb.pcap(frames, linktype=layers.LINKTYPE_ETHERNET))


def test_the_server_name_becomes_neutral_and_the_handshake_still_parses(tmp_path, lab_env):
    raw = raw_ldaps(tmp_path, "dc01.corp-internal.example")
    assert "a TLS server name (SNI) that is not neutral" in sc.check_file(raw, lab_env, [])
    out = sc.sanitise("ldaps-04-encrypted", raw, tmp_path / "out", lab_env, personal=[])
    assert b"corp-internal" not in out.read_bytes()
    (conn,) = ldap_exchange.analyse(read_capture(out).packets, ldap_exchange.DEFAULT_PORTS.with_extra({1636})).connections
    assert conn.tls.server_name == "xxxx.xxxx-xxxxxxxx.xxxxxxx" and conn.tls.server_version == "TLS 1.3"
    assert conn.tls.completed
    assert sc.check_file(out, lab_env, []) == []


def test_neutral_name_keeps_the_shape():
    assert sc.neutral_name(b"ldap") == b"xxxx"
    assert sc.neutral_name(b"dc1.corp.example") == b"xxx.xxxx.xxxxxxx"


# --- a fixed bind password, with TCP numbers moved ---------------------------------------------------

def test_a_longer_or_shorter_password_keeps_the_stream_intact(tmp_path, lab_env):
    """Passwords of other lengths than the fixed value: every later message must still decode and pair."""
    binds = [(SVC, "a" * 40, 0), ("uid=dave,ou=people,dc=idlab,dc=example", "pw", 0), (SVC, "b" * 3, 49)]
    out = sc.sanitise("ldap-good", raw_relay(tmp_path, binds), tmp_path / "out", lab_env, personal=[])
    (conn,) = ldap_exchange.analyse(read_capture(out).packets).connections
    assert conn.problems == [] and conn.gaps == 0
    assert [(op.request.dn, op.request.password_length, op.result.result_code) for op in conn.operations] == [
        (SVC, 9, 0), ("uid=dave,ou=people,dc=idlab,dc=example", 9, 0), (SVC, 9, 49)]
    # The server's acknowledgements follow the new numbers: each acknowledges exactly what the client sent.
    client_end = {}
    for p in read_capture(out).packets:
        if p.dport == 389:
            client_end[p.ts] = (p.tcp_seq + len(p.payload)) % (1 << 32)
    acks = [p.tcp_ack for p in read_capture(out).packets if p.sport == 389 and p.payload]
    assert all(ack in client_end.values() for ack in acks)


def test_sack_blocks_on_a_rewritten_connection_are_refused(tmp_path, lab_env):
    raw = raw_relay(tmp_path, [(SVC, REAL_BIND, 0)])
    with open(raw, "rb") as f:
        frames = [(ts, frame) for ts, frame in dpkt.pcap.Reader(f)]
    ts, frame = frames[-1]  # the server's bind response: give it a SACK block
    eth = dpkt.ethernet.Ethernet(frame)
    eth.data.data.opts = struct.pack("!BBII", 5, 10, 1, 2) + b"\x01\x01"
    eth.data.data.off = (20 + len(eth.data.data.opts)) // 4
    eth.data.len = len(eth.data)
    frames[-1] = (ts, bytes(eth))
    path = pb.write(tmp_path, "sack.pcap", pb.pcap(frames, linktype=layers.LINKTYPE_ETHERNET))
    with pytest.raises(sc.Unsafe, match="SACK"):
        sc.sanitise("ldap-good", path, tmp_path / "out", lab_env, personal=[])


def test_sanitising_is_idempotent(tmp_path, lab_env):
    once = sc.sanitise("radius-reject", raw_radius(tmp_path), tmp_path / "a", lab_env, personal=[])
    twice = sc.sanitise("radius-reject", once, tmp_path / "b", lab_env, personal=[])
    assert once.read_bytes() == twice.read_bytes()
    once = sc.sanitise("ldap-04-broken", raw_relay(tmp_path, [(SVC, REAL_BIND, 0), (SVC, "not-the-bind-password", 49)]),
                       tmp_path / "c", lab_env, personal=[])
    twice = sc.sanitise("ldap-04-broken", once, tmp_path / "d", lab_env, personal=[])
    assert once.read_bytes() == twice.read_bytes()
