"""pcapng end to end: whole analyses of pcapng files, including files with
several interfaces of different link types and clocks, as Wireshark writes
when it captures on more than one interface.

The reader's own tests (test_capture.py) cover the format block by block;
these check that what an engineer gets from a pcapng file is what they
would get from the same packets as pcap. One file is written by dpkt's
pcapng writer, so the reader is not only checked against this project's
own test writer.
"""

import io
import json

import dpkt

import ldap_build as lb
import pcapbuild as pb
from ldap_build import Conversation
from auth_capture_explainer import layers
from auth_capture_explainer.cli import main
from radius_trace import Trace

LDAP_IF, RADIUS_IF = 0, 1


def run(path, *argv):
    out = io.StringIO()
    code = main([str(path), "--json", *argv], stdout=out, stderr=io.StringIO())
    return code, json.loads(out.getvalue())


def two_protocols():
    """An LDAP service bind that fails, and a NAS resending into silence, as two separate traces."""
    c = Conversation().handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, "cn=svc,ou=services,dc=example", "x"))
    c.server_says(1.2, lb.bind_response(1, 49))
    t = Trace()
    for i in range(3):
        t.request(1.5 + 2 * i, 16, secret=b"nas-secret", password=b"pw")
    return c, t


def test_a_multi_interface_pcapng_file(tmp_path):
    """Interface 0: Ethernet, microseconds, carrying LDAP. Interface 1: Linux cooked v2, nanoseconds, the
    RADIUS server's own interface, with each packet's direction. Packets interleaved in time order."""
    c, t = two_protocols()
    blocks = [pb.idb(layers.LINKTYPE_ETHERNET), pb.idb(layers.LINKTYPE_LINUX_SLL2, tsresol=9)]
    timed = [(ts, LDAP_IF, pb.ether(ip)) for ts, ip in c.ips]
    timed += [(ts, RADIUS_IF, pb.sll2(ip, 0)) for ts, ip in t.ips]  # 0: arriving at this host
    for ts, if_id, frame in sorted(timed):
        units = round(ts * (1_000_000_000 if if_id == RADIUS_IF else 1_000_000))
        blocks.append(pb.epb(if_id, units, frame))
    path = pb.write(tmp_path, "two-interfaces.pcapng", pb.pcapng(*blocks))
    code, data = run(path)
    assert code == 1
    cap = data["capture"]
    assert (cap["format"], cap["link_types"], cap["packets"]) == ("pcapng", ["Ethernet", "Linux cooked v2"], 8)
    assert cap["first_packet"] == "1970-01-01T00:00:01.000000Z"
    assert cap["last_packet"] == "1970-01-01T00:00:05.500000Z"  # the nanosecond clock read right
    causes = {c["pattern"] for c in data["likely_causes"]}
    assert causes == {"ldap-service-bind-failed", "radius-secret-mismatch"}
    point = next(f for f in data["findings"] if f["check_id"] == "radius.capture_point")
    assert point["details"]["where"] == "server"  # from the cooked interface's directions


def test_pcapng_epb_direction_flags_set_the_capture_point(tmp_path):
    """Ethernet carries no direction, but pcapng's packet flags can: Wireshark sets them on Windows."""
    _, t = two_protocols()
    blocks = [pb.idb(layers.LINKTYPE_RAW)] + [pb.epb(0, round(ts * 1e6), ip, flags=1) for ts, ip in t.ips]
    _, data = run(pb.write(tmp_path, "flags.pcapng", pb.pcapng(*blocks)))
    point = next(f for f in data["findings"] if f["check_id"] == "radius.capture_point")
    assert point["details"]["where"] == "server"


def test_a_file_written_by_dpkt_reads_the_same_as_pcap(tmp_path):
    c, t = two_protocols()
    timed = sorted(c.ips + t.ips)
    as_pcap = pb.write(tmp_path, "same.pcap", pb.pcap(timed, linktype=layers.LINKTYPE_RAW))
    buf = io.BytesIO()
    writer = dpkt.pcapng.Writer(buf, linktype=layers.LINKTYPE_RAW)
    for ts, ip in timed:
        writer.writepkt(ip, ts=ts)
    as_pcapng = pb.write(tmp_path, "same.pcapng", buf.getvalue())
    (_, a), (_, b) = run(as_pcap), run(as_pcapng)
    assert b["capture"]["format"] == "pcapng"
    for key in ("findings", "likely_causes", "conversations", "servers", "summary"):
        assert a[key] == b[key], key
