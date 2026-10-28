"""Reading .pcap and .pcapng files: every variant the formats allow, files
that are not captures, and files that are cut short, damaged or too big."""

import pytest

import pcapbuild as pb
from auth_capture_explainer import capture, layers
from auth_capture_explainer.capture import CaptureError, Limits, read_capture

RADIUS = b"\x01\x07\x00\x14" + b"A" * 16


def frame(sport=40000):
    return pb.ether(pb.udp(pb.CLIENT, pb.SERVER, sport, 1812, RADIUS))


def three_packets(**kw):
    return pb.pcap([(1000.25, frame(1)), (1001.5, frame(2)), (1002.75, frame(3))], **kw)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_pcap_in_any_byte_order_and_resolution(tmp_path, endian, nano):
    cap = read_capture(pb.write(tmp_path, "a.pcap", three_packets(endian=endian, nano=nano)))
    assert (cap.format, cap.frames, cap.linktypes, cap.notes) == ("pcap", 3, [1], [])
    assert [p.ts for p in cap.packets] == [1000.25, 1001.5, 1002.75]
    assert [p.sport for p in cap.packets] == [1, 2, 3]
    assert (cap.first_ts, cap.last_ts) == (1000.25, 1002.75)


def test_report_name_is_the_file_name_only(tmp_path):
    folder = tmp_path / "customer-ticket"
    folder.mkdir()
    cap = read_capture(pb.write(folder, "auth.pcap", three_packets()))
    assert cap.name == "auth.pcap"


def test_pcap_linux_cooked_v2(tmp_path):
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    data = pb.pcap([(1.0, pb.sll2(ip, 0)), (2.0, pb.sll2(ip, 4))], linktype=layers.LINKTYPE_LINUX_SLL2)
    cap = read_capture(pb.write(tmp_path, "any.pcap", data))
    assert [p.direction for p in cap.packets] == ["in", "out"]


def test_pcap_records_snapshot_cut(tmp_path):
    full = frame()
    data = pb.pcap([(1.0, full[:50], len(full))], snaplen=50)
    p = read_capture(pb.write(tmp_path, "a.pcap", data)).packets[0]
    assert p.truncated


def test_pcapng_interfaces_keep_their_own_link_type_and_clock(tmp_path):
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    data = pb.pcapng(
        pb.idb(layers.LINKTYPE_ETHERNET),  # microseconds
        pb.idb(layers.LINKTYPE_LINUX_SLL2, tsresol=9, tsoffset=100),  # nanoseconds, offset 100 s
        pb.epb(0, 5_000_000, pb.ether(ip)),
        pb.epb(1, 5_000_000_000, pb.sll2(ip, 4)),
    )
    cap = read_capture(pb.write(tmp_path, "a.pcapng", data))
    assert cap.format == "pcapng" and cap.linktypes == [1, 276]
    assert [(p.ts, p.direction) for p in cap.packets] == [(5.0, None), (105.0, "out")]


def test_pcapng_binary_timestamp_resolution(tmp_path):
    data = pb.pcapng(pb.idb(1, tsresol=0x80 | 10), pb.epb(0, 3 * 1024, frame()))  # 1/1024 s
    assert read_capture(pb.write(tmp_path, "a.pcapng", data)).packets[0].ts == 3.0


@pytest.mark.parametrize("flags,direction", [(1, "in"), (2, "out"), (0, None), (0x30 | 2, "out")])
def test_pcapng_packet_direction_flag(tmp_path, flags, direction):
    data = pb.pcapng(pb.idb(1), pb.epb(0, 1, frame(), flags=flags))
    assert read_capture(pb.write(tmp_path, "a.pcapng", data)).packets[0].direction == direction


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_big_and_little_endian(tmp_path, endian):
    data = pb.pcapng(pb.idb(1, endian=endian), pb.epb(0, 2_000_000, frame(), endian=endian), endian=endian)
    assert read_capture(pb.write(tmp_path, "a.pcapng", data)).packets[0].ts == 2.0


def test_pcapng_new_section_resets_interfaces_and_byte_order(tmp_path):
    ip = pb.udp(pb.CLIENT, pb.SERVER, 40000, 1812, RADIUS)
    data = (pb.pcapng(pb.idb(1), pb.epb(0, 1_000_000, pb.ether(ip)))
            + pb.shb(">") + pb.idb(layers.LINKTYPE_RAW, endian=">") + pb.epb(0, 2_000_000, ip, endian=">"))
    cap = read_capture(pb.write(tmp_path, "a.pcapng", data))
    assert cap.linktypes == [1, 101] and [p.ts for p in cap.packets] == [1.0, 2.0]


def test_pcapng_simple_and_obsolete_packet_blocks(tmp_path):
    data = pb.pcapng(pb.idb(1), pb.obsolete_pb(0, 7_000_000, frame(1)), pb.spb(frame(2)))
    cap = read_capture(pb.write(tmp_path, "a.pcapng", data))
    # A simple packet block has no timestamp of its own, so it takes the previous one.
    assert [(p.sport, p.ts) for p in cap.packets] == [(1, 7.0), (2, 7.0)]


def test_pcapng_other_blocks_are_skipped(tmp_path):
    data = pb.pcapng(pb.idb(1, name="eth0"), pb.nrb(), pb.epb(0, 1, frame()))
    cap = read_capture(pb.write(tmp_path, "a.pcapng", data))
    assert cap.frames == 1 and cap.notes == []


def test_pcapng_decryption_secrets_are_noted_and_never_used(tmp_path):
    data = pb.pcapng(pb.idb(1), pb.dsb(), pb.epb(0, 1, frame()))
    cap = read_capture(pb.write(tmp_path, "a.pcapng", data))
    assert len(cap.notes) == 1 and "never decrypts" in cap.notes[0]
    assert "CLIENT_RANDOM" not in cap.notes[0]


def test_skipped_frames_are_counted_by_reason(tmp_path):
    data = pb.pcap([(1, pb.arp()), (2, frame()), (3, b"\x00" * 6), (4, pb.arp()), (5, b"\x01" * 8)])
    cap = read_capture(pb.write(tmp_path, "a.pcap", data))
    assert cap.frames == 5 and len(cap.packets) == 1
    assert cap.ignored == {"not IP": 2}
    assert cap.malformed == {"Ethernet header cut short": 2}
    assert cap.first_malformed == {"Ethernet header cut short": 3}


def test_unsupported_link_type_is_reported_per_frame(tmp_path):
    cap = read_capture(pb.write(tmp_path, "a.pcap", pb.pcap([(1, b"\x00" * 30)], linktype=147)))
    assert cap.linktypes == [147] and cap.ignored == {"link type 147 is not supported": 1}


# --- not a capture ----------------------------------------------------------------

@pytest.mark.parametrize("content,expected", [
    (b"", "empty or too short"),
    (b"\xd4\xc3", "empty or too short"),
    (b"No.  Time  Source  Destination\n1 0.0 ...", "looks like text"),
    (b"\x1f\x8b\x08\x00" + b"\x00" * 20, "gzip"),
    (b"PK\x03\x04" + b"\x00" * 20, "zip"),
    (b"\x34\xcd\xb2\xa1" + b"\x00" * 20, "Kuznetzov"),
    (b"snoop\x00\x00\x00" + b"\x00" * 20, "snoop"),
    (b"GMBU" + b"\x00" * 20, "Network Monitor"),
    (bytes(range(200, 232)), "not recognised"),
])
def test_not_a_capture(tmp_path, content, expected):
    with pytest.raises(CaptureError, match=expected):
        read_capture(pb.write(tmp_path, "x.pcap", content))


def test_missing_file(tmp_path):
    with pytest.raises(CaptureError, match="cannot open missing.pcap"):
        read_capture(tmp_path / "missing.pcap")


def test_pcapng_with_a_bad_byte_order_mark(tmp_path):
    data = bytearray(pb.pcapng(pb.idb(1)))
    data[8:12] = b"\x00\x00\x00\x00"
    with pytest.raises(CaptureError, match="byte-order mark"):
        read_capture(pb.write(tmp_path, "a.pcapng", bytes(data)))


# --- limits ---------------------------------------------------------------------

def test_file_over_the_size_limit_is_refused_before_reading(tmp_path):
    path = pb.write(tmp_path, "big.pcap", three_packets())
    with pytest.raises(CaptureError, match="big.pcap is over the 0 MiB limit"):
        read_capture(path, Limits(max_bytes=100))


def test_packet_limit_stops_with_a_note(tmp_path):
    cap = read_capture(pb.write(tmp_path, "a.pcap", three_packets()), Limits(max_packets=2))
    assert cap.frames == 2 and cap.stopped_early
    assert cap.notes == ["Stopped after 2 packets (the limit); the rest of the file was not read."]


# --- cut short or damaged ----------------------------------------------------------

def test_pcap_cut_short_at_every_point_keeps_whole_packets(tmp_path):
    data = three_packets()
    record = 16 + len(frame())
    for end in range(25, len(data)):
        cap = read_capture(pb.write(tmp_path, "cut.pcap", data[:end]))
        whole = (end - 24) // record
        assert len(cap.packets) == whole, end
        assert cap.notes == ([] if (end - 24) % record == 0 else [capture.CUT_SHORT]), end


def test_pcap_header_cut_short(tmp_path):
    cap = read_capture(pb.write(tmp_path, "cut.pcap", three_packets()[:10]))
    assert cap.frames == 0 and cap.notes == [capture.CUT_SHORT]


def test_pcapng_cut_short_at_every_point_keeps_whole_packets(tmp_path):
    blocks = [pb.idb(1), pb.epb(0, 1, frame(1)), pb.epb(0, 2, frame(2))]
    data = pb.pcapng(*blocks)
    boundaries = {len(pb.shb()) + sum(len(b) for b in blocks[:i]) for i in range(len(blocks) + 1)}
    for end in range(5, len(data)):
        cap = read_capture(pb.write(tmp_path, "cut.pcapng", data[:end]))
        whole = sum(1 for b in boundaries if b <= end) - 2  # minus the SHB-only and SHB+IDB boundaries
        assert len(cap.packets) == max(whole, 0), end
        assert cap.notes == ([] if end in boundaries else [capture.CUT_SHORT]), end


def test_pcap_record_claiming_too_many_bytes(tmp_path):
    data = bytearray(three_packets())
    data[24 + 8:24 + 12] = (capture.MAX_RECORD + 1).to_bytes(4, "little")  # first record's incl_len
    cap = read_capture(pb.write(tmp_path, "a.pcap", bytes(data)))
    assert cap.frames == 0 and "damaged at packet record 1" in cap.notes[0]


def _pcapng_with_second_block(block):
    return pb.pcapng(pb.idb(1), pb.epb(0, 1, frame()), block)


@pytest.mark.parametrize("length", [8, 13, capture.MAX_BLOCK + 4])
def test_pcapng_block_with_an_impossible_length(tmp_path, length):
    bad = (6).to_bytes(4, "little") + length.to_bytes(4, "little") + b"\x00" * 16
    cap = read_capture(pb.write(tmp_path, "a.pcapng", _pcapng_with_second_block(bad)))
    assert len(cap.packets) == 1 and f"a block that claims {length} bytes" in cap.notes[0]


def test_pcapng_block_whose_length_fields_disagree(tmp_path):
    good = bytearray(pb.epb(0, 2, frame()))
    good[-4:] = (len(good) + 4).to_bytes(4, "little")
    cap = read_capture(pb.write(tmp_path, "a.pcapng", _pcapng_with_second_block(bytes(good))))
    assert len(cap.packets) == 1 and "two length fields disagree" in cap.notes[0]


def test_pcapng_packet_claiming_more_data_than_its_block(tmp_path):
    bad = bytearray(pb.epb(0, 2, frame()))
    bad[8 + 12:8 + 16] = (len(bad)).to_bytes(4, "little")  # captured length > what the block holds
    cap = read_capture(pb.write(tmp_path, "a.pcapng", _pcapng_with_second_block(bytes(bad))))
    assert len(cap.packets) == 1 and "claims" in cap.notes[0]


def test_pcapng_packet_for_an_undescribed_interface(tmp_path):
    cap = read_capture(pb.write(tmp_path, "a.pcapng", _pcapng_with_second_block(pb.epb(3, 2, frame()))))
    assert len(cap.packets) == 1 and "interface 3, which the file never described" in cap.notes[0]


def test_pcapng_simple_packet_block_before_any_interface(tmp_path):
    cap = read_capture(pb.write(tmp_path, "a.pcapng", pb.pcapng(pb.spb(frame()))))
    assert cap.frames == 0 and "no interface described" in cap.notes[0]


def test_reading_from_a_stream():
    import io
    cap = capture.read_stream(io.BytesIO(three_packets()))
    assert (cap.name, cap.frames) == ("standard input", 3)


def test_a_stream_over_the_limit_stops_at_the_limit():
    import io

    class Endless(io.RawIOBase):
        read_sizes = []

        def read(self, n=-1):
            self.read_sizes.append(n)
            return b"\xd4" * n

    with pytest.raises(CaptureError, match="standard input is over the 0 MiB limit"):
        capture.read_stream(Endless(), limits=Limits(max_bytes=1000))
    assert Endless.read_sizes == [1001]
