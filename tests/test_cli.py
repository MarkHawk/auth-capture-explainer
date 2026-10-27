"""The command line: exit codes, every option, the three ways to give the
secret, standard input, limits, and output that never carries the secret."""

import io
import json

import pytest

import ldap_build as lb
import pcapbuild as pb
import radius_sign as sign
from ldap_build import Conversation
from pcap_analyser import __version__
from pcap_analyser import secret as secrets
from pcap_analyser.cli import EXIT_ERROR, EXIT_FAIL, EXIT_NOTHING, EXIT_OK, main
from radius_trace import SERVER_SECRET, Trace, auth_for

SECRET_TEXT = SERVER_SECRET.decode()


def run(*argv, stdin=None, terminal=None):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdin=stdin, stdout=out, stderr=err, terminal=terminal)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def good_login(tmp_path):
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"pw")
    t.reply(1.004, 1, secret=SERVER_SECRET)
    return pb.capture_file(tmp_path, "good.pcap", t)


@pytest.fixture
def no_reply(tmp_path):
    t = Trace()
    for i in range(3):
        t.request(1.0 + 2 * i, 16, secret=b"sample-nas-secret", password=b"pw")
    return pb.capture_file(tmp_path, "silent.pcap", t)


@pytest.fixture
def secret_file(tmp_path):
    path = tmp_path / "radius.secret"
    path.write_text(SECRET_TEXT + "\n")
    return path


# --- exit codes ------------------------------------------------------------------------------

def test_a_clean_capture_exits_0(good_login):
    code, out, err = run(str(good_login))
    assert code == EXIT_OK and err == ""
    assert out.startswith(f"pcap-analyser {__version__}\nCapture:  good.pcap (pcap, raw IP, 2 packets over 4 ms")
    assert "Verdict: no problems found" in out


def test_a_failure_exits_1(no_reply):
    code, out, _ = run(str(no_reply))
    assert code == EXIT_FAIL and "FAIL  Requests unanswered" in out


@pytest.mark.parametrize("make,message", [
    (lambda p: p / "missing.pcap", "cannot open missing.pcap"),
    (lambda p: pb.write(p, "notes.txt", b"just some text, not a capture"), "notes.txt is not a pcap or pcapng"),
    (lambda p: pb.write(p, "empty.pcap", b""), "empty.pcap is empty"),
])
def test_unreadable_input_exits_2(tmp_path, make, message):
    code, out, err = run(str(make(tmp_path)))
    assert code == EXIT_ERROR and out == "" and err.startswith(f"pcap-analyser: {message}")


def test_errors_name_the_file_not_its_folder(tmp_path):
    folder = tmp_path / "private-folder"
    folder.mkdir()
    _, _, err = run(str(folder / "x.pcap"))
    assert "private-folder" not in err


def test_usage_errors_exit_2(capsys):
    for argv in ([], ["x.pcap", "--radius-port", "99999"], ["x.pcap", "--captured-on", "router"],
                 ["x.pcap", "--max-size", "0"], ["x.pcap", "--secret", "--secret-env", "X"]):
        with pytest.raises(SystemExit) as e:
            main(argv, stdout=io.StringIO(), stderr=io.StringIO())
        assert e.value.code == 2, argv


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out == f"pcap-analyser {__version__}\n"


# --- the secret --------------------------------------------------------------------------------

def test_secret_from_a_file(good_login, secret_file):
    code, out, _ = run(str(good_login), "--secret-file", str(secret_file))
    assert code == EXIT_OK and "Secret:   given from file radius.secret (never shown)" in out
    assert "PASS  Shared secret" in out and SECRET_TEXT not in out


def test_secret_from_the_environment(good_login, monkeypatch):
    monkeypatch.setenv("RADIUS_SECRET_FOR_TEST", SECRET_TEXT)
    code, out, _ = run(str(good_login), "--secret-env", "RADIUS_SECRET_FOR_TEST")
    assert code == EXIT_OK and "environment variable RADIUS_SECRET_FOR_TEST" in out and SECRET_TEXT not in out


class Tty(io.StringIO):
    def isatty(self):
        return True


def test_secret_from_the_prompt(good_login, monkeypatch):
    monkeypatch.setattr(secrets.getpass, "getpass", lambda prompt: SECRET_TEXT)
    code, out, _ = run(str(good_login), "--secret", terminal=Tty())
    assert code == EXIT_OK and "given from the prompt" in out and SECRET_TEXT not in out


def test_secret_never_accepted_on_the_command_line(good_login):
    with pytest.raises(SystemExit) as e:
        main([str(good_login), f"--secret={SECRET_TEXT}"], stdout=io.StringIO(), stderr=io.StringIO())
    assert e.value.code == 2


@pytest.mark.parametrize("argv,message", [
    (["--secret-file", "/nonexistent/radius.secret"], "cannot read the secret file radius.secret"),
    (["--secret-env", "NOT_SET_ANYWHERE_X"], "NOT_SET_ANYWHERE_X is not set"),
])
def test_secret_errors_exit_2(good_login, argv, message):
    code, out, err = run(str(good_login), *argv)
    assert code == EXIT_ERROR and out == "" and message in err


def test_prompting_needs_a_terminal(good_login):
    code, _, err = run(str(good_login), "--secret", terminal=io.StringIO())
    assert code == EXIT_ERROR and "use --secret-file or --secret-env" in err


def test_a_wrong_secret_is_reported_without_showing_either_value(good_login, tmp_path):
    wrong = tmp_path / "wrong.secret"
    wrong.write_text("canary-wrong-value")
    code, out, _ = run(str(good_login), "--secret-file", str(wrong), "--json")
    assert code == EXIT_FAIL and "canary" not in out and SECRET_TEXT not in out
    data = json.loads(out)
    assert data["likely_causes"][0]["pattern"] == "radius-secret-unknown"


# --- standard input, ports, context and limits ---------------------------------------------------

def test_reading_standard_input(good_login):
    code, out, _ = run("-", stdin=io.BytesIO(good_login.read_bytes()))
    assert code == EXIT_OK and "Capture:  standard input (pcap" in out


def test_extra_ports(tmp_path):
    t = Trace()
    t.request(1.0, 1, sport=11812)
    t.reply(1.01, 1, sport=11812)
    path = pb.capture_file(tmp_path, "odd-port.pcap", t)
    code, out, _ = run(str(path))
    assert code == EXIT_NOTHING and "Nothing to analyse" in out and "UDP 11812 (2)" in out and "--radius-port" in out
    _, out, _ = run(str(path), "--radius-port", "11812")
    assert "192.0.2.2:11812 (non-standard port) answered" in out


def test_ldap_port_and_service_dn(tmp_path):
    c = Conversation(sport=1389).handshake(1.0)
    c.client_says(1.1, lb.bind_request(1, "cn=thing,dc=example", "x"))
    c.server_says(1.2, lb.bind_response(1, 49))
    path = pb.capture_file(tmp_path, "ldap.pcap", c)
    _, out, _ = run(str(path), "--ldap-port", "1389")
    assert "a bind as cn=thing,dc=example" in out and "--service-dn" in out
    _, out, _ = run(str(path), "--ldap-port", "1389", "--service-dn", "cn=thing,dc=example")
    assert "you named it as a service account" in out and "How sure:  confirmed by the capture" in out


def test_captured_on(no_reply):
    _, out, _ = run(str(no_reply), "--captured-on", "server")
    assert "Taken on: the server, as you said" in out and "You said the capture was taken on the server." in out


def test_reply_window(tmp_path):
    t = Trace()
    t.request(1.0, 1)
    t.raw(3.0, pb.udp(pb.CLIENT, "198.51.100.9", 1, 53, b"x"))  # something later, so the capture lasts 2 s
    path = pb.capture_file(tmp_path, "late.pcap", t)
    assert "Capture ended" in run(str(path))[1]
    assert "Requests unanswered" in run(str(path), "--reply-window", "1.5")[1]


def test_limits(good_login):
    code, _, err = run(str(good_login), "--max-size", "1")
    assert code == EXIT_OK and err == ""
    big = good_login.parent / "big.pcap"
    big.write_bytes(good_login.read_bytes() + b"\x00" * (1024 * 1024 + 10))
    code, _, err = run(str(big), "--max-size", "1")
    assert code == EXIT_ERROR and "over the 1 MiB limit" in err
    _, out, _ = run(str(good_login), "--max-packets", "1")
    assert "Stopped after 1 packets" in out


# --- output -------------------------------------------------------------------------------------

def test_json(no_reply, secret_file):
    code, out, _ = run(str(no_reply), "--secret-file", str(secret_file), "--json")
    data = json.loads(out)
    assert data["schema_version"] == 1 and data["tool"] == "pcap-analyser" and data["version"] == __version__
    assert data["capture"]["name"] == "silent.pcap" and data["capture"]["packets"] == 3
    assert data["options"]["secret_given"] and data["options"]["secret_source"] == "file radius.secret"
    assert {f["check_id"] for f in data["findings"]} >= {"radius.unanswered", "radius.secret"}
    (cause,) = data["likely_causes"]
    assert cause["pattern"] == "radius-secret-mismatch" and cause["runbook_url"].endswith(
        "05-radius-shared-secret-mismatch.md")
    assert data["conversations"][0]["resent"] == 2 and data["summary"]["exit_code"] == code == EXIT_FAIL
    assert SECRET_TEXT not in out and "sample-nas-secret" not in out


def test_no_colour_when_not_a_terminal(no_reply):
    assert "\033[" not in run(str(no_reply))[1]


def test_the_module_runs(good_login):
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-m", "pcap_analyser", str(good_login)], capture_output=True, text=True)
    assert result.returncode == 0 and "Verdict: no problems found" in result.stdout


def test_a_signed_reply_from_the_wrong_secret_end_to_end(tmp_path, secret_file):
    """Runbook 05, step 3, through the whole command line: a legacy server that rejects every password."""
    t = Trace()
    t.request(1.0, 1, secret=SERVER_SECRET, password=b"right")
    t.raw(2.0, pb.udp(pb.SERVER, pb.CLIENT, 1812, 40000, sign.reply(3, 1, auth_for(1), [], b"other-secret")))
    code, out, _ = run(str(pb.capture_file(tmp_path, "legacy.pcap", t)), "--secret-file", str(secret_file))
    flat = " ".join(out.split())
    assert code == EXIT_FAIL
    assert "For 192.0.2.10 (NAS-Identifier \"nas\") to 192.0.2.2:1812: shared secret mismatch, confirmed" in flat
    assert "Its Access-Rejects are not about the users' passwords" in flat
    assert "How sure: confirmed by the capture" in flat


def test_prompting_while_the_capture_comes_in_on_standard_input(good_login, monkeypatch):
    """The secret is asked on the terminal, the capture is read from the pipe: both at once."""
    monkeypatch.setattr(secrets, "terminal_available", lambda: True)
    monkeypatch.setattr(secrets.getpass, "getpass", lambda prompt: SECRET_TEXT)
    code, out, _ = run("-", "--secret", stdin=io.BytesIO(good_login.read_bytes()))
    assert code == EXIT_OK and "given from the prompt" in out and "PASS  Shared secret" in out


def test_no_terminal_at_all_is_refused(good_login, monkeypatch):
    monkeypatch.setattr(secrets, "terminal_available", lambda: False)
    code, _, err = run("-", "--secret", stdin=io.BytesIO(good_login.read_bytes()))
    assert code == EXIT_ERROR and "no terminal here" in err


class Interrupted(io.RawIOBase):
    """Standard input that delivers some bytes, then the user presses Ctrl-C."""

    def __init__(self, data):
        self.data, self.done = data, False

    def readable(self):
        return True

    def read(self, n=-1):
        if self.done:
            raise KeyboardInterrupt
        self.done = True
        return self.data


def test_ctrl_c_while_reading_standard_input_analyses_what_arrived(no_reply):
    code, out, err = run("-", stdin=Interrupted(no_reply.read_bytes()))
    assert code == EXIT_FAIL and err == "" and "Traceback" not in out
    assert "Capture:  standard input (pcap, raw IP, 3 packets over 4.0 s" in out and "stopped early)" in out
    assert "WARN  Capture file" in out and "Reading was interrupted (Ctrl-C)" in " ".join(out.split())
    assert "FAIL  Requests unanswered" in out


def test_standard_input_ending_part_way_through_a_packet(no_reply):
    data = no_reply.read_bytes()
    code, out, _ = run("-", stdin=io.BytesIO(data[:-7]))
    assert code == EXIT_FAIL and "stopped early)" in out and "the capture was cut short" in " ".join(out.split())


def test_ctrl_c_during_the_analysis_exits_cleanly(good_login, monkeypatch):
    from pcap_analyser import cli

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "analyse", interrupted)
    code, out, err = run(str(good_login))
    assert (code, out, err) == (cli.EXIT_INTERRUPTED, "", "pcap-analyser: interrupted\n")


def test_ctrl_c_part_way_through_a_file(good_login, monkeypatch):
    from pcap_analyser import capture, layers

    real = layers.decode

    def decode_then_interrupt(frame, *args):
        if frame == 2:
            raise KeyboardInterrupt
        return real(frame, *args)

    monkeypatch.setattr(capture.layers, "decode", decode_then_interrupt)
    code, out, _ = run(str(good_login))
    assert "stopped early)" in out and "Reading was interrupted (Ctrl-C) after 2 packets" in " ".join(out.split())


def test_nothing_to_analyse_has_its_own_exit_code(tmp_path):
    t = Trace()
    t.raw(1.0, pb.udp(pb.CLIENT, pb.SERVER, 40000, 53, b"q"))
    path = pb.capture_file(tmp_path, "dns.pcap", t)
    code, out, _ = run(str(path))
    assert code == EXIT_NOTHING == 3 and "Verdict: nothing to analyse" in out
    code, out, _ = run(str(path), "--json")
    assert json.loads(out)["summary"]["exit_code"] == 3


def test_the_exit_codes_are_in_the_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "0 no failed checks, 1 at least one FAIL, 2 the capture or the secret could not be read, 3 the capture " \
           "holds no RADIUS or LDAP to analyse, 130 interrupted" in help_text


def test_verbose_flag(tmp_path):
    t = Trace()
    t.health_check(0.5, 1)
    t.request(1.0, 2)
    t.reply(1.01, 2)
    path = pb.capture_file(tmp_path, "h.pcap", t)
    assert "Health checks" in run(str(path))[1]
    assert "Health checks" not in run(str(path), "--verbose")[1]
