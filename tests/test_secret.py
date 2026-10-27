"""Reading the shared secret: from a file, the environment or a prompt, and
never showing it in a repr, a str or an error message."""

import io

import pytest

from pcap_analyser import secret as sec
from pcap_analyser.secret import Secret, SecretError

VALUE = "canary-shared-secret"


def no_value_in(text):
    return VALUE not in text and VALUE[:8] not in text


def test_repr_and_str_never_show_the_value():
    s = Secret(VALUE.encode(), "file x")
    assert no_value_in(repr(s)) and no_value_in(str(s)) and no_value_in(f"{s}") and no_value_in(f"{s!r}")
    assert repr(s) == "<Secret from file x, hidden>"
    assert s.value == VALUE.encode()


def test_secrets_do_not_compare_by_value():
    a, b = Secret(b"x", "a"), Secret(b"x", "b")
    assert a != b and a == a
    with pytest.raises(TypeError):
        hash(a)


def test_from_file_removes_one_trailing_newline_only(tmp_path):
    for content, expected in ((VALUE + "\n", VALUE), (VALUE + "\r\n", VALUE), (VALUE, VALUE),
                              (VALUE + "\n\n", VALUE + "\n"), (" " + VALUE + " \n", " " + VALUE + " ")):
        path = tmp_path / "secret"
        path.write_text(content, newline="")
        assert sec.from_file(path).value == expected.encode(), repr(content)


def test_from_file_names_the_file_not_its_folder(tmp_path):
    path = tmp_path / "radius.secret"
    path.write_text(VALUE)
    s = sec.from_file(path)
    assert s.source == "file radius.secret"


@pytest.mark.parametrize("content,error", [
    ("", "is empty"),
    ("\n", "is empty"),
    ("x" * (sec.MAX_SECRET + 10), "is it the right file"),
], ids=["empty", "newline-only", "too-big"])
def test_from_file_refuses(tmp_path, content, error):
    path = tmp_path / "secret"
    path.write_text(content)
    with pytest.raises(SecretError, match=error) as e:
        sec.from_file(path)
    assert "xxxxxxxx" not in str(e.value)


def test_from_file_missing(tmp_path):
    with pytest.raises(SecretError, match="cannot read the secret file nope"):
        sec.from_file(tmp_path / "nope")


def test_from_env():
    assert sec.from_env("RS", {"RS": VALUE}).value == VALUE.encode()
    assert sec.from_env("RS", {"RS": VALUE}).source == "environment variable RS"
    with pytest.raises(SecretError, match="RS is not set"):
        sec.from_env("RS", {})
    with pytest.raises(SecretError, match="is empty"):
        sec.from_env("RS", {"RS": ""})


class FakeTty(io.StringIO):
    def isatty(self):
        return True


def test_from_prompt_reads_with_echo_off(monkeypatch):
    asked = []
    monkeypatch.setattr(sec.getpass, "getpass", lambda prompt: asked.append(prompt) or VALUE)
    s = sec.from_prompt(FakeTty())
    assert s.value == VALUE.encode() and s.source == "the prompt" and "not shown" in asked[0]


def test_from_prompt_refuses_without_a_terminal():
    with pytest.raises(SecretError, match="use --secret-file or --secret-env"):
        sec.from_prompt(io.StringIO())


def test_from_prompt_when_nothing_is_entered(monkeypatch):
    def eof(prompt):
        raise EOFError

    monkeypatch.setattr(sec.getpass, "getpass", eof)
    with pytest.raises(SecretError, match="no secret was entered"):
        sec.from_prompt(FakeTty())


def test_whitespace_warnings_never_show_the_value():
    assert Secret(b"plain", "x").warnings() == []
    notes = Secret(b" padded\t", "x").warnings()
    assert len(notes) == 2 and "starts with whitespace" in notes[0] and "ends with whitespace" in notes[1]
    assert all("padded" not in n for n in notes)
