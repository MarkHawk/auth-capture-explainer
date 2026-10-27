"""Get the RADIUS shared secret without it ever being shown.

Three ways in, so it never has to go on a command line, where it would land
in shell history and the process list:

- prompt: read from the terminal with echo off (--secret with no value);
- file: read from a file (--secret-file), one trailing newline removed;
- env: read from a named environment variable (--secret-env).

The value is held in a Secret, whose repr and str never include it, so a
traceback, a log line or a debug print cannot show it. Errors name where
the secret was to come from, never what was read.

The only things said about the value itself are those that explain a
mismatch without revealing it: that it is empty, or that it starts or ends
with whitespace (a classic cause of secrets that look identical but are not).
"""

import getpass
import os
import pathlib
import sys

MAX_SECRET = 1024  # bytes; real RADIUS secrets are far shorter, so anything bigger is the wrong file


class SecretError(ValueError):
    """The secret could not be read. The message never contains the value."""


class Secret:
    __slots__ = ("_value", "source")

    def __init__(self, value, source):
        if not isinstance(value, bytes):
            raise TypeError("Secret takes bytes")
        self._value = value
        self.source = source  # e.g. "prompt", "file", "environment variable RADIUS_SECRET"

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return f"<Secret from {self.source}, hidden>"

    __str__ = __repr__

    def __eq__(self, other):  # no comparisons that a test failure could print the value from
        return NotImplemented

    __hash__ = None

    def warnings(self):
        """Remarks about the secret's shape that may explain a mismatch, without its value."""
        notes = []
        if self._value != self._value.lstrip():
            notes.append("The secret you gave starts with whitespace; the other side may not have it.")
        if self._value != self._value.rstrip():
            notes.append("The secret you gave ends with whitespace; the other side may not have it.")
        return notes


def _check(value, source):
    if not value:
        raise SecretError(f"the secret from {source} is empty")
    if len(value) > MAX_SECRET:
        raise SecretError(f"the secret from {source} is over {MAX_SECRET} bytes; is it the right file?")
    return Secret(value, source)


def from_prompt(stream=None, prompt="RADIUS shared secret (not shown): "):
    """Read the secret from the terminal with echo off. Refuses when there is no terminal to ask."""
    stream = stream if stream is not None else sys.stdin
    if not stream.isatty():
        raise SecretError("--secret asks for the secret on the terminal, and there is none here; "
                          "use --secret-file or --secret-env instead")
    try:
        typed = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt) as e:
        raise SecretError("no secret was entered") from e
    return _check(typed.encode("utf-8"), "the prompt")


def from_file(path):
    path = pathlib.Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_SECRET + 2:
            raise SecretError(f"the secret file {path.name} is {size} bytes; is it the right file?")
        data = path.read_bytes()
    except OSError as e:
        raise SecretError(f"cannot read the secret file {path.name}: {e.strerror or type(e).__name__}") from None
    for ending in (b"\r\n", b"\n"):
        if data.endswith(ending):
            data = data[:-len(ending)]
            break
    return _check(data, f"file {path.name}")


def from_env(name, environ=None):
    environ = os.environ if environ is None else environ
    if name not in environ:
        raise SecretError(f"the environment variable {name} is not set")
    return _check(environ[name].encode("utf-8"), f"environment variable {name}")
