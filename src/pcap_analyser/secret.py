"""Get the RADIUS shared secret without it ever being shown.

Three ways in, so it never has to go on a command line, where it would land
in shell history and the process list:

- prompt: read from the terminal with echo off (--secret, which takes no value). It
  asks on the controlling terminal, so it works while the capture itself
  arrives on standard input;
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


def terminal_available():
    """True if there is a terminal to ask on, even when standard input is a pipe (a capture coming in).
    getpass reads the controlling terminal (/dev/tty) itself; but where there is none it silently falls back
    to standard input, which here may be the capture, so check first. On Windows getpass reads the console."""
    if sys.platform == "win32":
        return True
    try:
        with open("/dev/tty", "rb"):
            return True
    except OSError:
        return False


def from_prompt(terminal=None, prompt="RADIUS shared secret (not shown): "):
    """Ask for the secret on the terminal with echo off. terminal: a stream standing in for the controlling
    terminal, for tests; by default the real one is used, whatever standard input is."""
    there = terminal.isatty() if terminal is not None else terminal_available()
    if not there:
        raise SecretError("--secret asks for the secret on the terminal, and there is no terminal here; "
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
