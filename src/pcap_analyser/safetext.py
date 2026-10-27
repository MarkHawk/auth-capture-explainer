"""Show text from a capture without letting it disturb a terminal or a report.

Values in a capture (user names, DNs, Reply-Message, diagnosticMessage) are
chosen by whoever sent the packet. Anything unprintable is escaped, invalid
UTF-8 is shown as escapes rather than dropped, and long values are cut short
with their full length noted.
"""

MAX_SHOWN = 120  # characters


def text(value, limit=MAX_SHOWN):
    s = value.decode("utf-8", errors="backslashreplace") if isinstance(value, bytes) else value
    s = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in s)
    if limit and len(s) > limit:
        size = f"{len(value)} bytes" if isinstance(value, bytes) else f"{len(value)} characters"
        return s[:limit] + f"... ({size})"
    return s
