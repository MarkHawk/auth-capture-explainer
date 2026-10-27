"""Small helpers for writing findings in plain English."""

MAX_NAMES = 3  # things named in one sentence before "and N more"


def plural(n, word, plural_form=None):
    """e.g. "1 reply", "3 replies"."""
    return f"{n} {word if n == 1 else (plural_form or word + 's')}"


def times(n):
    return {1: "once", 2: "twice"}.get(n, f"{n} times")


def listing(values, quote=True):
    """e.g. '"dave", "erin" and 2 more', without repeats or empty values."""
    values = list(dict.fromkeys(v for v in values if v))
    shown = [f'"{v}"' if quote else v for v in values[:MAX_NAMES]]
    if len(values) > MAX_NAMES:
        shown.append(f"{len(values) - MAX_NAMES} more")
    if len(shown) <= 1:
        return "".join(shown)
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def secs(s):
    """A duration, e.g. "under 1 ms", "12 ms", "1.5 s"."""
    if s is None:
        return "-"
    if s < 0.001:
        return "under 1 ms"
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"


def article(word):
    return "an" if word[:1].upper() in "AEIOU" else "a"
