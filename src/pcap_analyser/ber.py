"""A small, strict BER decoder: enough for LDAP, and safe on hostile input.

LDAP (RFC 4511) uses a restricted BER: definite lengths only, no indefinite
form, and small tags. This decoder accepts exactly that and refuses the rest
with a BerError, so a crafted message cannot make it allocate, recurse or
loop without bound:

- lengths are definite, at most four length bytes, and checked against the
  bytes actually present before anything is sliced;
- the whole message is capped (MAX_LENGTH) and nesting is capped (MAX_DEPTH);
- integers are capped at eight bytes.

Incomplete is raised, rather than BerError, when the bytes so far are a
valid start but stop short, so a TCP stream reader can wait for more.
"""

from dataclasses import dataclass

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3
INTEGER, OCTET_STRING, NULL, ENUMERATED, SEQUENCE, SET, BOOLEAN = 2, 4, 5, 10, 16, 17, 1

MAX_LENGTH = 16 * 1024 * 1024  # one LDAP message; real ones are far smaller
MAX_DEPTH = 32
MAX_INTEGER_BYTES = 8
MAX_TAG_BYTES = 4


class BerError(ValueError):
    """The bytes are not valid BER (of the kind LDAP uses)."""


class Incomplete(BerError):
    """The bytes are a valid start, but stop before the element ends."""

    def __init__(self, needed):
        super().__init__(f"needs at least {needed} more bytes")
        self.needed = needed


@dataclass(frozen=True)
class Element:
    cls: int  # UNIVERSAL, APPLICATION, CONTEXT or PRIVATE
    constructed: bool
    tag: int
    value: bytes  # the contents
    start: int  # offset of the identifier in the buffer it was read from
    end: int  # offset just past the element

    def is_(self, cls, tag):
        return self.cls == cls and self.tag == tag

    def children(self, depth=0):
        """The elements inside a constructed element."""
        if not self.constructed:
            raise BerError("a primitive element has no children")
        if depth >= MAX_DEPTH:
            raise BerError(f"nested more than {MAX_DEPTH} deep")
        out, pos = [], 0
        while pos < len(self.value):
            try:
                child = read(self.value, pos)
            except Incomplete as e:
                raise BerError("an element runs past the end of the one that contains it") from e
            out.append(child)
            pos = child.end
        return out

    def integer(self):
        return to_integer(self.value)

    def text(self):
        return self.value.decode("utf-8", errors="backslashreplace")


def read(buf, pos=0):
    """The element starting at buf[pos]. Raises Incomplete if buf ends first, BerError if it is invalid."""
    start = pos
    if pos >= len(buf):
        raise Incomplete(1)
    first = buf[pos]
    pos += 1
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    if tag == 0x1F:  # high tag number form
        tag = 0
        for i in range(MAX_TAG_BYTES + 1):
            if pos >= len(buf):
                raise Incomplete(1)
            if i == MAX_TAG_BYTES:
                raise BerError("the tag number is too long")
            b = buf[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if pos >= len(buf):
        raise Incomplete(1)
    n = buf[pos]
    pos += 1
    if n == 0x80:
        raise BerError("indefinite length, which LDAP does not allow")
    if n & 0x80:
        count = n & 0x7F
        if count > 4:
            raise BerError(f"a length of {count} bytes is too long")
        if pos + count > len(buf):
            raise Incomplete(pos + count - len(buf))
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    else:
        length = n
    if length > MAX_LENGTH:
        raise BerError(f"an element of {length} bytes is over the {MAX_LENGTH}-byte limit")
    if pos + length > len(buf):
        raise Incomplete(pos + length - len(buf))
    return Element(cls, constructed, tag, bytes(buf[pos:pos + length]), start, pos + length)


def to_integer(value):
    if not value:
        raise BerError("an empty integer")
    if len(value) > MAX_INTEGER_BYTES:
        raise BerError(f"an integer of {len(value)} bytes is too long")
    return int.from_bytes(value, "big", signed=True)


def expect(element, cls, tag, what):
    """element, if it has this class and tag; BerError naming what was expected otherwise."""
    if not element.is_(cls, tag):
        raise BerError(f"expected {what}")
    return element
