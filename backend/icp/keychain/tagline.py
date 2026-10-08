"""Per-entry tags, kept as the last line of an entry's notes:

    Tags: #work #finance #side-project

Apple has no user-assigned categories that sync. Notes do, and this line shows on every Apple
device as ordinary note text, so it is the one per-entry, multi-valued category that stays in
iCloud Passwords. Pear reads it as list metadata (tier 1) and writes it only on a tag edit.

Parsing is tolerant and writing is canonical:

    tagline = [WS] "Tags" ":" WS1 tag *(WS1 tag) [WS]     "Tags" ASCII, any case
    tag     = "#" 1..32 of (Unicode L*, M*, N*, "_", "-")
    WS/WS1  = [ \\t]* / [ \\t]+

A tag cannot hold whitespace, "#", ":", a comma or a control character, so nothing ever needs
escaping. A line with one bad token, more than 16 tags or a tag over 32 characters is not a
tag line: it stays in the body as it is, and Pear never "repairs" a line it did not write. Only
the final line counts; the same text anywhere else is body text.

Every function here is pure: no I/O, no logging, nothing about who calls it.
"""

from __future__ import annotations

import unicodedata

LABEL = "Tags"
MAX_TAGS = 16
MAX_TAG_CHARS = 32
_WS = " \t"


def fold(tag: str) -> str:
    """The comparison key: "#Straße" and "#STRASSE" are one tag, so are "#ｗｏｒｋ" and "#work"."""
    return unicodedata.normalize("NFKC", tag).casefold()


def _tagchar(ch: str) -> bool:
    return ch in "_-" or unicodedata.category(ch)[0] in "LMN"


def canon(tag) -> str | None:
    """The canonical (display and write) form of one tag without its "#": NFC, lower case.
    None when it breaks the grammar."""
    if not isinstance(tag, str) or not tag:
        return None
    if not all(_tagchar(ch) for ch in tag):
        return None
    out = unicodedata.normalize("NFC", unicodedata.normalize("NFC", tag).lower())
    if not 1 <= len(out) <= MAX_TAG_CHARS or not all(_tagchar(ch) for ch in out):
        return None
    return out


def canon_list(tags) -> list[str]:
    """Canonical tags from a client: strings with or without one leading "#", de-duplicated
    by fold key (the first one wins), in the order given. ValueError on anything the grammar
    refuses, and on more than MAX_TAGS."""
    if not isinstance(tags, (list, tuple)) or len(tags) > MAX_TAGS:
        raise ValueError("tags is a list of at most 16 strings")
    out, seen = [], set()
    for t in tags:
        if not isinstance(t, str):
            raise ValueError("a tag is a string")
        c = canon(t[1:] if t.startswith("#") else t)
        if c is None:
            raise ValueError("a tag is 1 to 32 letters, digits, marks, '_' or '-'")
        if fold(c) not in seen:
            seen.add(fold(c))
            out.append(c)
    return out


def line(tags) -> str:
    """The canonical tag line for already-canonical `tags` ("" for none)."""
    return f"{LABEL}: " + " ".join("#" + t for t in tags) if tags else ""


def parse_line(text: str) -> list[str] | None:
    """The canonical tags of one line, or None when it is not a tag line. One trailing "\\r"
    is allowed (the line of a CRLF note)."""
    s = text[:-1] if text.endswith("\r") else text
    s = s.lstrip(_WS)
    head = s[:len(LABEL) + 1]
    if not head.isascii() or head.lower() != LABEL.lower() + ":":
        return None
    rest = s[len(LABEL) + 1:]
    if not rest or rest[0] not in _WS:
        return None
    tokens = rest.strip(_WS).replace("\t", " ").split(" ")
    tokens = [t for t in tokens if t]
    if not tokens or len(tokens) > MAX_TAGS:
        return None
    out, seen = [], set()
    for tok in tokens:
        if not tok.startswith("#"):
            return None
        c = canon(tok[1:])
        if c is None:
            return None
        if fold(c) not in seen:
            seen.add(fold(c))
            out.append(c)
    return out


def _parts(raw: str):
    """(body, sep, line, tags) with raw == body + sep + line, or None without a tag line.

    `line` is everything after the last "\\n" (with its trailing "\\r", if any). `sep` is the
    newline before it plus at most one more line break: exactly what compose() adds (a blank
    line) or a single newline typed on an Apple device."""
    idx = raw.rfind("\n")
    cand = raw[idx + 1:]
    tags = parse_line(cand)
    if tags is None:
        return None
    if idx < 0:
        return "", "", cand, tags
    body = raw[:idx]
    if body.endswith("\r"):
        body = body[:-1]
    if body.endswith("\n"):
        body = body[:-1]
        if body.endswith("\r"):
            body = body[:-1]
    return body, raw[len(body):idx + 1], cand, tags


def split(raw: str) -> tuple[str, list[str]]:
    """(body, tags). Notes without a tag line are all body; notes that are only the line give
    ("", tags)."""
    p = _parts(raw or "")
    if p is None:
        return raw or "", []
    return p[0], p[3]


def _sep(body: str) -> str:
    """CRLF for a CRLF-only body, else LF. A body ending in a lone "\\r" also gets CRLF: an LF
    after it would read back as one CRLF and eat that "\\r"."""
    if body.endswith("\r"):
        return "\r\n"
    return "\r\n" if "\r\n" in body and "\n" not in body.replace("\r\n", "") else "\n"


def compose(body: str, tags) -> str:
    """Notes from a body and canonical tags: the line goes last, after one blank line."""
    if not tags:
        return body
    if not body:
        return line(tags)
    sep = _sep(body)
    return body + sep + sep + line(tags)


def replace_tags(raw: str, tags) -> str:
    """`raw` with its tags set to canonical `tags`. An existing line is replaced on its own,
    keeping the separator before it byte for byte; no tags removes it with that separator.
    Without a line, compose(raw, tags)."""
    raw = raw or ""
    p = _parts(raw)
    if p is None:
        return compose(raw, tags)
    body, sep, _, _ = p
    if not tags:
        return body
    return body + sep + line(tags)


def replace_body(raw: str, body: str) -> str:
    """`raw` with its body replaced and its tag line (bytes and separator) kept: a body edit
    can never drop the tags."""
    raw = raw or ""
    p = _parts(raw)
    if p is None:
        return body
    _, sep, cand, tags = p
    if not body:
        return cand
    out = body + sep + cand
    if sep and split(out) == (body, tags):
        return out
    # No separator to keep (the notes were only the line), or the new body ends in a line
    # break the kept one would merge with: use compose's blank line, which always reads back.
    s = _sep(body)
    return body + s + s + cand
