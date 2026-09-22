"""RFC 6238 TOTP, from the secrets Apple stores in keychain metadata.

Apple keeps the secret two different ways, and both occur in a real keychain: as the raw HMAC
key, and as base32 ASCII (i.e. the text you would have scanned from the QR code, stored
verbatim). Observed lengths on one account were 10, 20, 32 and 190 bytes.

Telling them apart: base32 ASCII is by definition drawn from a 33-character alphabet, so a
value entirely within it is treated as text and decoded. A raw 20-byte key landing entirely
inside that alphabet by chance is about (33/256)**20, which is not worth guarding against.

Stdlib only - hmac and hashlib are all this needs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import struct
import time

_B32_ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")

# Apple stores the digest as a small int. Every item observed used 0, so the non-SHA1 mappings
# follow the conventional ordering and are unverified - a wrong guess yields wrong codes for
# that item only, and no item in this keychain exercises them.
_ALGORITHMS = {0: hashlib.sha1, 1: hashlib.sha256, 2: hashlib.sha512}

DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6


def key_bytes(secret) -> bytes:
    """The HMAC key.

    Apple stores the *decoded* key, always. Verified against its own originalURL on every
    entry that carries one: `stored == b32decode(url secret)` held 14/14, and the base32-text
    reading matched 0/14.

    This used to sniff the bytes and base32-decode anything drawn from that alphabet, which
    silently corrupted every key whose bytes happened to look like base32. A 20- or 32-byte
    random key lands entirely inside that alphabet often enough that it happens in practice,
    and the generated codes were simply wrong. Bytes are now taken as the key, full stop.

    A `str` is still treated as base32 text, since that is the form a human pastes out of an
    otpauth:// URI.
    """
    if isinstance(secret, (bytes, bytearray)):
        return bytes(secret)
    text = str(secret).strip().rstrip("=").upper()
    try:
        return base64.b32decode(text + "=" * (-len(text) % 8), casefold=True)
    except (ValueError, TypeError):
        return str(secret).encode("utf-8")


def code(secret, *, digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
         algorithm: int = 0, at: float | None = None) -> str:
    """The current code. `at` overrides the clock, for tests."""
    period = int(period) or DEFAULT_PERIOD
    digits = int(digits) or DEFAULT_DIGITS
    counter = int((time.time() if at is None else at) // period)
    digest = _ALGORITHMS.get(int(algorithm or 0), hashlib.sha1)
    mac = hmac.new(key_bytes(secret), struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def seconds_remaining(period: int = DEFAULT_PERIOD, at: float | None = None) -> int:
    """How long the current code stays valid - the TUI shows this as a countdown.

    Rounds up, so the result is 1..period and never 0: truncating gives 0 for the last
    fractional second, which reads as expired while the code is still good."""
    period = int(period) or DEFAULT_PERIOD
    now = time.time() if at is None else at
    return math.ceil(period - (now % period)) or period


class SetupError(ValueError):
    pass


_ALGORITHM_NAMES = {"SHA1": 0, "SHA256": 1, "SHA512": 2}


def parse_setup(text: str) -> dict:
    """A verification-code setup, from what a site gives you: an otpauth:// link (what its
    QR code holds) or the bare setup key. Returns {secret(bytes), digits, period, algorithm,
    issuer?, accountName?, originalURL?} in the form Apple stores; raises SetupError.

    Only time-based codes: an HOTP counter cannot be kept in step across devices."""
    import urllib.parse
    raw = (text or "").strip()
    if not raw:
        raise SetupError("paste the setup key or the otpauth:// link")
    if raw.lower().startswith("otpauth://"):
        u = urllib.parse.urlparse(raw)
        if u.netloc.lower() != "totp":
            raise SetupError("only time-based (TOTP) codes are supported")
        q = {k.lower(): v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        label = urllib.parse.unquote(u.path.lstrip("/"))
        issuer, _, account = label.partition(":") if ":" in label else ("", "", label)
        secret_text = q.get("secret", "")
        try:
            digits = int(q.get("digits", DEFAULT_DIGITS))
            period = int(q.get("period", DEFAULT_PERIOD))
        except ValueError:
            raise SetupError("the link's digits or period is not a number") from None
        alg_name = q.get("algorithm", "SHA1").upper()
        if alg_name not in _ALGORITHM_NAMES:
            raise SetupError(f"unsupported algorithm {alg_name}")
        cfg = {"digits": digits, "period": period, "algorithm": _ALGORITHM_NAMES[alg_name],
               "issuer": q.get("issuer") or issuer.strip(), "accountName": account.strip(),
               "originalURL": raw}
    else:
        secret_text, cfg = raw, {"digits": DEFAULT_DIGITS, "period": DEFAULT_PERIOD,
                                 "algorithm": 0}
    compact = "".join(secret_text.split()).rstrip("=").upper()
    if not compact or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for ch in compact):
        raise SetupError("that doesn't look like a setup key (letters A-Z and digits 2-7)")
    try:
        key = base64.b32decode(compact + "=" * (-len(compact) % 8))
    except (ValueError, TypeError):
        raise SetupError("that setup key is not valid base32") from None
    if len(key) < 10:
        raise SetupError("that setup key is too short to be real")
    if cfg["digits"] not in (6, 7, 8) or not 10 <= cfg["period"] <= 300:
        raise SetupError("unusual digits or period - check the link")
    cfg["secret"] = key
    return {k: v for k, v in cfg.items() if v not in ("", None)}
