"""Reading a 1.x vault, once, inside the daemon. This module never unlinks or writes anything:
it is handed bytes and returns plaintext.

What 1.x wrote under ~/.config/icp, all as `nacl.secret.SecretBox(key).encrypt(json)` (24-byte
nonce prefix, XSalsa20-Poly1305) with one 32-byte key:

    vault.enc       {"credentials": [Credential.storage_dict(), ...]}
    history.enc     {"accounts": {"<domain>\\x1f<username>": [{at, source, old, new, title}]}}
    nicknames.enc   {"names": {"<domain>\\x1f<username>": "<nickname>"}}
    aliases.enc     {"aliases": [HmeAlias as a dict, ...]}
    session.enc     the session dict
    check.enc       SecretBox(key).encrypt(b"icp-lockbox-v1")
    kdf.json        plaintext {"salt": hex, "opslimit", "memlimit", "alg": "argon2id"}
    device.json     plaintext device identity

The key is Argon2id(passphrase, kdf.json) - the lockbox key, which 1.3.x's agent held in
memory. 2.0 gets it either by PEEKing that agent (the importer does that, as the user) or by
deriving it here from the passphrase typed once into the Pear window.

to_canonical() turns the plaintext into the 2.0 model the importer writes, and is also the
"own figures" the converted store is checked against: counts and a SHA-256 over canonical JSON.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import json
from dataclasses import dataclass, field

import nacl.exceptions
import nacl.pwhash
import nacl.secret

from .. import totp as _otp
from . import ImportMismatch, Meta, Secrets
from . import entries as _entries
from . import format as fmt
from . import meta as _meta
from .ids import assign_ids, entry_id

KEY_BYTES = nacl.secret.SecretBox.KEY_SIZE
CHECK_PLAINTEXT = b"icp-lockbox-v1"

# 1.x wrote MODERATE (256 MiB). The bounds stop a planted kdf.json from making the daemon
# allocate gigabytes or spin for minutes; nothing 1.x ever wrote is outside them.
DEFAULT_OPS = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
DEFAULT_MEM = nacl.pwhash.argon2id.MEMLIMIT_MODERATE
OPS_RANGE = (nacl.pwhash.argon2id.OPSLIMIT_MIN, nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE)
MEM_RANGE = (nacl.pwhash.argon2id.MEMLIMIT_MIN, nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE)

ENCRYPTED = ("vault.enc", "history.enc", "nicknames.enc", "aliases.enc", "session.enc")
SOURCE_LOCAL = "local"


# --- the key ---------------------------------------------------------------------------------

def parse_kdf(kdf_json: bytes) -> tuple[bytes, int, int]:
    """(salt, opslimit, memlimit) from kdf.json. ValueError on anything 1.x would not write."""
    try:
        params = json.loads(bytes(kdf_json).decode("utf-8"))
        salt = bytes.fromhex(params["salt"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        raise ValueError("kdf.json is not a 1.x Argon2id parameter file") from None
    if not isinstance(params, dict) or params.get("alg", "argon2id") != "argon2id":
        raise ValueError("kdf.json is not for Argon2id")
    if len(salt) != nacl.pwhash.argon2id.SALTBYTES:
        raise ValueError("kdf.json salt has the wrong length")
    ops = params.get("opslimit", DEFAULT_OPS)
    mem = params.get("memlimit", DEFAULT_MEM)
    for v, (lo, hi) in ((ops, OPS_RANGE), (mem, MEM_RANGE)):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError("kdf.json limits are out of range")
    return salt, ops, mem


def key_from_passphrase(kdf_json: bytes, passphrase: str) -> bytes:
    salt, ops, mem = parse_kdf(kdf_json)
    if not isinstance(passphrase, str):
        raise ValueError("passphrase is text")
    return nacl.pwhash.argon2id.kdf(KEY_BYTES, passphrase.encode("utf-8"), salt,
                                    opslimit=ops, memlimit=mem)


def key_opens(check_enc: bytes, key: bytes) -> bool:
    """libsodium's MAC check is constant-time, and so is the comparison after it."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        return False
    try:
        plain = nacl.secret.SecretBox(bytes(key)).decrypt(bytes(check_enc))
    except (nacl.exceptions.CryptoError, TypeError, ValueError):
        return False
    return hmac.compare_digest(plain, CHECK_PLAINTEXT)


# --- the files -------------------------------------------------------------------------------

@dataclass
class V1Vault:
    credentials: list = field(default_factory=list)
    history: dict = field(default_factory=dict)
    nicknames: dict = field(default_factory=dict)
    aliases: list = field(default_factory=list)
    session: dict = field(default_factory=dict)
    device: dict = field(default_factory=dict)


def _open(files: dict, name: str, key: bytes, field_name: str, typ, default):
    blob = files.get(name)
    if blob is None:
        return default
    try:
        doc = json.loads(nacl.secret.SecretBox(key).decrypt(bytes(blob)).decode("utf-8"))
    except (nacl.exceptions.CryptoError, UnicodeDecodeError, ValueError, TypeError):
        raise ImportMismatch(f"{name} does not open with the key that opens check.enc") \
            from None
    if field_name is None:
        value = doc
    else:
        value = doc.get(field_name, default) if isinstance(doc, dict) else None
    if not isinstance(value, typ):
        raise ImportMismatch(f"{name} has an unexpected shape")
    return value


def read(files: dict, key: bytes) -> V1Vault:
    """Decrypt every v1 file present. The caller has already checked `key` with key_opens."""
    key = bytes(key)
    v = V1Vault(
        credentials=_open(files, "vault.enc", key, "credentials", list, []),
        history=_open(files, "history.enc", key, "accounts", dict, {}),
        nicknames=_open(files, "nicknames.enc", key, "names", dict, {}),
        aliases=_open(files, "aliases.enc", key, "aliases", list, []),
        session=_open(files, "session.enc", key, None, dict, {}),
    )
    if files.get("device.json") is not None:
        try:
            dev = json.loads(bytes(files["device.json"]).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ImportMismatch("device.json is not JSON") from None
        if not isinstance(dev, dict):
            raise ImportMismatch("device.json has an unexpected shape")
        v.device = dev
    if not all(isinstance(c, dict) for c in v.credentials) \
            or not all(isinstance(a, dict) for a in v.aliases):
        raise ImportMismatch("vault.enc or aliases.enc has an unexpected shape")
    return v


# --- conversion ------------------------------------------------------------------------------

def iso(ts) -> str:
    """Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`; the epoch for anything unusable."""
    try:
        t = float(ts)
        return datetime.datetime.fromtimestamp(t, datetime.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return "1970-01-01T00:00:00Z"


def _totp_parts(t) -> tuple[bytes | None, dict]:
    """(raw seed, params) from a 1.x `totp` dict: hex when `secret_hex`, base32 text when a
    plain string (icp.totp.key_bytes's rule), raw bytes otherwise."""
    if not isinstance(t, dict) or not t.get("secret"):
        return None, {}
    s = t["secret"]
    if t.get("secret_hex") and isinstance(s, str):
        try:
            seed = bytes.fromhex(s)
        except ValueError:
            raise ImportMismatch("vault.enc holds a TOTP secret that is not hex") from None
    else:
        seed = _otp.key_bytes(s)
    params = {"digits": int(t.get("digits") or 6), "period": int(t.get("period") or 30),
              "algorithm": int(t.get("algorithm") or 0)}
    if t.get("issuer"):
        params["issuer"] = str(t["issuer"])
    return seed, params


def credential_parts(c: dict) -> tuple[Meta, Secrets]:
    """One 1.x storage_dict as the 2.0 (Meta, Secrets) pair. `id` and `nickname` are left for
    the caller: the id depends on the rest of the batch, the nickname lives elsewhere."""
    seed, params = _totp_parts(c.get("totp"))
    notes = str(c.get("notes") or "")
    secrets = Secrets(
        password=str(c.get("password") or ""), notes=notes, totp_secret=seed,
        apple_history=[{"date": iso(h.get("at")), "value": str(h.get("password"))}
                       for h in (c.get("apple_history") or [])
                       if isinstance(h, dict) and h.get("password") is not None],
        totp_params=params)
    m = Meta(id="", title=str(c.get("title") or ""), domain=str(c.get("domain") or ""),
             sites=[str(s) for s in (c.get("sites") or [])],
             username=str(c.get("username") or ""), nickname="", has_totp=seed is not None,
             has_notes=bool(notes), mdat=_num(c.get("mdat")), history_count=0,
             apple_title=str(c.get("apple_title") or ""),
             aliases=[str(a) for a in (c.get("aliases") or [])])
    return m, secrets


def canonical_secrets(s: Secrets) -> dict:
    """The comparison form of an entry's secrets: exactly what its box stores minus id/v."""
    p = _entries.to_payload("x", 0, s)
    del p["id"], p["v"]
    return p


def _num(v) -> float:
    if v is None or isinstance(v, bool):
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ImportMismatch("a v1 date is not a number") from None


def _split_account(key: str) -> tuple[str, str]:
    domain, _, username = key.partition("\x1f")
    return domain, username


def to_canonical(v1: V1Vault) -> dict:
    """The 2.0 model of a v1 vault:

        {"entries": {id: {"meta": {...}, "secrets": {...}|null, "deleted": bool,
                          "history": [[at, source, value], ...] oldest first}},
         "nicknames": {id: name}, "aliases": [...], "session": {...}, "device": {...}}

    History for an account that is no longer in the vault is kept on a tombstoned entry, so
    nothing 1.x remembered is dropped; it reappears if the account comes back."""
    parts = [credential_parts(c) for c in v1.credentials]
    ids = assign_ids((m.domain, m.username) for m, _ in parts)
    out_entries: dict = {}
    for id, (m, s) in zip(ids, parts):
        out_entries[id] = {"meta": _meta.fields_from(m), "secrets": canonical_secrets(s),
                           "deleted": False, "history": []}

    for account, items in v1.history.items():
        if not isinstance(account, str) or not isinstance(items, list):
            raise ImportMismatch("history.enc has an unexpected shape")
        domain, username = _split_account(account)
        id = entry_id(domain, username)
        hist = [[_num(e.get("at")), SOURCE_LOCAL, e["old"]] for e in items
                if isinstance(e, dict) and isinstance(e.get("old"), str)]
        if not hist:
            continue
        hist.sort(key=lambda h: h[0])                       # 1.x kept newest first
        hist = hist[-_entries.MAX_HISTORY:]
        if id not in out_entries:
            stub = Meta(id=id, title="", domain=domain, sites=[], username=username,
                        nickname="", has_totp=False, has_notes=False, mdat=0.0,
                        history_count=0)
            out_entries[id] = {"meta": _meta.fields_from(stub), "secrets": None,
                               "deleted": True, "history": []}
        out_entries[id]["history"] = hist

    nicknames = {}
    for account, name in v1.nicknames.items():
        if isinstance(account, str) and isinstance(name, str) and name:
            nicknames[entry_id(*_split_account(account))] = name

    return {"entries": out_entries, "nicknames": nicknames, "aliases": list(v1.aliases),
            "session": dict(v1.session), "device": dict(v1.device)}


def counts(canon: dict) -> dict:
    ents = canon["entries"].values()
    return {"credentials": sum(1 for e in ents if not e["deleted"]),
            "history": sum(len(e["history"]) for e in ents),
            "nicknames": len(canon["nicknames"]), "aliases": len(canon["aliases"]),
            "session_keys": len(canon["session"])}


def digest(canon: dict) -> str:
    return hashlib.sha256(fmt.dumps(canon)).hexdigest()


def secrets_from_canonical(d: dict) -> Secrets:
    seed = d.get("totp_secret")
    try:
        return Secrets(password=d["password"], notes=d["notes"],
                       totp_secret=base64.b64decode(seed, validate=True) if seed else None,
                       apple_history=list(d["apple_history"]),
                       totp_params=dict(d["totp_params"]))
    except (KeyError, binascii.Error, TypeError) as e:
        raise ImportMismatch(f"internal conversion error ({type(e).__name__})") from None
