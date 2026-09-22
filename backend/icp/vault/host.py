"""Native-messaging host for the browser autofill extension. Speaks Chrome's native-messaging
protocol on stdin/stdout (4-byte LE length prefix + UTF-8 JSON) and answers domain queries from
the decrypted vault, read-only.

Protocol (JSON):
  -> {"cmd":"ping"}                              <- {"ok":true,"count":N}
  -> {"cmd":"match","domain":"login.example.com"} <- {"ok":true,"credentials":[{...}]}
  -> {"cmd":"totp","domain":"x","username":"y"}   <- {"ok":true,"code":"123456","seconds":23}
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import re
import struct
import sys


@dataclasses.dataclass(frozen=True)
class Credential:
    domain: str
    username: str
    password: str
    title: str = ""
    # Unix epoch seconds of the item's last change (keychain `mdat`, falling back to `cdat`);
    # 0 when unknown. Used to sort newest-first and to render a "last used N ago" line.
    mdat: float = 0.0
    # TOTP configuration lifted from the account's metadata item, or None. Kept as the raw
    # Apple form; icp.totp handles raw-vs-base32 and generates the code.
    totp: dict | None = None
    notes: str = ""
    # Apple's own password history from the entry's metadata record, newest first. Empty for
    # the many items Apple's Passwords app does not manage - those rely on our sync journal.
    apple_history: tuple = ()
    # The name given to this entry in Apple's Passwords app, synced from its metadata record.
    apple_title: str = ""
    # Extra domains this credential is offered on, inferred from metadata stubs that name the
    # same account but have no password item of their own. Apple stores no pointer we can
    # follow, so this is an inference, not a fact - see aliases_are_inferred in the picker.
    aliases: tuple = ()
    # Extra websites stored on the entry itself (metadata `s_as`). Unlike `aliases`, these are
    # a fact Apple records, and they are what the user edits.
    sites: tuple = ()

    def storage_dict(self) -> dict:
        """Everything, for the on-disk vault (encrypted)."""
        d = {"domain": self.domain, "username": self.username, "password": self.password,
             "title": self.title, "mdat": self.mdat, "notes": self.notes,
             "aliases": list(self.aliases),
             "apple_history": [dict(h) for h in (self.apple_history or ())],
             "apple_title": self.apple_title, "sites": list(self.sites)}
        if self.totp:
            t = dict(self.totp)
            s = t.get("secret")
            # plist gives bytes; JSON cannot hold them, so store hex and mark it.
            if isinstance(s, (bytes, bytearray)):
                t["secret"] = bytes(s).hex()
                t["secret_hex"] = True
            d["totp"] = t
        return d

    def public_dict(self) -> dict:
        """What crosses the native-messaging socket to the browser.

        The TOTP *secret* deliberately never leaves this process - a compromised extension
        would otherwise walk away with a permanent second factor rather than one 30-second
        code. Only the fact that a code exists is exposed; the CLI generates it locally."""
        return {"domain": self.domain, "username": self.username,
                "password": self.password, "title": self.title, "mdat": self.mdat,
                "has_totp": bool(self.totp), "aliases": list(self.aliases)}

    def totp_code(self):
        """(code, seconds_remaining) or None."""
        if not self.totp:
            return None
        from .. import totp as _totp
        secret = self.totp.get("secret")
        if self.totp.get("secret_hex") and isinstance(secret, str):
            secret = bytes.fromhex(secret)
        return (_totp.code(secret, digits=self.totp.get("digits", 6),
                           period=self.totp.get("period", 30),
                           algorithm=self.totp.get("algorithm", 0)),
                _totp.seconds_remaining(self.totp.get("period", 30)))


_APPLE_EPOCH = 978307200  # 2001-01-01 UTC in unix seconds (Apple "absolute time" origin)


def _to_unix(value) -> float:
    """Best-effort convert a keychain date (`mdat`/`cdat`) to unix epoch seconds; 0 if unknown.
    plistlib yields a datetime for binary-plist <date>; a CKKS dateValue arrives as `CKDate`;
    a bare number is Apple absolute time (secs since 2001) when small, already-unix when large."""
    if isinstance(value, datetime.datetime):
        return value.timestamp()
    value = getattr(value, "time", value)  # ckks.CKDate -> its .time (unix seconds)
    if isinstance(value, (int, float)) and value > 0:
        return float(value) + _APPLE_EPOCH if value < 1e9 else float(value)
    return 0.0


def _normalize_host(value: str) -> str:
    """Reduce a URL or host to a bare lowercase hostname (strip scheme/port/path/leading www)."""
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0]
    v = v.split("@")[-1]          # strip userinfo
    v = v.split(":", 1)[0]        # strip port
    if v.startswith("www."):
        v = v[4:]
    return v


def domains_match(page: str, stored: str) -> bool:
    """True if a stored item's domain should autofill on `page`.

    Matches exact host, and either being a sub-domain of the other (so `example.com` fills on
    `login.example.com` and vice-versa). Conservative: requires a dotted-boundary suffix so
    `notexample.com` never matches `example.com`.
    """
    p, s = _normalize_host(page), _normalize_host(stored)
    if not p or not s:
        return False
    if p == s:
        return True
    return p.endswith("." + s) or s.endswith("." + p)


def match_aliases(page_domain: str, aliases: list) -> list:
    """Hide My Email aliases (icp.hme.client.HmeAlias) whose recorded domain matches the
    page, same domains_match() rule as Credential. Duck-typed on `.domain` rather than
    importing HmeAlias - vault/ stays free of any import from the hme/ extension."""
    return [a for a in aliases if a.domain and domains_match(page_domain, a.domain)]


def _is_credential(domain: str, title: str) -> bool:
    """False for the non-login records iCloud Keychain also syncs: Protected Cloud Storage service
    blobs (label "PCS com.apple.*", whose `acct` is a base64 key) and per-site "Website Metadata"
    records. Checks the final domain/title so the marker is caught wherever it lands; real web
    logins are reverse-DNS free and never carry these names."""
    for tag in (domain, title):
        t = (tag or "").strip().lower()
        if t.startswith(("pcs ", "pcs-", "website metadata")) or "com.apple." in t:
            return False
    return True


_GENERIC_NAME_TOKENS = {
    "account", "accounts", "admin", "app", "dashboard", "login", "password", "passwords",
    "signin", "sign", "web", "www",
}


def _name_matches_host(page: str, name: str) -> bool:
    """Fallback for Passwords entries that decrypt as generic items with only a saved label.

    The iOS Passwords app can show a useful account name (for example "Cloudflare") even when
    the decrypted item has no `srvr` host. Match only whole hostname labels so this stays much
    narrower than substring matching.
    """
    labels = {label for label in _normalize_host(page).split(".") if label}
    if not labels:
        return False
    tokens = {
        token for token in re.findall(r"[a-z0-9]+", name.lower())
        if len(token) >= 4 and token not in _GENERIC_NAME_TOKENS
    }
    return bool(labels & tokens)


class CredentialStore:
    """In-memory read-only store. The pipeline builds this from decrypted keychain items."""

    def __init__(self, credentials=None):
        self._creds: list[Credential] = list(credentials or [])

    def __len__(self) -> int:
        return len(self._creds)

    def all(self) -> list["Credential"]:
        return list(self._creds)

    def match(self, page_domain: str) -> list[Credential]:
        def match_rank(c: Credential) -> int | None:
            if not _is_credential(c.domain, c.title):  # filters an older, unfiltered vault too
                return None
            if domains_match(page_domain, c.domain):
                return 0 if _normalize_host(page_domain) == _normalize_host(c.domain) else 1
            stored = _normalize_host(c.domain)
            if ("." not in stored) and _name_matches_host(page_domain, c.title or c.domain):
                return 2
            # Inferred aliases rank last: they come from a metadata stub naming this account at
            # that domain, not from a stored pointer, so a real match must always win.
            if any(domains_match(page_domain, a) for a in c.aliases):
                return 3
            return None

        ranked = [(rank, c) for c in self._creds if (rank := match_rank(c)) is not None]
        # exact-host matches first, then parent/subdomain, then label-only fallbacks; within a
        # tier, most-recently-used first (newest `mdat`), then title for a stable order.
        ranked.sort(key=lambda rc: (rc[0], -rc[1].mdat, rc[1].title, rc[1].username))
        return [c for _, c in ranked]

    @classmethod
    def from_items(cls, items) -> "CredentialStore":
        """Build from decrypted keychain item dicts (plist form). Apple `inet` password items use
        `srvr` (server/domain), `acct` (username), `v_Data` (plaintext password), `labl` (title);
        tolerate the common variants."""
        from ..keychain import metadata as _meta

        def _key(it):
            return (str(it.get("srvr") or it.get("server") or it.get("domain")
                        or it.get("url") or it.get("svce") or ""),
                    str(it.get("acct") or it.get("username") or it.get("user") or ""))

        # Pass 1. Apple stores per-account attributes in a sibling item whose v_Data is a
        # binary plist, not a password. Upstream treated those as logins, so a third of the
        # vault had "bplist00..." as its password and the extension would have typed it into
        # a form. Index them by (domain, account) and keep them out of the credential list.
        extras = {}
        # (domain, account) pairs that a metadata stub names but no password item occupies.
        stub_domains = {}
        pw_keys = set()
        for it in items:
            if not _meta.is_metadata(it.get("v_Data")):
                pw_keys.add(_key(it))
        for it in items:
            meta = _meta.parse(it.get("v_Data"))
            if meta is None:
                continue
            k = _key(it)
            if k not in pw_keys and k[0] and k[1] and _is_credential(k[0], str(it.get("labl") or "")):
                stub_domains.setdefault(k[1], set()).add(k[0])
            cfg, note = _meta.totp_config(meta), _meta.notes(meta)
            apple_hist = _meta.password_history(meta)
            apple_name = _meta.title(meta)
            extra_sites = _meta.sites(meta)
            if cfg or note or apple_hist or apple_name or extra_sites:
                slot = extras.setdefault(_key(it), {})
                if extra_sites and not slot.get("sites"):
                    slot["sites"] = extra_sites
                if apple_name and not slot.get("apple_title"):
                    slot["apple_title"] = apple_name
                if cfg and not slot.get("totp"):
                    slot["totp"] = cfg
                if note and not slot.get("notes"):
                    slot["notes"] = note
                if apple_hist and not slot.get("apple_history"):
                    slot["apple_history"] = apple_hist

        creds = []
        for it in items:
            if _meta.is_metadata(it.get("v_Data")):
                continue          # attributes, not a credential
            domain = (it.get("srvr") or it.get("server") or it.get("domain")
                      or it.get("url") or it.get("svce") or "")
            username = it.get("acct") or it.get("username") or it.get("user") or ""
            pw = it.get("v_Data") or it.get("password") or b""
            if isinstance(pw, (bytes, bytearray)):
                pw = pw.decode("utf-8", "replace")
            title = str(it.get("labl") or domain)
            if not _is_credential(str(domain), title):
                continue
            # Need a host/label to match against and at least a username or password to fill.
            if (not domain and not username) or not (username or pw):
                continue
            mdat = _to_unix(it.get("mdat") or it.get("cdat"))
            extra = extras.get(_key(it), {})
            # Apple stores no pointer from a stub to its credential (path, sha1, UUID, vwht and
            # bin0 were all checked and none resolves), so association is inferred from the
            # account name. Never alias onto the credential's own domain.
            alias = tuple(sorted(d for d in stub_domains.get(str(username), ())
                                 if not domains_match(d, str(domain))))
            creds.append(Credential(domain=str(domain), username=str(username),
                                    password=str(pw), title=title, mdat=mdat,
                                    totp=extra.get("totp"), notes=extra.get("notes", ""),
                                    apple_history=tuple(extra.get("apple_history") or ()),
                                    apple_title=extra.get("apple_title", ""),
                                    aliases=alias, sites=tuple(extra.get("sites") or ())))
        return cls(creds)


# native-messaging framing
def read_message(stream=None) -> dict | None:
    stream = stream or sys.stdin.buffer
    raw_len = stream.read(4)
    if len(raw_len) < 4:
        return None
    (length,) = struct.unpack("<I", raw_len)
    data = stream.read(length)
    if len(data) < length:
        return None
    return json.loads(data.decode("utf-8"))


def write_message(message: dict, stream=None) -> None:
    stream = stream or sys.stdout.buffer
    encoded = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def handle(request: dict, store: CredentialStore, aliases: list | None = None) -> dict:
    cmd = request.get("cmd")
    if cmd == "ping":
        return {"ok": True, "count": len(store)}
    if cmd == "totp":
        # Returns a code that expires in at most `period` seconds - never the secret. A
        # compromised extension therefore gets one throwaway code rather than a permanent
        # second factor, which is why the seed still never crosses this socket.
        domain, username = request.get("domain", ""), request.get("username", "")
        if not domain:
            return {"ok": False, "error": "missing domain"}
        for c in store.match(domain):
            if c.totp and (not username or c.username == username):
                code, seconds = c.totp_code()
                return {"ok": True, "code": code, "seconds": seconds,
                        "username": c.username, "domain": c.domain}
        return {"ok": False, "error": "no verification code for that account"}

    if cmd == "match":
        domain = request.get("domain", "")
        if not domain:
            return {"ok": False, "error": "missing domain"}
        matched = match_aliases(domain, aliases or [])
        return {"ok": True, "credentials": [c.public_dict() for c in store.match(domain)],
                "aliases": [a.public_dict() for a in matched]}
    return {"ok": False, "error": f"unknown cmd {cmd!r}"}


def serve(store: CredentialStore, *, aliases: list | None = None,
         instream=None, outstream=None) -> None:
    """Blocking native-messaging loop. Returns when the extension disconnects (EOF)."""
    while True:
        request = read_message(instream)
        if request is None:
            return
        write_message(handle(request, store, aliases), outstream)


def _maybe_trigger_sync() -> None:
    """If the vault is older than ICP_SYNC_MAX_AGE (default 6h), kick off a detached `sync`
    in the background and return immediately - the current request is still served from the
    existing vault, and the refreshed data is picked up on the next host spawn.

    Best-effort: never blocks and never raises. A debounce marker stops a multi-frame page from
    launching many syncs at once; `sync` itself holds a lock so only one ever runs."""
    import os
    import subprocess
    import time

    from .. import paths
    try:
        max_age = int(os.environ.get("ICP_SYNC_MAX_AGE", str(6 * 3600)))
        if max_age <= 0:
            return  # auto-sync disabled
        vault = paths.vault_file()
        if vault.exists() and (time.time() - vault.stat().st_mtime) < max_age:
            return  # fresh enough
        if paths.needs_login_file().exists():
            return  # latched: a code would only go to the phone with nothing able to accept it
        attempt = paths.sync_attempt_file()
        if attempt.exists() and (time.time() - attempt.stat().st_mtime) < 300:
            return  # already triggered recently
        attempt.touch()
        subprocess.Popen(
            [sys.executable, "-m", "icp.cli.app", "sync"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


def main(argv=None) -> int:
    """Serve the decrypted vault; fall back to an empty store so the extension can still
    connect/ping when no vault has been synced yet. Hide My Email aliases are a best-effort
    add-on (empty list if no cache exists yet - the host never touches the network itself,
    the cache is only ever populated by `icp show`/`icp sync`)."""
    _maybe_trigger_sync()
    try:
        from .store import load_vault
        store = load_vault()
    except Exception:
        store = CredentialStore([])
    try:
        from ..hme.store import load_aliases
        aliases = load_aliases()
    except Exception:
        aliases = []
    serve(store, aliases=aliases)
    return 0


if __name__ == "__main__":
    sys.exit(main())
