"""The v2 per-user store: /var/lib/pear-passwords/u<uid>/, read and written only by the daemon.

This file is the frozen interface between WP2 (which implements it, in this package) and its
callers: WP1's handlers and WP3's Apple pipeline. Signatures, field names and exception kinds
here do not change without a foundation amendment on v2-base; the bodies are WP2's.

Key hierarchy (spec section 3): RK_list unlocks meta, session, aliases and nicknames through
HKDF subkeys; SK_secret opens one entry box at a time and is wiped at once. Writes only ever
need PK_secret, so sync and edits never unseal SK_secret - `unseal_count` lets a test prove it.

Rules every implementation keeps:
- A decrypt or AEAD error never deletes or rewrites anything; it surfaces as SealError("damaged").
- Every write is O_EXCL temp 0600, fsync, rename, fsync of the directory.
- Nothing here prompts, imports polkit, or reads $HOME.
- There is no sync lease: lock() wipes every key and subkey, always.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

SealKind = Literal["tpm-missing", "tpm-cleared", "damaged"]
StoreState = Literal["empty", "locked", "unlocked", "tpm-missing", "tpm-cleared", "damaged"]


class StoreError(Exception):
    """Base of every error this package raises."""


class SealError(StoreError):
    """The keys could not be unsealed, or a file failed its AEAD check.

    kind is "tpm-missing" (sealed with host+tpm2 and the TPM is gone - recoverable by turning
    PTT back on), "tpm-cleared" (a TPM is present but its SRK differs from the recorded one -
    unrecoverable), or "damaged" (unseal worked but a file does not decrypt; files are kept)."""

    def __init__(self, kind: SealKind, detail: str = ""):
        if kind not in ("tpm-missing", "tpm-cleared", "damaged"):
            raise ValueError(f"unknown seal error kind {kind!r}")
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


class StoreLocked(StoreError):
    """The call needs tier 1 (RK_list) and the store is locked."""


class EntryNotFound(StoreError, KeyError):
    """No live (non-tombstoned) entry has this id."""


class WrongPassphrase(StoreError):
    """A v1 key - PEEKed from the 1.3.2 agent or derived from the typed passphrase - does not
    open check.enc."""


class ImportMismatch(StoreError):
    """The converted v2 store did not re-open to the same counts and digest as the v1 read.
    The tmp directory has already been removed; v1 stays authoritative."""


@dataclass
class Meta:
    """The non-secret part of one entry, held under K_meta. This is all tier 1 releases.

    `id` is opaque to callers (at most 128 characters of [A-Za-z0-9._:-]) and stable across
    syncs for the same keychain item. `domain` is the primary site host, `sites` the extra
    sites Apple stores on the entry (s_as). `aliases` are inferred from metadata stubs and are
    for display only: autofill never matches on them. `mdat` is unix seconds, 0 if unknown.
    """

    id: str
    title: str
    domain: str
    sites: list[str]
    username: str
    nickname: str
    has_totp: bool
    has_notes: bool
    mdat: float
    history_count: int
    apple_title: str = ""
    aliases: list[str] = field(default_factory=list)


@dataclass
class Secrets:
    """The secret part of one entry, sealed to PK_secret in entries/<id>.box.

    `totp_secret` is the raw seed (never base32 text) and `totp_params` its
    {digits, period, algorithm}, both None/empty when the entry has no code. `apple_history`
    is Apple's own password history for the item, newest first, as list of
    {"date": iso8601, "value": str}."""

    password: str
    notes: str
    totp_secret: bytes | None
    apple_history: list
    totp_params: dict = field(default_factory=dict)


@dataclass
class SyncItem:
    """One decrypted keychain item handed from the Apple pipeline to apply_sync. Plaintext and
    transient: the caller drops it as soon as apply_sync returns."""

    id: str
    meta: Meta
    secrets: Secrets


# The implementation modules import the exceptions and dataclasses above, so they come in only
# once those exist.
import datetime as _dt  # noqa: E402
import hmac as _hmac  # noqa: E402
import logging as _logging  # noqa: E402
import os as _os  # noqa: E402
import time as _time  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from .. import paths as _paths  # noqa: E402
from ..daemon import paths as _system_paths  # noqa: E402
from . import entries as _entries  # noqa: E402
from . import format as _fmt  # noqa: E402
from . import keys as _keys  # noqa: E402
from . import meta as _meta  # noqa: E402
from . import seal as _seal  # noqa: E402
from . import session_store as _ss  # noqa: E402
from .ids import check_id as _check_id  # noqa: E402

_log = _logging.getLogger(__name__)
_TIERS = ("list", "secret")
_KEYS_FORMAT = 2


class UserStore:
    """One uid's v2 store. Not thread-safe: the daemon serializes calls per uid."""

    unseal_count: int
    """How many times SK_secret was unsealed by this object. A test hook: sync must leave it 0."""

    uid: int

    def __init__(self, uid: int, _root=None):
        self.uid = uid
        self.unseal_count = 0
        self._dir = _Path(_root) if _root is not None else _paths.user_dir(uid)
        self._rk: _keys.SecretBytes | None = None
        self._sub: dict | None = None
        self._pk: bytes | None = None
        self._doc: dict | None = None
        self._nick: dict | None = None
        self._fail: str | None = None

    def __repr__(self) -> str:
        return f"<UserStore u{self.uid} {self.state()}>"

    # --- lifecycle ---------------------------------------------------------------------------
    @classmethod
    def open(cls, uid: int) -> "UserStore":
        """Bind to /var/lib/pear-passwords/u<uid>/ without touching any key. state() and
        status() work on the result; nothing secret is read."""
        return cls(uid)

    @classmethod
    def create(cls, uid: int) -> "UserStore":
        """Make a new store: random RK_list and an X25519 SK/PK pair, sealed with
        systemd-creds --with-key=auto, plus an empty meta. The result is unlocked.

        Refuses (StoreError) if u<uid> already holds a store; reset() is the way over one."""
        store = cls(uid)
        if store._has_keys():
            raise StoreError(f"u{uid} already holds a store")
        backend = _seal.get_backend()
        _fmt.ensure_dir(_Path(_paths.STATE_ROOT))
        kd = _fmt.ensure_dir(store._keys_dir())
        _entries.EntryFiles(store._dir).ensure()

        sealed_with = _seal.sealed_with_now(backend)
        srk = backend.srk_fingerprint() if sealed_with == "host+tpm2" else None
        rk = _keys.new_root()
        sk, pk = _keys.new_keypair()
        written: list = []
        try:
            blobs = {"list": backend.encrypt(store._cred_name("list"), bytes(rk)),
                     "secret": backend.encrypt(store._cred_name("secret"), bytes(sk))}
            # Read both back before anything depends on them: a blob that does not open now
            # would be a store that can never be unlocked.
            # (Not counted in unseal_count: SK_secret was generated here, nothing is released.)
            store._verify_blob(backend, "list", blobs["list"], rk)
            store._verify_blob(backend, "secret", blobs["secret"], sk)
            sub = _keys.derive(rk)
            for tier in _TIERS:
                written.append(kd / store._cred_file(tier))
                _fmt.atomic_write(written[-1], blobs[tier])
            written.append(kd / _paths.SECRET_PUB)
            _fmt.atomic_write(written[-1], _keys.pk_record(sub["meta"], pk))
            store._rk, store._sub, store._pk = rk, sub, pk
            store._doc, store._nick = _meta.empty(), {}
            written.append(store._dir / _paths.META_FILE)
            store._write_meta()
            # keys.json last: until it exists the directory is not a store anyone relies on.
            store._write_keys_json({"format": _KEYS_FORMAT, "sealed_with": sealed_with,
                                    **({"tpm_srk_fp": srk} if srk else {}),
                                    "created": _time.time()})
        except BaseException:
            store.lock()
            rk.wipe()
            # Fresh keys that never became a store guard nothing; leaving them would make the
            # directory look like a store that can never be unlocked.
            for f in written:
                try:
                    _os.unlink(f)
                except FileNotFoundError:
                    pass
            raise
        finally:
            sk.wipe()
        return store

    @classmethod
    def reset(cls, uid: int) -> "UserStore":
        """The "Start over" button after tpm-cleared or damaged: rename u<uid> to
        u<uid>.broken-<unix time> (never delete - the files are kept for diagnosis), then
        create() a fresh store. Returns it unlocked."""
        d = _paths.user_dir(uid)
        if _os.path.lexists(d):
            aside = _paths.user_aside_dir(uid, "broken", _time.time())
            n = 1
            while _os.path.lexists(aside):
                aside = _paths.user_aside_dir(uid, "broken", _time.time() + n)
                n += 1
            _os.rename(d, aside)
            _fmt.fsync_dir(d.parent)
            _log.warning("u%d: store moved aside to %s for diagnosis", uid, aside.name)
        return cls.create(uid)

    def state(self) -> StoreState:
        """Cheap, no unseal: "empty" with no keys, "unlocked" while RK_list is in memory,
        otherwise "locked" - or the SealError kind recorded by the last failed unlock()."""
        if self._rk is not None:
            return "unlocked"
        if self._fail is not None:
            return self._fail
        return "locked" if self._has_keys() else "empty"

    def status(self) -> dict:
        """What hello reports: {state, signed_in, sealed_with, synced_at, needs_login}.

        signed_in is whether session.v2 exists (no key needed). sealed_with comes from the
        plaintext keys.json ("host" | "host+tpm2", None when empty). synced_at (unix seconds)
        and needs_login live under K_meta, so they are None while locked."""
        state = self.state()
        try:
            kj = self._read_keys_json()
        except SealError:
            kj = None
        sealed = kj.get("sealed_with") if kj else None
        unlocked = state == "unlocked"
        return {"state": state,
                "signed_in": state != "empty" and _ss.signed_in(self._dir),
                "sealed_with": sealed if sealed in ("host", "host+tpm2") else None,
                "synced_at": self._doc.get("synced_at") if unlocked else None,
                "needs_login": bool(self._doc.get("needs_login")) if unlocked else None}

    def unlock(self) -> None:
        """Unseal RK_list, derive the subkeys, load meta. Raises SealError. Deletes any
        keys/*.prev left by an earlier re-seal once this unlock has succeeded."""
        if self._rk is not None:
            return
        if not self._has_keys():
            raise StoreError("empty: there is no store to unlock")
        try:
            rk = self._unseal_list()
        except SealError as e:
            self._fail = e.kind
            raise
        sub: dict = {}
        try:
            sub = _keys.derive(rk)
            pk = _keys.pk_from_record(sub["meta"],
                                      _fmt.read_file(self._keys_dir() / _paths.SECRET_PUB))
            doc = _fmt.read_sealed(self._dir, _paths.META_FILE, bytes(sub["meta"]),
                                   _fmt.KIND_META, self.uid)
            if doc is None:
                raise SealError("damaged", "meta.v2 is missing")
            doc = _meta.check(doc)
            nick = _ss.load_nicknames(self._dir, sub["nicknames"], self.uid)
        except SealError as e:
            rk.wipe()
            _keys.wipe_all(sub)
            self._fail = e.kind
            raise
        self._rk, self._sub, self._pk, self._doc, self._nick = rk, sub, pk, doc, nick
        self._fail = None
        self._drop_prev()

    def lock(self) -> None:
        """Wipe RK_list, every subkey, the plaintext meta and any cached session. Idempotent.
        There is no partial lock: 2.0 has no sync lease."""
        if self._rk is not None:
            self._rk.wipe()
        _keys.wipe_all(self._sub or {})
        self._rk = self._sub = self._pk = None
        self._doc = self._nick = None

    def reseal_if_tpm_available(self) -> bool:
        """After a successful unlock: if a TPM2 is present and keys.json says "host", re-seal
        both key blobs with host+tpm2, verify the new blobs, keep the old ones as *.prev, and
        record the SRK fingerprint. Returns True if it re-sealed. Never touches data files."""
        self._need_unlocked()
        kj = self._read_keys_json() or {}
        if kj.get("sealed_with") == "host+tpm2":
            return False
        backend = _seal.get_backend()
        if not backend.tpm_present():
            return False
        kd = self._keys_dir()
        srk = backend.srk_fingerprint()
        try:
            sk = self._unseal_sk()
        except (SealError, _seal.SealUnavailable) as e:
            _log.warning("u%d: cannot re-seal, the entry key did not unseal (%s)", self.uid,
                         type(e).__name__)
            return False
        new = {t: kd / (self._cred_file(t) + _paths.NEW_SUFFIX) for t in _TIERS}
        try:
            plain = {"list": self._rk, "secret": sk}
            for t in _TIERS:
                _fmt.atomic_write(new[t], backend.encrypt(self._cred_name(t), bytes(plain[t])))
            # Verify before touching the blobs in use. A failure here leaves everything as it
            # was: the current blobs, keys.json and any rollback copies.
            for t in _TIERS:
                self._verify_blob(backend, t, _fmt.read_file(new[t]), plain[t])
        except (SealError, _seal.SealUnavailable, OSError) as e:
            for f in new.values():
                try:
                    f.unlink()
                except FileNotFoundError:
                    pass
            _log.warning("u%d: re-seal with the TPM did not verify (%s); kept host sealing",
                         self.uid, type(e).__name__)
            return False
        finally:
            sk.wipe()
        # Only now, with both new blobs proven, do the old ones step aside - kept as *.prev
        # until the next successful unlock, so a TPM that misbehaves right after can be
        # rolled back from.
        new_kj = kd / (_paths.KEYS_JSON + _paths.NEW_SUFFIX)
        _fmt.atomic_write(new_kj, _fmt.dumps({**kj, "format": _KEYS_FORMAT,
                                              "sealed_with": "host+tpm2",
                                              **({"tpm_srk_fp": srk} if srk else {}),
                                              "resealed": _time.time()}))
        for name, src in ((self._cred_file("list"), new["list"]),
                          (self._cred_file("secret"), new["secret"]),
                          (_paths.KEYS_JSON, new_kj)):
            _os.replace(kd / name, kd / (name + _paths.PREV_SUFFIX))
            _os.replace(src, kd / name)
        _fmt.fsync_dir(kd)
        _log.info("u%d: keys re-sealed with host+tpm2", self.uid)
        return True

    # --- tier 1: metadata ---------------------------------------------------------------------
    def list_meta(self) -> list[Meta]:
        """Every live entry's Meta. Raises StoreLocked."""
        self._need_unlocked()
        out = [_meta.to_meta(i, r, self._nick.get(i, "")) for i, r in _meta.live(self._doc)]
        out.sort(key=lambda m: (m.title.lower(), m.username.lower(), m.id))
        return out

    def get_meta(self, id: str) -> Meta:
        """One live entry's Meta. Raises StoreLocked or EntryNotFound."""
        self._need_unlocked()
        return _meta.to_meta(id, self._live(id), self._nick.get(id, ""))

    def set_sync_status(self, *, synced_at: float | None = None,
                        needs_login: bool | None = None) -> None:
        """Record the outcome of a sync (fields left None are unchanged). Raises StoreLocked."""
        self._need_unlocked()
        if synced_at is not None:
            self._doc["synced_at"] = float(synced_at)
        if needs_login is not None:
            self._doc["needs_login"] = bool(needs_login)
        self._write_meta()

    # --- tier 2: one entry ---------------------------------------------------------------------
    def open_entry(self, id: str) -> Secrets:
        """Unseal SK_secret, open entries/<id>.box, check the id inside it, wipe SK_secret at
        once, and return the plaintext. Increments unseal_count. The caller owns the result
        and must drop it when the grant ends. Raises StoreLocked, EntryNotFound, SealError."""
        self._need_unlocked()
        rec = self._live(id)
        files = _entries.EntryFiles(self._dir)
        blob = files.read(id)
        if blob is None:
            raise SealError("damaged", "entry box is missing")
        sk = self._unseal_sk()
        try:
            payload = _entries.open_box(bytes(sk), blob, id, int(rec.get("v", 0)))
        finally:
            sk.wipe()
        return _entries.from_payload(payload)

    def history(self, id: str) -> list[tuple[str, str]]:
        """Earlier values of the entry's password, newest first, as (iso8601 date, value):
        the local history boxes merged with Apple's own history. Unseals SK_secret like
        open_entry. Raises StoreLocked, EntryNotFound, SealError."""
        self._need_unlocked()
        rec = self._live(id)
        files = _entries.EntryFiles(self._dir)
        blob = files.read(id)
        hist = list(rec.get("hist") or [])
        blobs = [(h, files.read_history(id, h["n"])) for h in hist]
        if blob is None or any(b is None for _, b in blobs):
            raise SealError("damaged", "an entry or history box is missing")
        sk = self._unseal_sk()
        try:
            current = _entries.open_box(bytes(sk), blob, id, int(rec.get("v", 0)))
            local = [(float(h.get("at") or 0.0), _entries.open_box(bytes(sk), b, id)["password"],
                      h.get("source") or "local") for h, b in blobs]
        finally:
            sk.wipe()
        return _merge_history(local, current.get("apple_history") or [])

    def set_secrets(self, id: str, s: Secrets) -> None:
        """Replace one entry's secrets after a successful iCloud push: move the old box into
        history/<id>/ without decrypting it, seal the new one to PK_secret, update pwmac and
        mdat in meta. Never unseals SK_secret."""
        self._need_unlocked()
        rec = self._live(id)
        _entries.check_secrets(s)
        self._replace_secrets(id, rec, s, source="local", when=_time.time())
        rec["mdat"] = _time.time()
        self._write_meta()

    # --- sync ----------------------------------------------------------------------------------
    def apply_sync(self, items: Iterable[SyncItem], deleted: set[str]) -> dict:
        """Upsert what iCloud returned, using PK_secret and pwmac only.

        For each item: write its Meta; if pwmac(password) differs from the stored one, move
        the old box to history and seal the new secrets; if only non-password secrets changed,
        re-seal the box (the old one is not history). Ids in `deleted` are tombstoned in meta.
        Returns {"added": n, "changed": n, "deleted": n, "unchanged": n}.
        Must never unseal SK_secret (unseal_count stays unchanged)."""
        self._need_unlocked()
        items = list(items)
        for it in items:
            if not isinstance(it, SyncItem) or not isinstance(it.meta, Meta):
                raise ValueError("apply_sync takes SyncItems")
            _check_id(it.id)
            if it.meta.id != it.id:
                raise ValueError("SyncItem.meta.id differs from SyncItem.id")
            _entries.check_secrets(it.secrets)
        gone = set(deleted or ())
        counts = {"added": 0, "changed": 0, "deleted": 0, "unchanged": 0}
        entries = self._doc["entries"]
        now = _time.time()
        for it in items:
            fields = _meta.fields_from(it.meta)
            fields["has_totp"] = bool(it.secrets.totp_secret)
            fields["has_notes"] = bool(it.secrets.notes)
            rec = entries.get(it.id)
            if rec is None or rec.get("deleted"):
                if rec is None:
                    rec = entries[it.id] = {"v": 0, "hist": []}
                rec.pop("deleted", None)
                rec.pop("deleted_at", None)
                rec.update(fields)
                self._replace_secrets(it.id, rec, it.secrets, source="local", when=now)
                counts["added"] += 1
                continue
            touched = self._replace_secrets(it.id, rec, it.secrets, source="local", when=now)
            if touched or not _meta.same_fields(rec, fields):
                rec.update(fields)
                counts["changed"] += 1
            else:
                counts["unchanged"] += 1
        for id in gone:
            rec = entries.get(id) if isinstance(id, str) else None
            if rec is not None and not rec.get("deleted"):
                rec["deleted"], rec["deleted_at"] = True, now
                counts["deleted"] += 1
        self._write_meta()
        return counts

    def pwmac_matches(self, texts: list[str]) -> list[int]:
        """Indexes of `texts` whose HMAC(K_pwmac, text) equals some entry's current pwmac.
        Used by clip-history-check; compares MACs only, no SK. Raises StoreLocked."""
        self._need_unlocked()
        known = {r.get("pwmac") for _, r in _meta.live(self._doc)}
        k = self._sub["pwmac"]
        return [i for i, t in enumerate(texts)
                if isinstance(t, str) and _keys.pwmac(k, t) in known]

    # --- session, aliases, nicknames (tier 1 subkeys) -------------------------------------------
    def load_session(self) -> dict:
        """The former session.enc contents ({} when signed out). Raises StoreLocked."""
        self._need_unlocked()
        return _ss.load_session(self._dir, self._sub["session"], self.uid)

    def save_session(self, d: dict) -> None:
        """Replace session.v2. An empty dict removes it (sign-out). Raises StoreLocked."""
        self._need_unlocked()
        _ss.save_session(self._dir, self._sub["session"], self.uid, d)

    def load_aliases(self) -> list[dict]:
        """Hide My Email aliases as plain dicts. Raises StoreLocked."""
        self._need_unlocked()
        return _ss.load_aliases(self._dir, self._sub["aliases"], self.uid)

    def save_aliases(self, aliases: list[dict]) -> None:
        self._need_unlocked()
        _ss.save_aliases(self._dir, self._sub["aliases"], self.uid, aliases)

    def load_nicknames(self) -> dict[str, str]:
        """Local nicknames by entry id. Raises StoreLocked."""
        self._need_unlocked()
        return dict(self._nick)

    def save_nicknames(self, names: dict[str, str]) -> None:
        self._need_unlocked()
        _ss.save_nicknames(self._dir, self._sub["nicknames"], self.uid, names)
        self._nick = dict(names)

    def load_device(self) -> dict:
        """device.json (plaintext 0600, the Apple device identity - not a key). {} if absent."""
        return _ss.load_device(self._dir)

    def save_device(self, d: dict) -> None:
        _fmt.ensure_dir(self._dir)
        _ss.save_device(self._dir, d)

    # --- plaintext settings (state.json) -------------------------------------------------------
    def load_settings(self) -> dict:
        """{grant_s, idle_lock_s, clip_timeout_s} merged over protocol.DEFAULT_SETTINGS, plus
        "old_copy": {"dir", "files": [{"name", "sha256"}], "migrated_at"} once a migration
        recorded one. Works while locked."""
        return _ss.load_settings(self._dir)

    def save_settings(self, d: dict) -> None:
        """Validated by the caller; written as given."""
        _fmt.ensure_dir(self._dir)
        _ss.save_settings(self._dir, d)

    # --- migration from 1.x --------------------------------------------------------------------
    def import_v1(self, files: dict[str, bytes], key: bytes) -> dict:
        """Convert a v1 vault (protocol.IMPORT_FILES contents, keyed by file name) opened with
        the 32-byte v1 key into this store.

        Builds everything in u<uid>.tmp/, re-opens it through the v2 loaders, and compares
        counts and a SHA-256 over the canonical plaintext JSON with the figures from the v1
        read. On a match the tmp tree replaces the data files of u<uid>; on a mismatch it is
        removed and ImportMismatch is raised. Never unlinks or rewrites anything the caller
        passed in. Requires the store unlocked (it was just created by migrate-begin).

        Returns {"counts": {"credentials", "history", "nicknames", "aliases", "session_keys"},
        "digest": hex sha256}."""
        from . import importer
        return importer.import_v1(self, files, key)

    # --- internals -----------------------------------------------------------------------------
    def _keys_dir(self) -> _Path:
        return self._dir / _paths.KEYS_DIR

    def _has_keys(self) -> bool:
        kd = self._keys_dir()
        return _os.path.lexists(kd / _paths.KEYS_JSON) or _os.path.lexists(kd / _paths.LIST_CRED)

    def _cred_name(self, tier: str) -> str:
        return _system_paths.credential_name(tier, self.uid)

    @staticmethod
    def _cred_file(tier: str) -> str:
        return {"list": _paths.LIST_CRED, "secret": _paths.SECRET_CRED}[tier]

    def _need_unlocked(self) -> None:
        if self._rk is None:
            raise StoreLocked("the store is locked")

    def _live(self, id: str) -> dict:
        rec = _meta.live_record(self._doc, id)
        if rec is None:
            raise EntryNotFound(id)
        return rec

    def _read_keys_json(self) -> dict | None:
        raw = _fmt.read_file(self._keys_dir() / _paths.KEYS_JSON, 65536)
        if raw is None:
            return None
        doc = _fmt.loads(raw, _paths.KEYS_JSON)
        if not isinstance(doc, dict):
            raise SealError("damaged", "keys.json has the wrong shape")
        return doc

    def _write_keys_json(self, d: dict) -> None:
        _fmt.atomic_write(self._keys_dir() / _paths.KEYS_JSON, _fmt.dumps(d))

    def _write_meta(self) -> None:
        _fmt.write_sealed(self._dir, _paths.META_FILE, bytes(self._sub["meta"]),
                          _fmt.KIND_META, self.uid, self._doc)

    def _verify_blob(self, backend, tier: str, blob, want) -> None:
        if blob is None:
            raise SealError("damaged", f"{tier} blob vanished")
        try:
            got = backend.decrypt(self._cred_name(tier), blob)
        except _seal.UnsealRefused:
            raise SealError("damaged", f"freshly sealed {tier} blob does not open") from None
        if not _hmac.compare_digest(bytes(got), bytes(want)):
            raise SealError("damaged", f"freshly sealed {tier} blob opens to something else")

    def _unseal(self, tier: str, blob: bytes, backend) -> _keys.SecretBytes:
        """UnsealRefused and SealUnavailable pass through; the caller decides what they mean."""
        plain = backend.decrypt(self._cred_name(tier), blob)
        try:
            if len(plain) != _keys.KEY_BYTES:
                raise SealError("damaged", f"{tier} key has the wrong length")
            return _keys.SecretBytes(plain)
        finally:
            del plain

    def _unseal_list(self) -> _keys.SecretBytes:
        """RK_list from list.cred, rolling back to list.cred.prev (the blobs from before the
        last re-seal) when the current blob is refused and the previous one still opens."""
        backend = _seal.get_backend()
        kd = self._keys_dir()
        kj = self._read_keys_json()
        blob = _fmt.read_file(kd / _paths.LIST_CRED, 65536)
        if kj is not None and blob is not None:
            try:
                return self._unseal("list", blob, backend)
            except _seal.UnsealRefused:
                pass
        rk = self._rollback(backend)
        if rk is not None:
            return rk
        if kj is None or blob is None:
            raise SealError("damaged", "keys.json or list.cred is missing")
        raise SealError(_seal.classify(backend, kj.get("sealed_with"), kj.get("tpm_srk_fp")),
                        "list.cred was refused")

    def _rollback(self, backend) -> _keys.SecretBytes | None:
        kd = self._keys_dir()
        prev = {n: kd / (n + _paths.PREV_SUFFIX)
                for n in (_paths.LIST_CRED, _paths.SECRET_CRED, _paths.KEYS_JSON)}
        if not all(p.exists() for p in prev.values()):
            return None
        try:
            rk = self._unseal("list", _fmt.read_file(prev[_paths.LIST_CRED], 65536), backend)
        except (_seal.UnsealRefused, SealError):
            return None
        for name, p in prev.items():
            _os.replace(p, kd / name)
        _fmt.fsync_dir(kd)
        _log.warning("u%d: re-sealed keys were refused; rolled back to the previous blobs",
                     self.uid)
        return rk

    def _drop_prev(self) -> None:
        """The rollback window closes at the first successful unlock after a re-seal."""
        kd = self._keys_dir()
        dropped = False
        for name in (_paths.LIST_CRED, _paths.SECRET_CRED, _paths.KEYS_JSON):
            try:
                _os.unlink(kd / (name + _paths.PREV_SUFFIX))
                dropped = True
            except FileNotFoundError:
                pass
        if dropped:
            _fmt.fsync_dir(kd)

    def _unseal_sk(self) -> _keys.SecretBytes:
        """SK_secret, briefly. The caller wipes it in a finally. Counted in unseal_count."""
        self._need_unlocked()
        backend = _seal.get_backend()
        blob = _fmt.read_file(self._keys_dir() / _paths.SECRET_CRED, 65536)
        if blob is None:
            raise SealError("damaged", "secret.cred is missing")
        self.unseal_count += 1
        try:
            sk = self._unseal("secret", blob, backend)
        except _seal.UnsealRefused:
            kj = self._read_keys_json() or {}
            raise SealError(_seal.classify(backend, kj.get("sealed_with"),
                                           kj.get("tpm_srk_fp")),
                            "secret.cred was refused") from None
        if not _keys.sk_matches_pk(bytes(sk), self._pk):
            sk.wipe()
            raise SealError("damaged", "secret.cred does not match secret.pub")
        return sk

    def _replace_secrets(self, id: str, rec: dict, s: Secrets, *, source: str,
                         when: float) -> bool:
        """Seal `s` as the entry's current box if it differs from what meta says the box
        holds. A different password moves the old box into history first; other changes
        re-seal in place. Returns whether a box was written. Meta is updated in `rec` and
        written by the caller. Uses PK_secret only."""
        k = self._sub["pwmac"]
        pwm = _keys.pwmac(k, s.password)
        sm = _keys.smac(k, _entries.rest_canonical(s))
        files = _entries.EntryFiles(self._dir)
        has_box = files.exists(id)
        if has_box and rec.get("pwmac") == pwm and rec.get("smac") == sm:
            return False
        if has_box and rec.get("pwmac") not in (None, pwm):
            hist = rec.setdefault("hist", [])
            n = files.next_number(id, [h["n"] for h in hist])
            if files.move_to_history(id, n):
                hist.append({"n": n, "at": when, "source": source})
                while len(hist) > _entries.MAX_HISTORY:
                    files.drop_history(id, hist.pop(0)["n"])
        v = int(rec.get("v") or 0) + 1
        files.write(id, _entries.seal(self._pk, _entries.to_payload(id, v, s)))
        rec.update({"v": v, "pwmac": pwm, "smac": sm, "apple_n": len(s.apple_history or []),
                    "has_totp": bool(s.totp_secret), "has_notes": bool(s.notes)})
        return True


def _ts(iso: str) -> float:
    try:
        return _dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _iso(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return "1970-01-01T00:00:00Z"


def _merge_history(local: list, apple: list) -> list:
    """Local history (at, value, source) and Apple's [{date, value}], newest first. An Apple
    item with the same value in the same minute as a local one is the same change seen twice;
    the local one wins."""
    items = [(at, _entries.HistoryItem(_iso(at), value, "local")) for at, value, _ in local]
    known = {(value, round(at / 60)) for at, value, _ in local}
    for h in apple:
        if not isinstance(h, dict) or not isinstance(h.get("value"), str):
            continue
        at = _ts(h.get("date"))
        if (h["value"], round(at / 60)) in known:
            continue
        items.append((at, _entries.HistoryItem(str(h.get("date") or _iso(at)), h["value"],
                                               "apple")))
    items.sort(key=lambda p: p[0], reverse=True)
    return [item for _, item in items]


def v1_key_from_passphrase(kdf_json: bytes, passphrase: str) -> bytes:
    """Argon2id(passphrase) with the salt and limits from the v1 kdf.json (256 MiB at the
    moderate preset). Returns the 32-byte v1 key; does not check it."""
    from . import legacy
    return legacy.key_from_passphrase(kdf_json, passphrase)


def v1_key_opens(check_enc: bytes, key: bytes) -> bool:
    """True if `key` opens the v1 check.enc. Constant-time with respect to the key."""
    from . import legacy
    return legacy.key_opens(check_enc, key)


__all__ = [
    "EntryNotFound", "ImportMismatch", "Meta", "SealError", "SealKind", "Secrets",
    "StoreError", "StoreLocked", "StoreState", "SyncItem", "UserStore", "WrongPassphrase",
    "v1_key_from_passphrase", "v1_key_opens",
]
