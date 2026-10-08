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


class UserStore:
    """One uid's v2 store. Not thread-safe: the daemon serializes calls per uid."""

    unseal_count: int
    """How many times SK_secret was unsealed by this object. A test hook: sync must leave it 0."""

    uid: int

    # --- lifecycle ---------------------------------------------------------------------------
    @classmethod
    def open(cls, uid: int) -> "UserStore":
        """Bind to /var/lib/pear-passwords/u<uid>/ without touching any key. state() and
        status() work on the result; nothing secret is read."""
        raise NotImplementedError

    @classmethod
    def create(cls, uid: int) -> "UserStore":
        """Make a new store: random RK_list and an X25519 SK/PK pair, sealed with
        systemd-creds --with-key=auto, plus an empty meta. The result is unlocked.

        Refuses (StoreError) if u<uid> already holds a store; reset() is the way over one."""
        raise NotImplementedError

    @classmethod
    def reset(cls, uid: int) -> "UserStore":
        """The "Start over" button after tpm-cleared or damaged: rename u<uid> to
        u<uid>.broken-<unix time> (never delete - the files are kept for diagnosis), then
        create() a fresh store. Returns it unlocked."""
        raise NotImplementedError

    def state(self) -> StoreState:
        """Cheap, no unseal: "empty" with no keys, "unlocked" while RK_list is in memory,
        otherwise "locked" - or the SealError kind recorded by the last failed unlock()."""
        raise NotImplementedError

    def status(self) -> dict:
        """What hello reports: {state, signed_in, sealed_with, synced_at, needs_login}.

        signed_in is whether session.v2 exists (no key needed). sealed_with comes from the
        plaintext keys.json ("host" | "host+tpm2", None when empty). synced_at (unix seconds)
        and needs_login live under K_meta, so they are None while locked."""
        raise NotImplementedError

    def unlock(self) -> None:
        """Unseal RK_list, derive the subkeys, load meta. Raises SealError. Deletes any
        keys/*.prev left by an earlier re-seal once this unlock has succeeded."""
        raise NotImplementedError

    def lock(self) -> None:
        """Wipe RK_list, every subkey, the plaintext meta and any cached session. Idempotent.
        There is no partial lock: 2.0 has no sync lease."""
        raise NotImplementedError

    def reseal_if_tpm_available(self) -> bool:
        """After a successful unlock: if a TPM2 is present and keys.json says "host", re-seal
        both key blobs with host+tpm2, verify the new blobs, keep the old ones as *.prev, and
        record the SRK fingerprint. Returns True if it re-sealed. Never touches data files."""
        raise NotImplementedError

    # --- tier 1: metadata ---------------------------------------------------------------------
    def list_meta(self) -> list[Meta]:
        """Every live entry's Meta. Raises StoreLocked."""
        raise NotImplementedError

    def get_meta(self, id: str) -> Meta:
        """One live entry's Meta. Raises StoreLocked or EntryNotFound."""
        raise NotImplementedError

    def set_sync_status(self, *, synced_at: float | None = None,
                        needs_login: bool | None = None) -> None:
        """Record the outcome of a sync (fields left None are unchanged). Raises StoreLocked."""
        raise NotImplementedError

    # --- tier 2: one entry ---------------------------------------------------------------------
    def open_entry(self, id: str) -> Secrets:
        """Unseal SK_secret, open entries/<id>.box, check the id inside it, wipe SK_secret at
        once, and return the plaintext. Increments unseal_count. The caller owns the result
        and must drop it when the grant ends. Raises StoreLocked, EntryNotFound, SealError."""
        raise NotImplementedError

    def history(self, id: str) -> list[tuple[str, str]]:
        """Earlier values of the entry's password, newest first, as (iso8601 date, value):
        the local history boxes merged with Apple's own history. Unseals SK_secret like
        open_entry. Raises StoreLocked, EntryNotFound, SealError."""
        raise NotImplementedError

    def set_secrets(self, id: str, s: Secrets) -> None:
        """Replace one entry's secrets after a successful iCloud push: move the old box into
        history/<id>/ without decrypting it, seal the new one to PK_secret, update pwmac and
        mdat in meta. Never unseals SK_secret."""
        raise NotImplementedError

    # --- sync ----------------------------------------------------------------------------------
    def apply_sync(self, items: Iterable[SyncItem], deleted: set[str]) -> dict:
        """Upsert what iCloud returned, using PK_secret and pwmac only.

        For each item: write its Meta; if pwmac(password) differs from the stored one, move
        the old box to history and seal the new secrets; if only non-password secrets changed,
        re-seal the box (the old one is not history). Ids in `deleted` are tombstoned in meta.
        Returns {"added": n, "changed": n, "deleted": n, "unchanged": n}.
        Must never unseal SK_secret (unseal_count stays unchanged)."""
        raise NotImplementedError

    def pwmac_matches(self, texts: list[str]) -> list[int]:
        """Indexes of `texts` whose HMAC(K_pwmac, text) equals some entry's current pwmac.
        Used by clip-history-check; compares MACs only, no SK. Raises StoreLocked."""
        raise NotImplementedError

    # --- session, aliases, nicknames (tier 1 subkeys) -------------------------------------------
    def load_session(self) -> dict:
        """The former session.enc contents ({} when signed out). Raises StoreLocked."""
        raise NotImplementedError

    def save_session(self, d: dict) -> None:
        """Replace session.v2. An empty dict removes it (sign-out). Raises StoreLocked."""
        raise NotImplementedError

    def load_aliases(self) -> list[dict]:
        """Hide My Email aliases as plain dicts. Raises StoreLocked."""
        raise NotImplementedError

    def save_aliases(self, aliases: list[dict]) -> None:
        raise NotImplementedError

    def load_nicknames(self) -> dict[str, str]:
        """Local nicknames by entry id. Raises StoreLocked."""
        raise NotImplementedError

    def save_nicknames(self, names: dict[str, str]) -> None:
        raise NotImplementedError

    def load_device(self) -> dict:
        """device.json (plaintext 0600, the Apple device identity - not a key). {} if absent."""
        raise NotImplementedError

    def save_device(self, d: dict) -> None:
        raise NotImplementedError

    # --- plaintext settings (state.json) -------------------------------------------------------
    def load_settings(self) -> dict:
        """{grant_s, idle_lock_s, clip_timeout_s} merged over protocol.DEFAULT_SETTINGS, plus
        "old_copy": {"dir", "files": [{"name", "sha256"}], "migrated_at"} once a migration
        recorded one. Works while locked."""
        raise NotImplementedError

    def save_settings(self, d: dict) -> None:
        """Validated by the caller; written as given."""
        raise NotImplementedError

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
        raise NotImplementedError


def v1_key_from_passphrase(kdf_json: bytes, passphrase: str) -> bytes:
    """Argon2id(passphrase) with the salt and limits from the v1 kdf.json (256 MiB at the
    moderate preset). Returns the 32-byte v1 key; does not check it."""
    raise NotImplementedError


def v1_key_opens(check_enc: bytes, key: bytes) -> bool:
    """True if `key` opens the v1 check.enc. Constant-time with respect to the key."""
    raise NotImplementedError


__all__ = [
    "EntryNotFound", "ImportMismatch", "Meta", "SealError", "SealKind", "Secrets",
    "StoreError", "StoreLocked", "StoreState", "SyncItem", "UserStore", "WrongPassphrase",
    "v1_key_from_passphrase", "v1_key_opens",
]
