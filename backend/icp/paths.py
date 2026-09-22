"""Filesystem locations. Everything lives under $XDG_CONFIG_HOME/icp."""

import os
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = Path(base) / "icp"
    d.mkdir(parents=True, exist_ok=True)
    # Tokens and identity are sensitive; keep the directory private.
    os.chmod(d, 0o700)
    return d


def device_file() -> Path:
    return config_dir() / "device.json"


def session_file() -> Path:
    return config_dir() / "session.enc"


def fallback_key_file() -> Path:
    return config_dir() / "master.key"


def vault_key_file() -> Path:
    """0600 copy of the derived lockbox key, used after fingerprint so the TUI
    does not need Secret Service or a live agent."""
    return config_dir() / "vault.key"


def needs_login_file() -> Path:
    """Set when Apple demanded 2FA during an unattended refresh, cleared on a good sync.

    While it exists, automated syncs stand down. Without it every retry re-triggers Apple's
    sign-in push, so a expired token turns into a code arriving on your phone every few
    minutes that nothing on this machine is able to accept."""
    return config_dir() / "needs-login"


def history_file() -> Path:
    """Encrypted password-change journal. Holds old passwords, so it is vault-grade."""
    return config_dir() / "history.enc"


def nicknames_file() -> Path:
    """User-chosen entry names. Encrypted - a list of nicknames against accounts is a map of
    someone's life even though no single nickname is a secret."""
    return config_dir() / "nicknames.enc"


def vault_file() -> Path:
    return config_dir() / "vault.enc"


def aliases_file() -> Path:
    return config_dir() / "aliases.enc"


def sync_lock_file() -> Path:
    return config_dir() / "sync.lock"


def sync_attempt_file() -> Path:
    return config_dir() / "sync.attempt"
