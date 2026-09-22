"""Setting a passphrase changes the master key. Everything encrypted under the old key has to
be re-written under the new one - history and nicknames included, or they become unreadable."""
import argparse
import os
import sys
import types

import pytest

from icp.auth import agent, lockbox, prompt, session
from icp.cli import app
from icp.hme import store as hme_store
from icp.vault import history, nicknames, store as vault_store

MODULES_WITH_KEY = (session, vault_store, hme_store, history, nicknames)


@pytest.fixture
def keys(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    state = {"key": os.urandom(32)}
    for m in MODULES_WITH_KEY:
        monkeypatch.setattr(m, "_master_key", lambda: state["key"], raising=True)
    new_key = os.urandom(32)

    def initialise(passphrase):
        state["key"] = new_key            # from now on everything reads with the new key
        return new_key
    monkeypatch.setattr(lockbox, "initialise", initialise)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: False)
    monkeypatch.setattr(prompt, "ask_passphrase", lambda **kw: "correct horse battery")
    monkeypatch.setattr(agent, "lock", lambda: None)
    monkeypatch.setattr(agent, "unlock", lambda p: None)
    import icp.auth.held_key as held_key
    monkeypatch.setattr(held_key, "save", lambda k: None)
    monkeypatch.setitem(sys.modules, "secretstorage", types.SimpleNamespace(
        dbus_init=lambda: (_ for _ in ()).throw(RuntimeError("no dbus in tests"))))
    return state


def test_history_and_nicknames_survive_a_passphrase_change(keys):
    accounts = {}
    history.record(accounts, "example.com", "alex", old="a", new="b", source="sync", when=1.0)
    history.save(accounts)
    nicknames.save({"example.com\x1falex": "Work"})
    assert app.cmd_passphrase(argparse.Namespace()) == 0
    assert history.for_account(history.load(), "example.com", "alex")
    assert nicknames.load() == {"example.com\x1falex": "Work"}
