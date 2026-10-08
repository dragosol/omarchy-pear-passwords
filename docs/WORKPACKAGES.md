# Pear Passwords 2.0 work packages

Every work package branches from `v2-base`, which holds only the frozen shared interfaces. This
page says who owns which file, how the packages plug into each other, and what nobody may change
on their own branch. The design is the 2.0 spec, with the owner decisions of 2026-10-08 on
top: per-account grant 120 s, clipboard 30 s, one-time v1 import, autofill rebuilt as a generic
host with no bundled extension, and no sync lease.

## 1. Frozen interfaces (foundation, `v2-base`)

| File | What it fixes |
|---|---|
| `docs/protocol.md` | The wire protocol: framing, roles, tickets, prompts, every op, event and error code |
| `docs/WORKPACKAGES.md` | This page |
| `backend/icp/daemon/protocol.py` | The same contract as constants, plus `OpError` and the `Connection` / `Session` / `SessionRegistry` handler interfaces |
| `backend/icp/daemon/paths.py`, `system/paths.env` | Every system path, user, group, unit, polkit action and pear-exec role target |
| `backend/icp/daemon/context.py` (+ `daemon/__init__.py`) | `UserContext`, `Frontend`, `BackgroundFrontend`, `NeedsLogin`, `Cancelled` |
| `backend/icp/vstore/__init__.py` | `UserStore`, `Meta`, `Secrets`, `SyncItem`, `SealError` and the other store exceptions: names and signatures (WP2 fills in the bodies) |
| `backend/icp/daemon/apple.py` | WP3's function signatures (WP3 fills in the bodies) |
| `backend/icp/daemon/autofill.py` | WP6's handler signatures and semantics (WP6 fills in the bodies) |

A package that needs one of these changed asks the integrator; the change lands on `v2-base`
and every branch merges it. Filling in a body marked `raise NotImplementedError` in a file you
own is not a change to the interface; changing a name, a parameter, a return shape or a
documented rule is.

`backend/tests/test_paths_agree.py`, `test_protocol_contract.py` and
`test_v2_interfaces.py` guard the frozen files and must stay green on every branch.

## 2. Ownership

| WP | Owns (only this package edits these) | Deletes |
|---|---|---|
| **WP1** daemon core, policy, units | `backend/icp/daemon/` except `apple.py`, `autofill.py` and the frozen files; `polkit/`; `system/units/`, `system/sysusers.d/`, `system/tmpfiles.d/`, `system/libexec/pear-passwordsd` | `polkit/org.icp.unlock.policy` |
| **WP2** storage, sealing, TPM, legacy import | `backend/icp/vstore/` (bodies of `__init__.py`, new modules); `vault/store.py`, `vault/history.py`, `vault/nicknames.py`, `hme/store.py` (as adapters); `backend/icp/paths.py`; `backend/tests/fixtures/` | `auth/lockbox.py`, `auth/held_key.py` |
| **WP3** Apple pipeline | `backend/icp/cli/`, `backend/icp/auth/` (except the two files WP2 deletes), `backend/icp/octagon/`, body of `backend/icp/daemon/apple.py` | `auth/agent.py`, `auth/prompt.py`, `ui/reauth.py`, `ui/polkit_gate.py`, `cli/appapi.py` |
| **WP4** client side | `native/` (`pear-exec.c` with all four roles), `backend/icp/client/` except `autofill*.py`, `app/`, `plugin/` | `app/launch.sh` |
| **WP5** installer, docs, repo guards | `system/install-root.sh`, `system/uninstall-root.sh`, `system/lib/`, `tools/`, `SHA256SUMS`, `install.sh`, `uninstall.sh`, `README.md`, `docs/` except the frozen files and `docs/autofill-protocol.md`, `manifest.json`, `backend/pyproject.toml`, `systemd/` | `systemd/pear-passwords-sync.{service,timer}` |
| **WP6** autofill host | body of `backend/icp/daemon/autofill.py`; `backend/icp/client/autofill.py` (the native-messaging host); `backend/icp/client/autofill_register.py` and `system/bin/pear-passwords-autofill` (the opt-in register/unregister command); `system/libexec/pear-autofill-host` (wrapper); `system/native-messaging/io.github.dragosol.pearpasswords.json.in` (manifest template); `docs/autofill-protocol.md` | – |

Not in this repository: **the browser extension.** HANCORE would not approve a plugin that
bundles an extension that is not on addons.mozilla.org, so the plugin ships only a generic host
that anyone's extension can use. The owner's own Zen extension lives in the separate local repo
`/home/dragos/Projects/pear-autofill-extension`; WP6 updates it there (click or shortcut only,
origin from the tabs API, host name `io.github.dragosol.pearpasswords`). Nobody pushes that
repo.

Tests: each package adds its tests under `backend/tests/` with its own file names (the spec
lists them per package). WP6's are `test_autofill_origin.py`, `test_autofill_handlers.py`
(fake registry: locked reveals nothing, no-match for unknown and non-matching ids, a prompt
per fill, re-check after approval, rate-limit bucket), `test_autofill_host_framing.py` and
`test_autofill_register.py` (scratch HOME; refuses to overwrite or remove a file whose hash is
not in its receipt).

## 3. Collision rules

1. Edit only files your package owns. Need a change elsewhere? Ask the owner, or the
   integrator for a frozen file.
2. Add new modules only inside directories you own. New shared fixtures go through WP2.
3. Never edit another package's tests to make yours pass.
4. Shared test helpers: put them in your own test file, or ask WP2 to add them to
   `backend/tests/fixtures/`.
5. `backend/pyproject.toml` and `manifest.json` are WP5's. Ask WP5 for entry points or
   package data (for example WP6's `system/bin` wrapper needs no entry point; it runs
   `python -I -m icp.client.autofill_register`).
6. No new runtime dependency beyond `backend/requirements.lock`. jeepney, PyNaCl, cryptography
   are already there.
7. Each package keeps the whole suite green on its branch:
   `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend XDG_CONFIG_HOME=<scratch> python -m pytest -p no:cacheprovider -q backend/tests`.

## 4. Integration contract

### 4.1 WP1 dispatch

`daemon/server.py` reads a line, checks size and JSON, checks `op` against
`protocol.ROLE_OPS[conn.role]` (`unknown-op` / `forbidden`), and calls a handler
`await handler(registry, conn, req)` from one dispatch table. A handler returns the reply
payload without `rid` or raises `protocol.OpError`; the server adds `rid`. Any other exception
is logged and answered `internal`.

| ops | handler | owner |
|---|---|---|
| everything in `ROLE_OPS["ui"]`, `["clip"]`, `["migrate"]` | `daemon/handlers.py` | WP1 |
| `autofill-query` | `daemon.autofill.handle_autofill_query` | WP6 |
| `autofill-fill` | `daemon.autofill.handle_autofill_fill` | WP6 |

WP1 provides to every handler (`protocol.SessionRegistry`):

- `registry.get(uid)` gives the `Session` (`unlocked()`, `store`, `ui`, `settings`);
- `registry.authorize(conn, action, details)` is the only way to raise a polkit dialog. It
  owns sanitizing, the pidfd subject, the per-bucket rate limits and cancel-on-EOF, and raises
  `OpError` on any refusal;
- `registry.run_store(uid, fn, *args)` runs a blocking `UserStore` call in a worker thread under
  that uid's lock;
- `registry.notify_ui(uid, event)` and `registry.connections(uid, role)`.

WP1 also builds the `autofill` hello reply (state collapsed to locked/unlocked/unavailable),
enforces `MAX_AUTOFILL_CONNS`, and sends `{"event":"state"}` to autofill connections on every
lock and unlock. WP6 never touches tickets, grants or sessions directly.

### 4.2 WP1 to WP3 (Apple)

WP1 builds `UserContext(uid, store, anisette_url, frontend)` and calls the functions in
`daemon/apple.py` through `asyncio.to_thread` under the uid's store lock:

| op or trigger | call | frontend |
|---|---|---|
| after `unlock`, scheduler, `sync` | `apple.sync(ctx)` | `None` (questions raise `NeedsLogin`) |
| `signin{mode:"login"}` | `apple.login(ctx)` | WP1's `daemon/frontend.py` socket frontend |
| `signin{mode:"relogin"}` | `apple.relogin(ctx)` | socket frontend |
| `set` | `apple.push_set(ctx, id, fields)` | `None` |
| `create` | `apple.create(ctx, fields)` | `None` |
| `delete` | `apple.delete(ctx, id)` | `None` |
| `signout` | `apple.signout(ctx)` | `None` |

The socket frontend (WP1, `daemon/frontend.py`) implements `context.Frontend` by sending the
sign-in stream of `docs/protocol.md` section 9.2 and blocking the worker thread until the
matching `answer` arrives; cancel or EOF raises `context.Cancelled` in the worker.
`cli/jsonui.py` stays WP3's stdio frontend for development only. Error mapping in WP1:
`NeedsLogin` to `needs-login` (and the `needs-login` event), `AnisetteError` to
`anisette-unavailable`, connection errors to `network`, other `AppleError` to `apple` with a
sanitized `detail`.

`daemon/scheduler.py` and `daemon/apple.py` never import or name the authorization module;
WP1's and WP5's tests grep and walk the AST for it.

### 4.3 WP1 to WP2 (store)

WP1 opens `UserStore.open(uid)` per uid, calls `unlock()` after an approved `.unlock`, then
`reseal_if_tpm_available()`, and `lock()` on every lock trigger. `SealError.kind` becomes the
state and the `unlock` refusal reason. `open_entry` is called once per grant and the result is
kept only for the grant. Migration: `migrate-begin` calls `UserStore.create(uid)`; `import-key`
uses `v1_key_opens` / `v1_key_from_passphrase`; `import-commit` calls `store.import_v1(files,
key)`. `reset` calls `UserStore.reset(uid)`. Settings live in `load_settings` /
`save_settings`.

### 4.4 WP4 roles and pear-exec

`pear-exec` takes exactly one argument, the role, and execs a fixed argv
(`paths.ROLE_TARGETS`):

| role | target | started by | stdin/stdout |
|---|---|---|---|
| `ui` | `/usr/bin/quickshell -p $P/app` | the `.desktop` entry | kept |
| `clip` | `$P/venv/bin/python -I -m icp.client.clip` | the UI, with a ticket on stdin | kept |
| `migrate` | `$P/venv/bin/python -I -m icp.client.migrate` | the UI, with a ticket on stdin | kept |
| `autofill` | `$P/venv/bin/python -I -m icp.client.autofill` | `$P/libexec/pear-autofill-host`, run by the browser | kept (native messaging) |

All four go through the same environment scrub and compositor check. The browser passes its
own arguments (manifest path, extension id or origin) to the host wrapper; the wrapper drops
them and runs `exec $P/libexec/pear-exec autofill`, because pear-exec refuses extra arguments.
WP4's `test_pear_exec_env.py` checks the role table and every path against `system/paths.env`.

The UI's process allowlist gains nothing for autofill: the window never starts the host.

### 4.5 WP5 install

The root step installs, in addition to everything in spec section 4.1:

- `$P/libexec/pear-autofill-host` (root 0755, from `system/libexec/pear-autofill-host`);
- `/usr/local/bin/pear-passwords-autofill` (root 0755, from `system/bin/pear-passwords-autofill`);
- the policy with all four actions, including `.autofill`.

Both new files go in the receipt like every other file. **No native-messaging manifest is
written by `install.sh` or the root step, for any browser.** Autofill is off until the user
runs, once per browser:

```sh
pear-passwords-autofill register --browser zen --extension-id <id>
pear-passwords-autofill unregister --browser zen
pear-passwords-autofill unregister --all
```

`register` writes `io.github.dragosol.pearpasswords.json` from WP6's template into that
browser's user manifest directory and records its hash in a receipt under
`$XDG_STATE_HOME/pear-passwords/autofill-receipts`; it refuses to overwrite a file it did not
write. `unregister` removes only a file whose hash matches the receipt. `uninstall.sh` (WP5)
runs `pear-passwords-autofill unregister --all` before the root uninstall removes the command.
The README gets a section "Autofill (bring your own extension)" pointing at
`docs/autofill-protocol.md`.

### 4.6 Migration and the 1.x host (WP4)

`client/migrate.py` always disables the legacy `icp-host.service`, `icp-sync.*` and
`pear-passwords-sync.*` user units, and, only with the consent checkbox, moves content-matched
`org.icp.native.json` manifests into the v1 backup. It never registers the new host; the
migration screen shows the one `register` command instead. `~/icp` is never touched.

## 5. Decisions the foundation made where the spec was open

1. **Locked autofill.** `autofill-query` and `autofill-fill` work only while the Pear window
   has tier 1 open. Locked, they disclose nothing about any site, never unseal and never
   prompt. A fill while unlocked still raises its own `.autofill` dialog.
2. **Matching without a public suffix list.** No PSL is installed on the target and no new
   dependency is allowed, so "registrable domain" is: exact host or dot-boundary
   sub/parent domain of the entry's domain or sites, where the shorter host has two or more
   labels and is not in a small frozen list of multi-label public suffixes in
   `daemon/autofill.py`. Name-only and inferred-alias matches are never used for autofill.
3. **Line limits.** 64 KiB caps client-to-daemon lines only; daemon-to-client lines may be up to
   8 MiB (554 entries of Meta exceed 64 KiB). `import-file` is chunked at 32 KiB raw.
4. **Passphrase path.** The old passphrase is typed in the window and handed to the importer on
   its stdin, which sends `import-key{passphrase}`; it never travels as an argument.
5. **Purge.** The window cannot unlink files itself (no `rm` in its allowlist), so
   `purge-old-copy` issues a `migrate`/`purge` ticket and the importer deletes the recorded,
   hash-matching files.
6. **Ops the spec implied but did not list:** `release` (selection changed: drop the grant),
   `cancel`, `answer`, `signout`, `totp-preview` (1.3.2 parity for pairing codes), and
   `set.fields.totp` / `nickname` / `sites` for the existing edit screens.
7. **Meta on the wire** carries the 1.3.2 display fields (`primary`, `secondary`, `no_site`,
   `is_wifi`, `ambiguous`) so the list renders as it does today; internal Apple records are
   hidden unless `unlock{all:true}`.
8. **`Secrets.totp_params`** was added next to `totp_secret`, because a code needs digits,
   period and algorithm as well as the seed.
9. **`UserStore.lock()`** has no `keep_session` parameter (that existed only for the lease).
   `status()`, `get_meta()`, `set_sync_status()`, `reset()`, `load/save_device()` and
   `load/save_settings()` were added so no caller reads a file behind the store's back.
10. **Frontend** includes `emit`, `confirm_yn` and `choose` as well as `stage`, `ask` and
    `secret`, because the sign-in flow already calls all six.
11. **Clip outcomes** add `withdrawn` (a lock or a new copy) and `failed` to pasted, expired
    and replaced.
12. **Settings** need no dialog: only the authenticated window can send them, and with the
    lease gone nothing in them widens access beyond one entry for at most 600 s.
