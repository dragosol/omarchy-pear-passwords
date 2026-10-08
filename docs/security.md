# Pear Passwords 2: security design

This is the reviewer's document: what the parts are, who holds which key, what each check is,
what Pear defends against and what it does not, and which test proves each claim. Every claim
below ends with the tests that check it (`Tests:`); `backend/tests/test_docs_claims.py` fails if
a claim has none or names a test that does not exist. The wire protocol is in
[protocol.md](protocol.md), and the browser-facing autofill messages in
[autofill-protocol.md](autofill-protocol.md).

Owner decisions that override the original design: a per-account grant lasts **120 s**, a
clipboard offer **30 s**; the 1.x vault is imported **once**; browser autofill is a generic,
**opt-in** native-messaging host with **no bundled extension**; there is **no sync lease**, so
a locked computer does not sync.

## 1. Components

```
 you (uid 1000)                               |  pear-passwords (system user)
                                              |
 launcher ──> pear-exec ui ──> quickshell     |
              (root:pear-client 2755)  │      |
                                       │ one JSON-lines socket per process
              pear-exec clip ──> pear-clip ───┼──> /run/pear-passwords/client.sock
              pear-exec migrate ──> importer ─┤     (pear-passwords:pear-client 0660)
 browser ──> pear-autofill-host               |        │
              └─> pear-exec autofill ─────────┘        v
                                              |   pear-passwordsd ──> polkitd (system bus)
                                              |        │   CheckAuthorization(pidfd subject)
                                              |        ├──> systemd-creds (host key / TPM2)
                                              |        ├──> /var/lib/pear-passwords/u<uid>/
                                              |        └──> iCloud, anisette 127.0.0.1:6969
```

- **pear-passwordsd** runs as `pear-passwords`, socket-activated, with no capabilities,
  `ProtectSystem=strict`, `ProtectHome=yes`, private /tmp, devices and IPC, a native-only
  `@system-service` syscall filter without `@privileged`, `LimitCORE=0` and a CI exposure
  target of 2.5 or lower in `systemd-analyze security`. Tests: `test_unit_hardening.py`.
- **pear-exec** is the only way to get effective group `pear-client`, which is the only group
  that can open the socket. The group has no members, and the installer and the daemon refuse
  to run if it ever has. Tests: `test_pear_exec_env.py`, `test_daemon_peer.py`,
  `test_install_root_receipts.py::InstallRootTests`.
- **pear-exec** takes exactly one argument (`ui`, `clip`, `migrate` or `autofill`), refuses
  root, builds the environment from scratch (no `LD_*`, `PYTHON*`, `QT_PLUGIN_PATH`, `QML*`
  import paths; XDG homes pointed at an empty root-owned directory; `QML_DISABLE_DISK_CACHE=1`;
  a system-only fontconfig), checks that `WAYLAND_DISPLAY` is the user's oldest Hyprland, and
  executes a fixed root-owned argv only if every path and parent is root-owned and not group-
  or other-writable. The set-gid exec makes the child non-dumpable whatever `ptrace_scope` is.
  Tests: `test_pear_exec_env.py`.
- **The window** has no `IpcHandler`, renders every `Text` as plain text, logs no values, and
  starts only a fixed list of programs. Tests: `test_qml_no_ipc.py`,
  `test_qml_text_plain.py`, `test_qml_no_console_log.py`, `test_qml_process_allowlist.py`.
- **pear-clip** speaks the Wayland data-control protocol itself and holds the value in memory.
  It identifies each reader by the pipe it hands over: Omarchy's history watcher gets nothing,
  any other reader is the one counted paste, and the offer is withdrawn after that paste or
  30 s. It never uses `wl-copy` (which stages its input in `/tmp`). Tests:
  `test_clip_policy.py`, `test_repo_guards.py::ClipboardGuardTests`.

## 2. Key hierarchy

Per user, in `/var/lib/pear-passwords/u<uid>/` (0700 `pear-passwords`; your uid cannot list it):

| File | What it is |
|---|---|
| `keys/list.cred` | `RK_list`, 32 random bytes, sealed by `systemd-creds --user` under uid `pear-passwords`, `--with-key=auto --tpm2-pcrs= --tpm2-public-key=` |
| `keys/secret.cred` | `SK_secret`, the X25519 private key that opens entries, sealed the same way |
| `keys/secret.pub` | `PK_secret` plus a MAC under the metadata key, so it cannot be swapped |
| `meta.v2`, `aliases.v2`, `nicknames.v2`, `session.v2` | XChaCha20-Poly1305 under subkeys of `RK_list` (HKDF-SHA256), with the file kind, uid and name in the associated data |
| `entries/<id>.box`, `history/<id>/<n>.box` | `crypto_box_seal` to `PK_secret`, padded, with the id inside |

- A file that fails to decrypt is reported as `damaged` and **never deleted**; files cannot be
  swapped between names or users. Tests: `test_store_v2.py`.
- Sync and edits write with the public key only and detect changes with
  `HMAC(K_pwmac, password)`, so sync never unseals `SK_secret`. Tests:
  `test_pwmac_sync_diff.py`.
- In memory: nothing while locked; `RK_list`, its subkeys and the metadata after the first
  dialog; one entry's fields for at most the grant (120 s) after the second. Tests:
  `test_grants.py`, `test_logind_lock.py`.
- Re-sealing to host+TPM2 happens at the first unlock after a TPM appears; the old blobs stay
  as `*.prev` until the next successful unlock, and a missing TPM is told apart from a cleared
  one. Tests: `test_seal_reseal.py`.

## 3. Peer verification

On every accept the daemon reads `SO_PEERCRED` (gid must be `pear-client`, uid at least
1000), takes `SO_PEERPIDFD` for the life of the connection, checks `/proc/<pid>/status`
(real gid = the user's, effective = `pear-client`, real = effective uid), records the start
time and confirms the pid with `pidfd_send_signal(pidfd, 0)`. One `ui` connection per uid;
`clip` and `migrate` need a single-use ticket issued on that uid's UI connection within 10 s,
and must be children of that UI process. Tests: `test_daemon_peer.py`, `test_tickets.py`,
`test_protocol_limits.py`.

## 4. Prompts

Four polkit actions, each `auth_self` for active sessions and `no` for any and inactive, with
no `_keep` and the owner annotation `unix-user:pear-passwords` that lets the non-root daemon
check other users' subjects. The subject is the caller's pidfd. Tests: `test_policy_file.py`,
`test_policy_readme_sync.py`, `test_repo_guards.py::PolicyGuardTests`,
`test_daemon_polkit.py`.

- Only the ops in protocol.md section 5 raise a dialog, with user interaction allowed only
  while handling one of them; one outstanding and three answered dialogs per minute per bucket
  (`ui` and `autofill`). Tests: `test_daemon_polkit.py`, `test_protocol_contract.py`.
- The scheduler and the Apple pipeline never import or name the polkit module, and no
  `AllowUserInteraction` appears in them. Tests: `test_scheduler_no_prompt.py`,
  `test_repo_guards.py::BackgroundNeverPromptsTests`.
- Nothing else prompts: no zenity, `systemd-ask-password`, getpass or passphrase prompt
  anywhere in the backend or the window. Tests: `test_no_secret_prompts.py`,
  `test_apple_ctx.py`.

## 5. Autofill

- Off until the user runs `pear-passwords-autofill register`; no installer writes a manifest.
  `unregister` removes only a manifest whose hash its receipt recorded. Tests:
  `test_autofill_register.py`, `test_repo_guards.py::InstallerWritesNoManifestTests`.
- While the uid is locked, `autofill-query` answers only `locked` (or `unavailable`), and
  `autofill-fill` answers `locked`: nothing reveals which sites have accounts. Every fill
  raises `.autofill` with the account and the origin's host, and is re-checked after approval.
  An unknown id and a non-matching id give the same `no-match`. Tests:
  `test_autofill_handlers.py`.
- Origins must be `https` with an ASCII host; matching is exact host or a dot-boundary
  sub/parent domain that is not a public suffix. Tests: `test_autofill_origin.py`,
  `test_autofill_host_framing.py`.

## 6. Installer

- The root step runs from a root-owned copy of the stage checked against the published hash of
  `SHA256SUMS`; it refuses symlinks and unlisted files, installs wheels offline with
  `--require-hashes`, and compiles `pear-exec` from source. Tests:
  `test_sha256sums_current.py`, `test_install_root_receipts.py::InstallRootTests`.
- A path is overwritten or removed only if its bytes are the staged file, the receipt's record,
  or a frozen released copy (the 1.x `org.icp.unlock.policy`). Foreign, edited and symlinked
  destinations, same-named units, drop-ins and policies, and a `pear-client` group with members
  stop the install before any write. Tests: `test_install_root_receipts.py::InstallRootTests`.
- Uninstall removes only receipt-matching files, keeps edited ones in the receipt, and keeps
  the vault and the service user unless `--purge <uid>` is confirmed by typing. Tests:
  `test_install_root_receipts.py::UninstallRootTests`.
- The user step removes 1.x files from your home only on an exact hash match. Tests:
  `test_install_user_files.py`.

## 7. Threat model

| Attacker | Outcome | Notes |
|---|---|---|
| A copy of `~/.config/icp` or all of `/home` | Holds | After the move nothing in `/home` decrypts anything; the renamed v1 backup is sealed by the old passphrase only. |
| A program running as you, any `ptrace_scope` | Mostly holds | No socket access, no state access, no unseal, no ptrace or `/proc` reads of Pear's processes, no injection. Residual: clipboard during an offer, screen capture of a revealed value, starting Pear to show a dialog, a rival polkit agent phishing the login password, denial of service. |
| Another local user | Holds | Per-uid state; the subject's uid must match; `auth_self`. |
| Remote login as you | Holds | `allow_any=no`, `allow_inactive=no`; pear-exec needs a local compositor. |
| Network | Holds | TLS verified, `trust_env=False`, no redirects, `icloud.com` endpoint check. |
| Disk image or backup of `/` with the host key, PTT off | Does not hold | Only LUKS protects it. |
| The same with PTT on | Holds | Blobs need this TPM. |
| Stolen laptop, off, locked, suspended or hibernated | Holds | Keys wiped on Lock, LockedHint and PrepareForSleep. |
| Root, the kernel, `empower`, `/etc/polkit-1/rules.d` | Not defended | Same position as systemd-homed. |
| Old v1 ciphertext in snapshots | Residual | Crackable by guessing the old passphrase. |

Tests for the locking rows: `test_logind_lock.py`. Tests for the network row:
`test_authenticated_transports.py`, `test_webauth.py::TlsVerificationTests`.

## 8. Verification gates (VM, before release)

These are run in an Arch VM with swtpm and a nested Hyprland, never on the owner's laptop, and
their results are recorded here. Each has a decided fallback. Status: **not yet run**.

| Gate | What | Fallback | How the fallback is switched on |
|---|---|---|---|
| G1 | `systemd-creds --user` from uid `pear-passwords` inside the hardened unit | root's `pear-passwords-seal.socket` (Accept=yes) runs system-scope `systemd-creds` for the daemon, one request per connection, only for the daemon's uid and `pear.(list\|secret).u<uid>` names (`icp.vstore.seal_service`) | an active `Environment=PEAR_SEAL_BACKEND=seal-service` line in the shipped `pear-passwordsd.service`; `install-root.sh` then enables the seal socket (installed, never enabled, otherwise) |
| G2 | polkit accepts a pidfd `unix-process` subject; `$(account)` shows | `{pid, start-time, uid}`, fixed message | `Environment=PEAR_POLKIT_SUBJECT=pid-start-time` in the shipped unit |
| G3 | Quickshell starts with egid != rgid under AT_SECURE | redesign the identity step | none: no release without one of the two |
| G4 | Quickshell with empty XDG homes and no disk cache; what it opens under `$HOME` | allowlist the residue | docs only |
| G5 | pear-clip can identify a reader's pipe at `ptrace_scope` 1 and 2 | a 250 ms window, documented as weaker | `READER_POLICY = "timing"` in `icp/client/clip.py` (root-owned; pear-exec passes no environment) |
| G6 | logind `Lock`, `LockedHint`, `PrepareForSleep` with Omarchy's lock | forward Hyprland's lock event | **not built**: which Hyprland event marks a session lock is for this gate to find; window close and the Lock button lock either way |
| G7 | what `CheckAuthorization` returns with no agent | under 300 ms non-dismissed failure = no agent | this classification is what ships |
| G8 | `MemoryDenyWriteExecute=yes` with cffi, cryptography, srp; Argon2id at 256 MiB | drop MDWE, documented | delete the `MemoryDenyWriteExecute=yes` line |

Tests for the switches: `test_seal_service.py`, `test_install_root_receipts.py::InstallRootTests::test_seal_service_runs_only_when_the_daemon_unit_selects_it`, `test_daemon_polkit.py`, `test_clip_policy.py::TimingFallbackTests`.

## 9. Rejected simplifications

Each of these was considered and rejected because it leaves a hole:

| Option | Why it fails |
|---|---|
| A user-level agent behind polkit (1.3.x) | Any process running as you skips the gate and talks to the agent or reads its files; the verdict is an exit code your own code reads. |
| `systemd-creds --user` alone | Any process of your uid decrypts it with no prompt (tested). |
| App-side system-scope `systemd-creds decrypt` | `auth_admin_keep`: one approval lasts about 5 minutes, per-account prompts stop working, the message cannot be branded, and the plaintext lands in a process running as you. |
| A daemon that serves any same-uid caller after polkit | An impostor can trigger a genuine-looking dialog and receive the result. |
| `wl-copy` for secrets | wl-clipboard 2.3.0 stages its input in a `/tmp` file. |
| A timing grace window for clipboard readers | It hands the value to whoever reads first; reader identification replaces it. |
| A user sync timer or a sync lease | Background activity that could prompt, or hold Apple tokens while the window is closed. |
| A bundled browser extension | Not reviewable as part of the plugin; the generic host plus a documented protocol replaces it. |

## 10. Corrections to earlier claims

1.x documentation and comments said things that were wrong. For the record:

- "polkit-1 includes system-auth" (in the 1.x policy comment and README): it does not on Arch;
  `/etc/pam.d/polkit-1` has its own stack. Fingerprint works because Omarchy configures it.
- "`ALWAYS_CHECK` forces a prompt": it only affects root subjects. 2.0 relies on plain
  `auth_self` without `_keep`, which prompts every time. Tests: `test_policy_file.py`.
- "Same-uid code can read the agent's key through `/proc`": wrong at `ptrace_scope` 1 or more
  for a process that is not a descendant. The 1.x agent's real weakness was the socket, which
  any same-uid process could talk to.
- The 1.x `appapi` comment "can already read vault.key" was stale: 1.0.1 removed `vault.key`.
- The 1.x comment that `wl-copy -o` clears the clipboard after one paste was false: `-o` serves
  one paste and exits, and the timer it relied on cleared whatever was on the clipboard then.

## 11. Open items

- The anisette base images' `apt-get` packages are resolved at build time and not pinned
  ([anisette-provenance.md](anisette-provenance.md)).
- The gates in section 8 have not run yet.
- Python cannot reliably zero memory; QML strings cannot be zeroed at all. A revealed value is
  overwritten after 20 s or on focus loss, not wiped.
