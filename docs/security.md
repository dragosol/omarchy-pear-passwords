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
- **The window** has no `IpcHandler`, renders every `Text` as plain text, logs no values, binds
  neither the primary selection nor a text-input protocol (`QT_WAYLAND_DISABLED_INTERFACES`
  from pear-exec), and starts only a fixed list of programs. The Omarchy components it
  instantiates (Commons `Style`, `Color`, `Util`; Ui `Button`, `TextField`) add exactly
  `hyprctl -j getoption decoration:rounding|general:gaps_out` and `fc-match -f %{family[0]}
  monospace` (through PATH=/usr/bin, with egid pear-client) and read
  `~/.local/state/omarchy/current/theme/{colors,shell}.toml`, `~/.config/omarchy/shell.toml`,
  and (watch only) `~/.config/fontconfig/fonts.conf` and
  `~/.local/state/omarchy/toggles/hypr/window-no-gaps.lua`: a same-uid program can change the
  window's colours and sizes, not its contents. Both lists are pinned by tests, so an Omarchy
  update that adds to them fails. Quickshell's runtime directory lets the same user kill the
  window (`qs kill`); its log holds no account data. Tests: `test_qml_no_ipc.py`,
  `test_qml_text_plain.py`, `test_qml_no_console_log.py`, `test_qml_process_allowlist.py`,
  `test_qml_grant_flow.py`, `test_pear_exec_env.py`.
- **pear-clip** speaks the Wayland data-control protocol itself and holds the value in memory.
  It identifies each reader by the pipe it hands over: Omarchy's history watcher gets nothing,
  any other reader is the one counted paste, and the offer is withdrawn after that paste or
  30 s. It never uses `wl-copy` (which stages its input in `/tmp`). Tests:
  `test_clip_policy.py`, `test_repo_guards.py::ClipboardGuardTests`.

## 2. Key hierarchy

Per user, in `/var/lib/pear-passwords/u<uid>/` (0700 `pear-passwords`; your uid cannot list it):

| File | What it is |
|---|---|
| `keys/list.cred` | `RK_list`, 32 random bytes, sealed by `systemd-creds --user` under uid `pear-passwords`. In uid scope the request goes through systemd's credentials service, which takes no PCR, public-key or (on systemd 261) key-type choice, so it always uses `auto`: host key, plus TPM2 when one is usable, no PCRs. Pear reads the key type back from the credential header and records that; it refuses an unscoped, TPM-only, null or public-key-bound blob, and seals nothing with a TPM while a `tpm2-pcr-public-key.pem` exists (that would bind the keys to a signed PCR policy) |
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
- Moving to host+TPM2 happens at the first unlock after a TPM appears, and it is a key
  rotation, not a re-wrap: a new `RK_list` and `SK/PK`, every file re-encrypted and every box
  re-sealed in `u<uid>.rotate`, read back through a real unseal and compared, then swapped in
  with one `renameat2(RENAME_EXCHANGE)`; the old tree is deleted at once and a leftover is
  removed by the next unlock. No host-only copy of a key that opens current data survives, so
  a pre-PTT backup opens only the vault as it was then. A missing TPM is told apart from a
  cleared one. A cleared TPM is recognised by its storage key fingerprint where systemd-tpm2-setup
  writes one (measured, UKI boots); on other boots (Limine or GRUB without a UKI) a working
  TPM that refuses the keys is reported as `tpm-cleared` too, with "most likely" wording. A
  failure of the mechanism itself (the credentials service unreachable, a busy or locked-out
  TPM) is transient and never becomes a seal state: a non-zero exit counts as a refusal only
  when a throwaway value still round-trips. Tests: `test_seal_reseal.py`,
  `test_seal_service.py`.

## 3. Peer verification

On every accept the daemon reads `SO_PEERCRED` (gid must be `pear-client`, uid at least
1000), takes `SO_PEERPIDFD` for the life of the connection, checks `/proc/<pid>/status`
(real gid = the user's, effective = `pear-client`, real = effective uid), records the start
time and confirms the pid is still that process by polling the pidfd (it turns readable when
the process exits; a signal 0 would be EPERM for another uid's process). One `ui` connection per uid;
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
  while handling one of them; one outstanding dialog per bucket (`ui` and `autofill`), and at
  most three refused (dismissed or denied) dialogs per minute per bucket and action; approvals
  are not counted. A polkitd refusal of the call itself is `internal`, never "no agent". Tests: `test_daemon_polkit.py`, `test_protocol_contract.py`.
- The scheduler and the Apple pipeline never import or name the polkit module, and no
  `AllowUserInteraction` appears in them. Tests: `test_scheduler_no_prompt.py`,
  `test_repo_guards.py::BackgroundNeverPromptsTests`.
- Nothing else prompts: no zenity, `systemd-ask-password`, getpass or passphrase prompt
  anywhere in the backend or the window. Tests: `test_no_secret_prompts.py`,
  `test_apple_ctx.py`.

## 5. Autofill

- Off until the user turns it on in the window (`autofill-enable`, one `.manage` dialog): until
  then the daemon refuses the autofill `hello`, and turning it off disconnects every host.
  The browser manifest is not the opt-in, because `pear-exec autofill` runs for any program
  of the user. No installer writes a manifest; `unregister` removes only a manifest whose hash
  its receipt recorded. Tests: `test_daemon_handlers.py::AutofillOptInTests`,
  `test_autofill_register.py`, `test_repo_guards.py::InstallerWritesNoManifestTests`.
- While autofill is on, any same-uid program can connect as an autofill host. A query gives it
  ids only, no usernames or labels, until a fill on that connection is approved; every fill is
  its own `.autofill` dialog, which says a browser extension is asking, and the window shows
  when a host is connected. Residual: a program that gets the user to approve one fill dialog
  receives that password. Tests: `test_autofill_handlers.py`,
  `test_autofill_host_framing.py`.
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
| A program running as you, any `ptrace_scope` | Mostly holds | No socket access except the autofill role while autofill is on, no state access, no unseal, no ptrace or `/proc` reads of Pear's processes, no injection. Residual: clipboard during an offer, screen capture of a revealed value, starting Pear to show a dialog, an autofill fill dialog approved by mistake (that one password), a rival polkit agent phishing the login password, denial of service, and control of the compositor (below). |
| Another local user | Holds | Per-uid state; the subject's uid must match; `auth_self`. |
| Remote login as you | Holds | `allow_any=no`, `allow_inactive=no`; pear-exec needs a local compositor. |
| Network | Holds | TLS verified, `trust_env=False`, no redirects, `icloud.com` endpoint check. |
| Disk image or backup of `/` with the host key, PTT off | Does not hold | Only LUKS protects it. |
| The same with PTT on | Holds | Blobs need this TPM. A pre-PTT copy still opens the data as it was then (the keys were rotated, so nothing written later); delete such snapshots. |
| Stolen laptop, off, suspended or hibernated | Holds | Keys wiped on PrepareForSleep (and on logind Lock and LockedHint where the locker sends them). |
| Stolen laptop, awake behind Omarchy's screen lock, Pear unlocked | Does not hold | Omarchy's lock emits neither Lock nor LockedHint and G6 is not built: the keys stay until Lock, window close, idle lock or sleep. |
| A program controlling the compositor (Hyprland plugin load or virtual keyboard/pointer, allowed by Hyprland's default `ecosystem:enforce_permissions = false`) | Does not hold | Sees what the window shows (the unlocked list, revealed values), reads what is typed into it (Apple password, 1.x passphrase, new passwords), can click Copy inside an approved grant and remove `no_screen_share`. Mitigation: `enforce_permissions = true` with `permission` rules denying `plugin` and `keyboard`, screen capture on ask. |
| Root, the kernel, `empower`, `/etc/polkit-1/rules.d` | Not defended | Same position as systemd-homed. |
| Old v1 ciphertext in snapshots | Residual | Crackable by guessing the old passphrase. |

Tests for the locking rows: `test_logind_lock.py`. Tests for the network row:
`test_authenticated_transports.py`, `test_webauth.py::TlsVerificationTests`.

## 8. Verification gates (VM, before release)

These are run in an Arch VM with swtpm and a nested Hyprland, never on the owner's laptop, and
their results are recorded here. Each has a decided fallback.

**Status: run on v2 at 380de03** (2026-10, on the build box): a podman Arch container with
systemd as PID 1 for the install path, G1 host key, G2, G3, G4, G5 at `ptrace_scope` 0, G7, G8
and `systemd-analyze`; an Arch cloud-image VM (KVM, OVMF UEFI, swtpm) for `ptrace_scope` 0, 1
and 2, the TPM re-seal, `tpm-missing`, `tpm-cleared` and autofill. As shipped at 380de03 every
connection was refused (the peer liveness check used signal 0, which is EPERM for another
uid's process); the gates below ran with that one line patched in the test environment, and
the fix is now in the tree (`test_daemon_peer.py`). Real Hyprland could not run headless there
(no DRM render node), so G3 and G5 used a test build of `pear-exec` that accepts sway as the
compositor, and the real Omarchy polkit agent was replaced by pkttyagent's text agent
registered for the session. Not run: real Hyprland, the Omarchy agent (fingerprint first),
XWayland paste, the clipboard under load, G6, and a real browser extension.

| Gate | What | Result | Fallback | How the fallback is switched on |
|---|---|---|---|---|
| G1 | `systemd-creds --user` from uid `pear-passwords` inside the hardened unit | **Passes** with the host key: round trip, wrong `--name` refused, tampered blob refused. swtpm with **UEFI** (OVMF): `has-tpm2` yes and the first unlock moved to TPM-sealed keys; under legacy BIOS (SeaBIOS) `has-tpm2` reports `-firmware` and Pear stays host-sealed, so the TPM path needs UEFI with TCG2. `tpm-missing` passes. `tpm-cleared` **failed** at 380de03 (reported `damaged`: the SRK PEM exists only on measured UKI boots); fixed since, see section 2. The fallback also passes (bonus run). | root's `pear-passwords-seal.socket` (Accept=yes) runs system-scope `systemd-creds` for the daemon, one request per connection, only for the daemon's uid and `pear.(list\|secret).u<uid>` names (`icp.vstore.seal_service`) | an active `Environment=PEAR_SEAL_BACKEND=seal-service` line in the shipped `pear-passwordsd.service`; `install-root.sh` then enables the seal socket (installed, never enabled, otherwise) |
| G2 | polkit accepts a pidfd `unix-process` subject; `$(account)` shows | **Passes** (with the liveness fix): the owner annotation is what lets uid `pear-passwords` check other users' subjects (`nobody` gets `NotAuthorized`); the dialog showed `Use the saved password for Work GitHub — dev@example.test`; grants are per entry; a seatless session and a process with no session are denied with no dialog. | `{pid, start-time, uid}`, fixed message | `Environment=PEAR_POLKIT_SUBJECT=pid-start-time` in the shipped unit |
| G3 | Quickshell starts with egid != rgid under AT_SECURE | **Passes** (sway build): Quickshell ran with `Gid: 1000 969 969 969`, passed the daemon's peer checks, unlocked through polkit and drew the list. Labels and background did not draw in the container either with or without set-gid (no theme there); to be checked visually on the XPS. | redesign the identity step | none: no release without one of the two |
| G4 | Quickshell with empty XDG homes and no disk cache; what it opens under `$HOME` | **Passes, with residue now documented** (section 1): QML only from `$P/app` and `/usr/share/omarchy`; under `$HOME`: `~/.drirc` (Mesa), Omarchy's theme and toggle files, and the `hyprctl`/`fc-match` children; Quickshell's runtime directory lets the same user `qs kill` the window; `qs ipc show` is empty and its log holds no account data. | allowlist the residue | docs only (and pinned by `test_qml_process_allowlist.py`) |
| G5 | pear-clip can identify a reader's pipe at `ptrace_scope` 1 and 2 | **Passes** at 0, 1 and 2: Omarchy's history watcher never got the password, the first paste got it and a second reader nothing, no paste expires at 30 s, an unrelated copy is `replaced` and survives, `x-kde-passwordManagerHint` offered. `mem`, `environ`, `fd`, `maps` of the UI and clip processes are EACCES and PTRACE_ATTACH EPERM at every scope. | a 250 ms window, documented as weaker | `READER_POLICY = "timing"` in `icp/client/clip.py` (root-owned; pear-exec passes no environment) |
| G6 | logind `Lock`, `LockedHint`, `PrepareForSleep` with Omarchy's lock | **Not run.** Omarchy's lock emits neither `Lock` nor `LockedHint` (checked in its source), so a screen lock does not lock Pear; README and section 7 say so. | forward Hyprland's lock event | **not built**: window close, the Lock button, idle lock and sleep lock either way |
| G7 | what `CheckAuthorization` returns with no agent | **Passes**: `[false, true, {"polkit.result":"auth_self"}]` in 1-2 ms with no `polkit.dismissed`, reported `no-agent`; a wrong password is `denied` after 2.3 s. A polkitd refusal of the call itself is now `internal`, not `no-agent`. | under 300 ms non-dismissed failure = no agent | this classification is what ships |
| G8 | `MemoryDenyWriteExecute=yes` with cffi, cryptography, srp; Argon2id at 256 MiB | **Passes**: PyNaCl, cryptography (P-384, X25519, AES-GCM, HKDF) and srp work under MDWE; Argon2id moderate took 0.17 s, 293 MiB maxrss. Old-style cffi `ffi.callback` would fail, and the code does not use it. | drop MDWE, documented | delete the `MemoryDenyWriteExecute=yes` line |

Also from that run: the install path, re-runs, upgrades and every refusal passed; uninstall
left `/run/pear-passwords/client.sock` behind and with it the identities (fixed: the sockets
`RemoveOnStop=yes`, uninstall removes stale runtime sockets and keeps itself while the
identities stay); idle exits logged an unlink error for systemd's socket (fixed:
`cleanup_socket=False`); an ABI mismatch restarted into the start limit (fixed:
`RestartPreventExitStatus=78`); the three-a-minute dialog limit blocked a third account
(fixed: only refusals count, per action). `systemd-analyze security`: 1.5 for
`pear-passwordsd.service`, 1.2 for `pear-passwords-seal@.service`; `systemd-analyze verify`
clean. Failed dialog passwords count toward `pam_faillock` like any other: three wrong ones
lock the account for ten minutes (Arch's default).

Tests for the switches: `test_seal_service.py`, `test_install_root_receipts.py::InstallRootTests::test_seal_service_runs_only_when_the_daemon_unit_selects_it`, `test_daemon_polkit.py`, `test_clip_policy.py::TimingFallbackTests`.

## 9. Rejected simplifications

Each of these was considered and rejected because it leaves a hole:

| Option | Why it fails |
|---|---|
| A user-level agent behind polkit (1.3.x) | Any process running as you skips the gate and talks to the agent or reads its files; the verdict is an exit code your own code reads. |
| `systemd-creds --user` alone | Any process of your uid decrypts it with no prompt (tested). |
| App-side system-scope `systemd-creds decrypt` | `auth_admin_keep`: one approval lasts about 5 minutes, per-account prompts stop working, the message cannot be branded, and the plaintext lands in a process running as you. |
| A daemon that serves any same-uid caller after polkit | An impostor can trigger a genuine-looking dialog and receive the result. The autofill role is the one accepted exception, off until turned on in the window, with a dialog that names a browser extension and no account names before an approved fill. |
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
- Gates G6 (screen lock) and the parts of G3/G5 that need real Hyprland and the Omarchy
  polkit agent have not run (section 8).
- Python cannot reliably zero memory; QML strings cannot be zeroed at all. A revealed value is
  overwritten after 20 s or on focus loss, not wiped.
