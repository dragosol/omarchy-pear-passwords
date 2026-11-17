# Anisette provenance

Apple's sign-in will not talk to a client that cannot produce anisette data, a
machine fingerprint that normally comes from Apple's own software. Pear Passwords
gets it from a small server in a podman container on `127.0.0.1:6969`: Apple's
Windows ADI library, `CoreADI64.dll` from iCloud for Windows, run under Wine by
Pear's loader (`anisette/loader`), which is built on Dadoum's
[apple-crates](https://tangled.org/dadoum.zone/apple-crates). This document says
exactly where that code and that DLL come from, and which parts of the chain are
authenticated and which are not.

## Why Windows

Until 2.0.4 the container ran [anisette-v3-server](https://github.com/Dadoum/anisette-v3-server),
which loads the ADI libraries from Apple Music for Android. Since October 2026
Apple's GrandSlam compares the platform a client names in `X-Mme-Client-Info`
with the platform of the ADI library that made its one-time password, and Apple ID
sign-in is not served to Android clients at all
([anisette-v3-server#61](https://github.com/Dadoum/anisette-v3-server/issues/61)).
Measured on 2026-11-11 with GrandSlam's first sign-in step for an account that
does not exist, where the right answer is an ordinary "wrong account" error:

| ADI library | Client identity | Answer |
| --- | --- | --- |
| Android (anisette-v3-server) | Pear's Mac identity | `-80045` |
| Android | `<PC> <Windows;…> <com.apple.AuthKit/1 (com.apple.akd/1.0)>` | HTTP 403 |
| Windows (`CoreADI64.dll`) | `<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>` | `-20970`, ordinary |
| Windows | Pear's Mac identity | `-80044` |

So the server runs the Windows DLL, and Pear names itself as iCloud for Windows
on every account call (`backend/icp/const.py`).

## What the container is

`pear-coreadi.exe`, a Windows program built from `anisette/loader` against
apple-crates, run by Wine (Fedora's `wine-core`, 64-bit only). It loads
`CoreADI64.dll` and nothing else from Apple, provisions the machine with Apple
once, and then answers `GET /` with a fresh set of machine headers. It serves
nothing else but `/healthz`.

The machine is the Wine prefix in the podman volume `pear-passwords-anisette`:
CoreADI keeps its provisioning there, and that identity is what Apple binds 2FA
trust to, which is why the volume outlives restarts. CoreADI also derives the
device id from the network adapter's MAC address and the computer name. A
container gets fresh ones on every start, so the unit fixes both: the MAC to one
locally administered address, the computer name to the host's machine id (`%m`),
so that two machines never present the same device. Apple sees the machine id only
hashed into that device id.

2.0's Android identity stays in the old `icp-anisette` volume, unused.
`./uninstall.sh --purge` deletes both.

## Which source it is built from

    repository  https://tangled.org/dadoum.zone/apple-crates
    commit      b6e2ac2e5eb971fed221e298a043d6a61402645b
    date        2026-10-27
    license     MPL (stated by the author on anisette-v3-server#61, 2026-11-13,
                replacing the LGPL-2.1-or-later he named first; the version and the
                license file are to follow in the repository)

`anisette/Containerfile` builds against that commit and nothing else. It fetches
the commit by its full 40-character SHA and aborts if `git rev-parse HEAD` does
not come back equal to it. The loader uses three of its crates: `adi`,
`library-coreadi` (which loads the DLL) and `grandslam` (which provisions). Every
crates.io dependency is pinned, with its checksum, by `anisette/loader/Cargo.lock`,
and the build runs `cargo build --locked`, which refuses to change it.

The image tag is the apple-crates revision plus the id of Pear's own recipe,
printed by `anisette/recipe-id.sh`: a hash of every file in `anisette/` that goes
into the image. Both are also labels on the image:

    podman image inspect --format \
        '{{index .Labels "io.github.dragosol.pear-passwords.apple-crates.revision"}} {{index .Labels "io.github.dragosol.pear-passwords.recipe"}}' \
        localhost/pear-passwords-anisette:b6e2ac2e5eb971fed221e298a043d6a61402645b-<recipe>

Build it with `anisette/build.sh`. `install.sh` does this for you if no image
with that revision and recipe exists, and then restarts the unit so it runs the
new image. Nothing is pulled from a registry except the two base images, which
are pinned by digest.

The loader (Pear's code, MIT) uses apple-crates' files unmodified and is built on
this machine, never distributed as a binary; the MPL's file-level terms are met
by apple-crates' source being fetched from its own repository at the pinned commit.

### Provisioning's TLS to Apple

`grandslam` talks to `gsa.apple.com` with reqwest over rustls, verifying the
certificate chain against the system roots plus Apple Root CA, which it bundles
(the same certificate as `backend/icp/certs/apple-root-ca.pem`). Peer
verification is never turned off. The provisioning endpoints come from Apple's
URL bag, fetched over that same verified connection.

## The DLL, and how it is delivered

`CoreADI64.dll` is Apple's, closed source, and its licence does not allow Pear to
redistribute it, so it is not in this repository or in the image. On first start
`anisette/entrypoint.sh` runs `anisette/fetch-coreadi.py`, which takes it from the
Microsoft Store package of iCloud for Windows, downloaded anonymously (no
account) through the Store's delivery service:

    product   9PKTQ5699M62 (iCloud for Windows, Apple Inc.)
    package   AppleInc.iCloud_15.10.39.0_x64__nzyj5cx40ttqa  (337 MB)
    sha256    bdca7b5b8b2819d758cd7ba4ea25bd87b7cca1ae7dc25627e6cd02248d8d38ca
    sha1      P1Kpw7IV6KPQTx4bY13iRTC5uyA=  (as the Store lists it)
    member    iCloud/CoreADI64.dll
    sha256    687133100a588c9da6e12d14b0a7a40be6c0870bd93cac9486866576f83298b0
    version   iCloud for Windows 15.10.0.39

The Store hands out a download URL that expires within hours, so the URL is not
pinned: it is asked for on each fetch. What is pinned, in `anisette/coreadi.sha256`,
is what it serves. The fetcher picks the package by its moniker and by the SHA-1
the Store lists for it, downloads it, and refuses it unless its SHA-256 matches;
then it refuses the DLL inside unless that matches too. Only then is the DLL
written to the volume. The other 335 MB are deleted.

The Store's delivery host chains to Microsoft Root Certificate Authority 2011,
which most Linux CA bundles leave out, so that one root
(`anisette/microsoft-root-ca-2011.pem`, SHA-256
`847DF6A7…ED7C61`) is the only anchor trusted for it. The product lookup
uses the system CA bundle. The package itself comes from Microsoft's CDN over
plain HTTP; the digests are what make it safe to use.

Every start checks the DLL in the volume again, and a mismatch stops the server
rather than being reported next to a running one: the volume outlives the image
and is writable, so an earlier start having written it is not evidence. The gate,
the digests and the CA file are root-owned and read-only in the image, and the
server runs as an unprivileged user.

### When the Store stops offering 15.10.39

The fetch then fails with "the Store no longer offers …" and nothing is
installed. A DLL already in the volume keeps working. To move to a newer iCloud,
record the new package's moniker, SHA-1 and SHA-256 and the new DLL's SHA-256 in
`fetch-coreadi.py` and `coreadi.sha256`, check that `library-coreadi` still loads
it, and release that as a reviewed change.

## Summary of what is and is not authenticated

| Link | Status |
| --- | --- |
| apple-crates revision | Pinned to a full commit SHA and enforced at build time |
| Loader binary | Built here from Pear's source and that revision, labelled with both |
| Rust dependencies | Pinned with checksums by `Cargo.lock`, built `--locked` |
| Provisioning TLS to Apple | Verified against system roots plus Apple Root CA |
| Base images | Pinned by digest |
| Fedora / Debian packages inside them | Not pinned, resolved at build time |
| Build reproducibility | Not bit-reproducible; the revision and recipe labels are the pin |
| apple-crates history | Trusted, not independently verified; commits not signature-checked |
| apple-crates license | MPL per its author; no license file or version at the pinned commit |
| DLL origin | The Microsoft Store's iCloud for Windows package, Apple Inc. |
| Store delivery TLS | Microsoft Root Certificate Authority 2011 only |
| Package and DLL bytes | Pinned by SHA-256 in `coreadi.sha256`, enforced before the DLL is written and on every start |
| Download URL | Not pinned; it expires within hours. Only what it serves is checked |
| Package signature | The MSIX's own signature is not verified; the digests stand in for it |
| What the DLL does | Closed source and unaudited; pinning names the bytes, not their behaviour |
