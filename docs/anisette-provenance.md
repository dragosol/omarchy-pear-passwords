# Anisette provenance

Apple's sign-in will not talk to a client that cannot produce anisette data, a
fingerprint that normally comes from macOS. Pear Passwords gets it from
[anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) by Dadoum,
running in a podman container on `127.0.0.1:6969`. This document says exactly
where that code and those libraries come from, and which parts of the chain are
authenticated and which are not.

## What the container is

A single static binary, built from D source, that serves anisette data over
HTTP. It keeps a machine identity in `adi.pb` and `device.json` inside the
podman volume `icp-anisette`; that identity is what Apple binds 2FA trust to,
which is why the volume outlives restarts.

It is third-party code and is not part of this repository.

## Which source revision it is built from

    repository  https://github.com/Dadoum/anisette-v3-server
    commit      684895737aaf1a1c4586fcd5b67509ffd500a36c
    date        2026-09-23
    subject     Merge pull request #58 from Taknok/drop-armv7

`anisette/Containerfile` builds that commit and nothing else. It fetches the
commit by its full 40-character SHA and aborts if `git rev-parse HEAD` does not
come back equal to it, so a moved branch or tag cannot substitute other code.
The resulting image carries the revision in
`org.opencontainers.image.revision`, so the running image can be asked what it
was built from:

    podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' \
        localhost/pear-passwords-anisette:684895737aaf1a1c4586fcd5b67509ffd500a36c

Build it with `anisette/build.sh`. `install.sh` does this for you if the image
is missing.

Upstream dependency versions are not resolved at build time from a floating
range. They come from the `dub.selections.json` checked in at that commit,
which pins registry packages to exact versions and pins the four Dadoum git
dependencies to exact commits, including `provision`
(`7717ce1f7b3c9779fe9982005d07b6665071a239`), the library that actually drives
Apple's ADI code.

## Why this is built locally instead of pulled

Until this change the unit pulled `docker.io/dadoum/anisette-v3-server` by
digest `sha256:0391510966a49dfc852a1d6f6d111b2d51ca35d4988b416386b47cdc24263531`.
Pinning that digest guaranteed the same bytes every time, but it did not say
what those bytes were built from, and the image cannot be made to say:

- It has no OCI labels at all. `podman image inspect --format '{{json .Labels}}'`
  returns `null`. There is no `org.opencontainers.image.source` and no
  `.revision`, so nothing in the image refers to a commit.
- Its build history shows the server arriving as a prebuilt
  `COPY /opt/anisette-v3-server` of 5,778,192 bytes. The binary was produced by
  some build that happened outside that image, with no record of which.
- The image was created 2025-04-13T23:17:19Z, about six minutes after upstream
  commit `e0d527b6547297b8e568d93e1bc443dac007bdfc` was pushed. That timing is
  consistent with a CI build of that commit, and it is only a correlation. It
  is not evidence, and this document does not rely on it.

So the digest pin answered "are these the same bytes as last time" and could
not answer "what source produced them". Building here answers the second
question and keeps the first, because the image that runs is the image this
machine produced.

### What that shifts rather than solves

This does not remove trust, it moves it to a set of named parties:

- GitHub, for serving the content of commit `6848957…`. The commit is addressed
  by its SHA, so GitHub cannot serve different content under it, but a
  compromise of the upstream repository before that commit is still inherited.
  The commits around it are not signed in a way this build verifies.
- The Debian archive, for the builder and runtime base images and for the
  packages installed into them. Both base images are pinned by digest
  (`debian:stable-20250520-slim@sha256:bd002736…`,
  `debian:stable-slim@sha256:d405c1e1…`), but `apt-get install` resolves package
  versions at build time and is not pinned.
- The D package registry and the Dadoum dependency repositories, for the
  dependencies named in `dub.selections.json`.
- The machine doing the build.

It also means the build is not bit-reproducible. Two machines building commit
`6848957…` will not get the same image ID, because apt and the package registry
are resolved when the build runs. The revision label is the pin, not the image
ID. That is also why the systemd unit names a local tag that contains the
commit SHA rather than a digest: a digest baked into the repository would be
wrong on every machine but the one that produced it.

The stronger arrangement, if it is ever wanted, is to build once, push to a
registry under this project's own control with a signature and an SBOM, and
have the unit pin that digest. That needs infrastructure this plugin does not
have today.

### Switching an existing install over

The locally built image keeps the upstream user (`Alcoholic`) and the upstream
paths (`/home/Alcoholic/.config/anisette-v3`), so an existing `icp-anisette`
volume is reused rather than replaced, and the machine identity in `adi.pb` is
not re-minted. That matters because re-minting it makes Apple treat the
computer as new and ask for a verification code again.

This was checked rather than assumed. The pulled image
(`sha256:0391510966…`) was started on a fresh volume and allowed to create and
provision a machine. It was then stopped and the locally built image was
started on that same volume. It logged only

    anisette-v3-server v2.2.2
    Listening for requests on http://0.0.0.0:6969/

with no "Machine requires provisioning", and `adi.pb` and `device.json` came
out byte-identical (`sha256:c9ff1fec…` and `sha256:737a2177…` before and
after). It then served anisette headers normally. Both images report the same
server version, `v2.2.2`.

## The Apple libraries, and how they are delivered

The server does not implement Apple's ADI itself. It loads two closed-source
Apple libraries and calls into them:

    libCoreADI.so
    libstoreservicescore.so

**These are not in the image, and this project does not ship them.** They are
downloaded by the server on first start, into `lib/` inside the `icp-anisette`
volume. From `source/app.d` at the pinned commit:

    auto coreADIPath = libraryPath.buildPath("libCoreADI.so");
    auto SSCPath = libraryPath.buildPath("libstoreservicescore.so");

    if (!(file.exists(coreADIPath) && file.exists(SSCPath))) {
        auto http = HTTP();
        log.info("Downloading libraries from Apple servers...");
        auto apkData = get!(HTTP, ubyte)("https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk", http);
        ...
        file.write(coreADIPath, apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libCoreADI.so"]));
        file.write(SSCPath, apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libstoreservicescore.so"]));
    }

In plain terms:

- The source is `https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk`,
  Apple's own CDN, serving the official Android build of Apple Music.
- The transport is HTTPS through libcurl (`std.net.curl`), which verifies the
  certificate chain and hostname by default. `ca-certificates` is installed in
  the runtime image so that verification has roots to work with. Nothing on the
  network can substitute a different APK.
- The APK is read as a ZIP archive and exactly two members are extracted:
  `lib/<arch>/libCoreADI.so` and `lib/<arch>/libstoreservicescore.so`, where
  `<arch>` is `x86_64`, `x86`, `arm64-v8a` or `armeabi-v7a`, chosen at compile
  time from the target architecture. Nothing else from the APK is written
  anywhere.
- The download happens only when both files are absent, so it is a first-start
  event, not traffic on every start.

### What is not checked

- **The APK is not digest-pinned.** The URL is a moving target. Whatever Apple
  serves at the moment of first start is what gets loaded.
- **No signature is verified.** The APK's own Android signature is not checked,
  and neither library is checked against any expected hash before it is loaded
  and executed in-process.
- **There is no fallback or allowlist.** If Apple ships a different build, the
  new libraries are used silently.

So the guarantee is: these libraries came from Apple, over a connection that
was verified to be Apple, out of the shipping Apple Music APK. The guarantee is
not: these are a specific reviewed set of bytes.

### The bytes currently being served

`anisette/apple-libs.sha256` records what that URL yielded on 2026-10-07:

    applemusic.apk                         142139820 bytes
      Last-Modified: Tue, 15 Apr 2025 18:26:03 GMT
      sha256 9aab4e3bfd44b509dd657b030d46df536c5592512c256fc59012cce47a2e9c9c

    lib/x86_64/libCoreADI.so                 1596128 bytes
      sha256 ece4ffa6bbe4239e8f0d4714da57e62ce5e3c581d19553a83d78ac897783b905
    lib/x86_64/libstoreservicescore.so       2391768 bytes
      sha256 d8be230df34c0044758d43e33a8dabd3236b9a4258c4d48cb366911224d52f68

The `Last-Modified` date says Apple has not replaced that APK in about eighteen
months, which is why recording the digests is worth anything: the expected
value is stable enough that a change means something.

These are observations, not a pin. The server does not consult them. They make
a change **detectable**, after the fact, by running:

    anisette/verify-apple-libs.sh

A `CHANGED` result is not by itself a compromise; the ordinary cause is a new
Apple Music release. It does mean the code being loaded is not the code these
digests describe, and that should be looked at rather than assumed.

## Summary of what is and is not authenticated

| Link | Status |
| --- | --- |
| Server source revision | Pinned to a full commit SHA and enforced at build time |
| Server binary | Built here from that source, labelled with the revision |
| D dependencies | Pinned to exact versions and commits by `dub.selections.json` |
| Base images | Pinned by digest |
| Debian packages inside them | Not pinned, resolved at build time |
| Build reproducibility | Not bit-reproducible; the revision label is the pin |
| Upstream repository history | Trusted, not independently verified; commits not signature-checked |
| Upstream license | None declared upstream, so the image label is `NOASSERTION` |
| Apple library origin | Apple's CDN over verified TLS, from the official Apple Music APK |
| Apple library bytes | Not pinned and not signature-checked; recorded so changes are detectable |
