# native/

`pear-exec.c` (WP4) will live here: the set-gid shim that is the only way to get effective gid
`pear-client` and so the only way to reach the daemon socket. It is about 200 lines of C,
compiled from source by the root install step and never shipped as a binary:

```sh
cc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now \
   -o pear-exec native/pear-exec.c
install -m2755 -o root -g pear-client pear-exec /usr/local/lib/pear-passwords/libexec/pear-exec
```

What it must do is in the spec, section 4.4, extended for the fourth role:

- exactly one argument, one of `ui`, `clip`, `migrate`, `autofill`; anything else exits 64;
- refuse ruid 0 and refuse if `pear-client` is already a supplementary group;
- build the environment from scratch (the compositor checks apply to every role), close fds
  above 2, keep stdin and stdout for every role;
- exec the fixed argv of the role, after checking that every target path and every parent
  directory is root-owned and not group- or other-writable.

Every path and name it hard-codes must equal `system/paths.env` (`PREFIX`, `VENV_PYTHON`,
`APP_DIR`, `FONTS_CONF`, `EMPTY_DIR`, `CLIENT_GROUP`, the `TARGET_*` values). WP4's
`test_pear_exec_env.py` builds it in a scratch directory and checks both the environment it
builds (non-set-gid test mode under `PEAR_EXEC_TEST_ROOT`) and those constants.
