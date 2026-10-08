"""Every security claim in the README and docs/security.md names the tests that prove it.

README "Security" bullets carry `<!-- tests: ... -->`; docs/security.md bullets and
paragraphs carry `Tests: ...`. Each id is `test_file.py`, `test_file.py::Class` or
`test_file.py::Class::method`, and must exist (the class and method are found with the AST).
A file another work package adds in 2.0 and that is not on this branch yet is reported, not
failed, but only if the spec assigns it (PLANNED); once the file exists, every id in it is
checked.

It also holds the README to the owner's decisions: 120 s per account, 30 s on the clipboard,
idle lock off, no sync lease, autofill opt-in with no bundled extension, and none of 1.x's
claims that are no longer true.
"""

import ast
import os
import re
import unittest

from icp.daemon import protocol

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS = os.path.join(ROOT, "backend", "tests")

# Test files the 2.0 spec assigns to the other work packages.
PLANNED = {
    # WP1
    "test_daemon_peer.py", "test_daemon_polkit.py", "test_grants.py", "test_tickets.py",
    "test_logind_lock.py", "test_scheduler_no_prompt.py", "test_protocol_limits.py",
    "test_policy_file.py", "test_unit_hardening.py",
    # WP2
    "test_store_v2.py", "test_seal_reseal.py", "test_pwmac_sync_diff.py", "test_migration_v1.py",
    # WP3
    "test_apple_ctx.py",
    # WP4
    "test_pear_exec_env.py", "test_clip_policy.py", "test_qml_text_plain.py", "test_qml_no_ipc.py",
    "test_qml_process_allowlist.py", "test_qml_no_console_log.py",
    # WP6
    "test_autofill_origin.py", "test_autofill_handlers.py", "test_autofill_host_framing.py",
    "test_autofill_register.py",
}
ID = re.compile(r"test_[a-z0-9_]+\.py(?:::[A-Za-z_][A-Za-z0-9_]*){0,2}")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _section(text, heading):
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"no section {heading!r}")
    return m.group(1)


def _bullets(section):
    """Top-level bullets, each with its continuation lines."""
    out, cur = [], None
    for line in section.splitlines():
        if line.startswith("- "):
            if cur is not None:
                out.append(cur)
            cur = line
        elif cur is not None and (line.startswith("  ") or not line.strip()) and line.strip():
            cur += "\n" + line
        elif cur is not None and not line.strip():
            out.append(cur)
            cur = None
    if cur is not None:
        out.append(cur)
    return out


def resolve(test_id):
    """None if the id exists, 'planned' if its file is a planned one not here yet, else why."""
    parts = test_id.split("::")
    path = os.path.join(TESTS, parts[0])
    if not os.path.exists(path):
        return "planned" if parts[0] in PLANNED else f"{parts[0]} does not exist"
    if len(parts) == 1:
        return None
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == parts[1]), None)
    if cls is None:
        return f"{parts[0]} has no class {parts[1]}"
    if len(parts) == 3 and not any(isinstance(n, ast.FunctionDef) and n.name == parts[2]
                                   for n in cls.body):
        return f"{parts[0]}::{parts[1]} has no {parts[2]}"
    return None


class ResolverTests(unittest.TestCase):
    def test_resolver(self):
        self.assertIsNone(resolve("test_docs_claims.py"))
        self.assertIsNone(resolve("test_docs_claims.py::ResolverTests::test_resolver"))
        self.assertIn("no class", resolve("test_docs_claims.py::Nope"))
        self.assertIn("has no", resolve("test_docs_claims.py::ResolverTests::nope"))
        self.assertIn("does not exist", resolve("test_nothing_like_this.py"))


class ClaimsHaveTestsTests(unittest.TestCase):
    def _check(self, claims, where):
        problems, planned = [], set()
        for claim in claims:
            ids = ID.findall(claim)
            head = claim.strip().splitlines()[0][:70]
            if not ids:
                problems.append(f"{where}: no test named for: {head}")
            for i in ids:
                r = resolve(i)
                if r == "planned":
                    planned.add(i.split("::")[0])
                elif r:
                    problems.append(f"{where}: {r} ({head})")
        self.assertEqual(problems, [], "\n".join(problems))
        return planned

    def test_readme_security_bullets(self):
        bullets = _bullets(_section(_read("README.md"), "Security"))
        self.assertGreaterEqual(len(bullets), 12)
        claims = []
        for b in bullets:
            m = re.search(r"<!-- tests: (.*?) -->", b, re.S)
            claims.append(m.group(1) if m else "")
        planned = self._check([c or b for c, b in zip(claims, bullets)], "README")
        for c, b in zip(claims, bullets):
            self.assertTrue(c, f"README bullet has no <!-- tests: --> marker: {b[:60]}")
        self.assertEqual(sorted(planned), [], "README names tests that do not exist")

    def test_security_md_claims(self):
        doc = _read("docs", "security.md")
        claims = []
        for heading in ("1. Components", "2. Key hierarchy", "3. Peer verification",
                        "4. Prompts", "5. Autofill", "6. Installer"):
            section = _section(doc, heading)
            bullets = _bullets(section)
            if bullets:
                claims.extend(bullets)
            # Paragraphs that are not bullets, tables or code make claims too, unless they only
            # introduce what follows (they end with a colon).
            for para in re.split(r"\n\s*\n", section):
                p = para.strip()
                if p and not p.startswith(("-", "|", "```")) and not p.endswith(":"):
                    claims.append(p)
        for c in claims:
            self.assertIn("Tests:", c, f"security.md claim without Tests: {c[:70]}")
        planned = self._check(claims, "security.md")
        self.assertEqual(sorted(planned), [], "security.md names tests that do not exist")


class OwnerDecisionsInDocsTests(unittest.TestCase):
    def setUp(self):
        self.readme = _read("README.md")

    def test_timings(self):
        self.assertEqual(protocol.GRANT_S_DEFAULT, 120)
        self.assertEqual(protocol.CLIP_TIMEOUT_S_DEFAULT, 30)
        self.assertIn("**2 minutes**", self.readme)
        self.assertIn("2:00", self.readme)
        self.assertIn("**30 seconds**", self.readme)
        self.assertIn("after one paste, or after 30 seconds", self.readme)
        for stale in ("15 s", "15 seconds", "60 s ", "two clocks", "5 minutes** after"):
            self.assertNotIn(stale, self.readme)

    def test_idle_lock_off_and_no_lease(self):
        self.assertIn("is off by default", self.readme)
        self.assertNotRegex(self.readme, r"(?i)\blease|sync_lease")
        self.assertIn("A locked computer does not\nsync", self.readme)

    def test_autofill_is_bring_your_own(self):
        section = _section(self.readme, "Autofill (bring your own extension)")
        self.assertIn("**off by default**", section)
        self.assertIn("No installer writes a browser manifest", section)
        self.assertIn("pear-passwords-autofill register --browser", section)
        self.assertIn("unregister --all", section)
        self.assertIn("docs/autofill-protocol.md", section)
        self.assertIn("**Every fill shows its own dialog**", section)
        self.assertIn("**The browser then holds that password**", section)
        self.assertNotRegex(self.readme, r"(?i)autofill (is )?removed")

    def test_required_sections(self):
        for heading in ("How unlocking works", "Install", "Migrating from 1.x",
                        "Autofill (bring your own extension)", "Clipboard", "Sync",
                        "TPM (the security chip)", "Backups", "What Pear protects against",
                        "Security", "Uninstall"):
            _section(self.readme, heading)
        self.assertIn("**Root and admin polkit rules are trusted.**", self.readme)
        self.assertIn("within 15 minutes before this\n> step", self.readme)
        self.assertIn("/var/lib/systemd/credential.secret", _section(self.readme, "Backups"))

    def test_retired_claims_are_gone(self):
        # The migration section may name 1.x's own keyring mode and its `icp passphrase`
        # command: that is what moving a keyring-keyed 1.x vault needs (2.0 uses neither).
        migration = _section(self.readme, "Migrating from 1.x")
        rest = self.readme.replace(migration, "")
        for stale in ("never uses sudo", "all under your home", "sudo tee", "One scan",
                      "ICP_KEY_GATE", "ICP_LOCK_TIMEOUT", "icp passphrase", "login keyring",
                      "ALWAYS_CHECK", "polkit-1 includes system-auth"):
            self.assertNotIn(stale, rest, stale)


class ReviewedResidualsInDocsTests(unittest.TestCase):
    """The review's honest-docs findings: what a reviewer reads must match what the code does."""

    @classmethod
    def setUpClass(cls):
        cls.readme = _read("README.md")
        cls.security = _read("docs", "security.md")
        cls.residuals = _section(cls.readme, "What Pear protects against")

    def test_autofill_is_not_called_unreachable(self):
        # escape-autofill-role-ungated
        unlocking = _section(self.readme, "How unlocking works")
        self.assertIn("autofill hosts once you turn autofill on", unlocking)
        self.assertNotIn("Off until the user runs `pear-passwords-autofill register`",
                         self.security)
        self.assertIn("autofill_enabled", _read("docs", "protocol.md") + _read(
            "backend", "icp", "vstore", "session_store.py"))

    def test_compositor_control_is_disclosed_with_its_mitigation(self):
        # escape-compositor-control-undisclosed
        self.assertIn("if it controls your compositor", self.residuals)
        self.assertIn("enforce_permissions = true", self.residuals)
        self.assertIn("A program controlling the compositor", self.security)

    def test_omarchy_components_reads_and_children_are_listed(self):
        # escape-omarchy-commons-home-reads-and-children, clipboard_ui-7
        for doc in (_section(self.readme, "Security"), self.security):
            for what in ("fc-match", "hyprctl -j getoption", "colors,shell}.toml",
                         ".config/omarchy/shell.toml", "fonts.conf", "gaps"):
                self.assertIn(what, doc, what)
        self.assertIn("window-no-gaps.lua", self.security)
        self.assertNotIn("no settings,\n  fonts or plugins from your home", self.readme)

    def test_omarchy_screen_lock_is_not_claimed_to_lock_pear(self):
        # installer-screen-lock-claim-false-on-omarchy
        self.assertNotIn("press **Lock**, lock the screen, suspend", self.readme)
        self.assertIn("Omarchy's lock does not lock Pear yet", self.readme)
        self.assertIn("awake behind Omarchy's screen lock", self.residuals)
        self.assertRegex(self.security, r"awake behind Omarchy's screen lock.*\| Does not hold")

    def test_install_inventory_is_complete_and_the_size_is_true(self):
        # installer-readme-inventory-inaccurate
        install = _section(self.readme, "Install")
        for path in ("pear-passwords-seal.socket", "pear-passwords-seal@.service",
                     "/etc/tmpfiles.d/pear-passwords.conf", "/usr/local/lib/pear-passwords/VERSION",
                     "uninstall-root", "etc/fonts.conf"):
            self.assertIn(path, install, path)
        claimed = int(re.search(r"set-gid program of about (\d+) lines", self.readme).group(1))
        actual = len(_read("native", "pear-exec.c").splitlines())
        self.assertLess(abs(claimed - actual) / actual, 0.1, (claimed, actual))

    def test_ptt_is_not_claimed_to_protect_old_backups(self):
        # crypto-ptt-reseal-does-not-rotate-keys
        self.assertNotIn("With PTT on they are useless without this computer's TPM", self.readme)
        self.assertIn("A backup taken **before** the switch", self.readme)


if __name__ == "__main__":
    unittest.main()
