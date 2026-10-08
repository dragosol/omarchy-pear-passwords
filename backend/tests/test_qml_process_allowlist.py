"""The window starts only the processes on its fixed list, with fixed argument shapes.

Every child of the window inherits its effective group pear-client, so a child can reach the
daemon. The list (spec section 4.5) is: hyprctl for the window rules, focusing the window and
opening a link through Hyprland; pear-exec clip and migrate; the touchpad watcher; and
`systemctl show` for diagnosing a service that will not start. Nothing else, no shell, and no
toolkit helper that would launch a browser as our child.
"""

import os
import re
import unittest

import qmlscan
from icp.daemon import paths

ALLOWED = {
    '[root.pearExec, "clip"]',
    '[root.pearExec, "migrate"]',
    '["/usr/bin/hyprctl", "eval", root.windowRulesLua]',
    '["/usr/bin/hyprctl", "dispatch", root.focusLua]',
    '["/usr/bin/hyprctl", "dispatch", opener.lua]',
    '["/usr/bin/python3", "-I", root.touchWatchPath]',
    '["/usr/bin/systemctl", "show", "-p", "LoadState,ActiveState,Result,ExecMainStatus", '
    '"pear-passwordsd.service"]',
}

SHELL_QML = os.path.join(qmlscan.APP, "shell.qml")


def property_value(code: str, name: str) -> str:
    m = re.search(r"readonly property string " + name + r":\s*(\"(?:[^\"\\]|\\.)*\")", code)
    assert m, name
    return eval(m.group(1))     # a plain JSON-style string literal from our own file


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.files = {p: qmlscan.strip_comments(qmlscan.read(p)) for p in qmlscan.app_files()}

    def test_every_command_is_on_the_list(self):
        found = []
        for path, code in self.files.items():
            for m in re.finditer(r"\bcommand\s*:\s*(\[[^\n]*\])", code):
                found.append(re.sub(r"\s+", " ", m.group(1)).strip())
        self.assertTrue(found)
        for cmd in found:
            self.assertIn(cmd, ALLOWED)

    def test_every_process_has_a_literal_command(self):
        # Independent of the matcher above: count Process elements and command bindings.
        procs = cmds = 0
        for code in self.files.values():
            scan = qmlscan.blank_strings(code)
            procs += len(re.findall(r"(?<![\w.])Process\s*\{", scan))
            cmds += len(re.findall(r"^\s*command\s*:", scan, re.M))
        self.assertEqual(procs, cmds)
        self.assertEqual(procs, len(ALLOWED))

    def test_no_other_way_to_start_a_process(self):
        for path, code in self.files.items():
            scan = qmlscan.blank_strings(code)
            for bad in (r"\bexecDetached\b", r"\bstartDetached\b", r"\bopenUrlExternally\b",
                        r"\.exec\s*\(", r"\bcommand\s*=", r"\bProcessContext\b"):
                self.assertIsNone(re.search(bad, scan), f"{path}: {bad}")
            for word in ('"sh"', '"bash"', '"-c"', '"/bin/sh"', '"xdg-open"'):
                self.assertNotIn(word, code, f"{path}: {word}")

    def test_fixed_paths(self):
        code = self.files[SHELL_QML]
        self.assertEqual(property_value(code, "pearExec"), paths.PEAR_EXEC)
        self.assertEqual(property_value(code, "socketPath"), paths.SOCKET_PATH)
        self.assertTrue(os.path.exists(os.path.join(qmlscan.APP, "touch_watch.py")))
        rules = re.search(r"readonly property string windowRulesLua:(.*?)\n\s*readonly", code,
                          re.S).group(1)
        self.assertIn("no_screen_share = true", rules)
        self.assertIn(f"^{paths.WINDOW_TITLE}$", rules)
        self.assertIn(f'title: "{paths.WINDOW_TITLE}"', code)
        self.assertEqual(property_value(code, "focusLua"),
                         f'hl.dsp.focus({{ window = "title:^{paths.WINDOW_TITLE}$" }})')

    def test_links_go_through_the_url_pattern(self):
        code = self.files[SHELL_QML]
        assigns = re.findall(r"opener\.lua\s*=\s*([^\n;]*)", code)
        self.assertEqual(assigns, ['"hl.dsp.exec_cmd(\\"xdg-open https://" + url + "\\")"'])
        body = re.search(r"function openDomain\(d\) \{(.*?)\n    \}", code, re.S).group(1)
        self.assertLess(body.index("root.urlPattern.test(url)"), body.index("opener.lua ="))
        pattern = re.search(r"readonly property var urlPattern: /(.*)/\n", code).group(1)
        rx = re.compile(pattern)
        for ok in ("github.com", "login.example.co.uk", "example.com:8443/login",
                   "example.com/a/b-c_d.e~f", "xn--bcher-kva.example"):
            self.assertTrue(rx.match(ok), ok)
        for bad in ('evil.com")', 'a.com";os.execute("x', "a.com;rm -rf", "$(id).com",
                    "a.com`id`", "localhost", "a b.com", "a.com\\", "a.com'", "-a.com",
                    "a.com/<script>", "a.com/$x", "a.com\nb", ""):
            self.assertIsNone(rx.match(bad), bad)


class AppFileTests(unittest.TestCase):
    def test_desktop_entry_runs_pear_exec(self):
        with open(os.path.join(qmlscan.APP, f"{paths.APP_ID}.desktop")) as f:
            lines = f.read().splitlines()
        self.assertIn(f"Exec={paths.PEAR_EXEC} ui", lines)
        self.assertEqual([l for l in lines if l.startswith("Exec=")], [f"Exec={paths.PEAR_EXEC} ui"])

    def test_launcher_script_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(qmlscan.APP, "launch.sh")))

    def test_fonts_conf_is_system_only(self):
        with open(os.path.join(qmlscan.APP, "fonts.conf")) as f:
            raw = f.read()
        conf = re.sub(r"<!--.*?-->", "", raw, flags=re.S)
        self.assertIn("<cachedir>/var/cache/fontconfig</cachedir>", conf)
        for bad in ("50-user", "51-local", "~", 'prefix="xdg"', "prefix='xdg'", "/home",
                    "conf.d", "<include>", "/etc/fonts"):
            self.assertNotIn(bad, conf)
        for path in re.findall(r">(/[^<]+)<", conf):
            self.assertTrue(path.startswith(("/usr/share/", "/usr/local/share/", "/var/cache/")),
                            path)


if __name__ == "__main__":
    unittest.main()
