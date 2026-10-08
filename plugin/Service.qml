pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io

// Shell-side half of Pear Passwords.
//
// The app itself is NOT loaded into omarchy-shell. It runs as its own Quickshell process,
// started by pear-exec from the root-owned copy in /usr/local/lib/pear-passwords/app, because
// plugins inside the shell share one QML scene and can reach each other's objects - no place
// for decrypted passwords. Nothing here copies QML anywhere or installs anything: since 2.0 the
// window is installed by the system step, which needs sudo and so is never run from here.
//
// What this does is tell you when that step is missing or out of date. pear-exec must exist,
// be owned by root, belong to group pear-client and carry the set-gid bit (2755); without that
// the window cannot reach its service. If the installed snapshot ($P/VERSION) is not this
// checkout's, an update is waiting for the same step.
QtObject {
  id: root

  readonly property string prefix: "/usr/local/lib/pear-passwords"
  readonly property string pearExec: prefix + "/libexec/pear-exec"
  readonly property string checkout: decodeURIComponent(
      Qt.resolvedUrl("..").toString().replace(/^file:\/\//, "").replace(/\/$/, ""))

  // "missing", "broken" (exists but not root:pear-client 2755), "outdated" or "ok";
  // "" until the checks have run.
  property string systemState: ""
  readonly property string hint: systemState === "missing"
      ? "Pear Passwords needs its one-time system step. Run ./install.sh in " + checkout
        + ", then paste the command it prints."
      : systemState === "broken"
      ? "Pear Passwords' system step looks damaged (pear-exec is not root-owned and set-gid). "
        + "Run ./install.sh in " + checkout + " and the command it prints again."
      : systemState === "outdated"
      ? "A Pear Passwords update is ready. Run ./install.sh in " + checkout
        + ", then paste the command it prints."
      : ""

  property Process ownership: Process {
    command: ["stat", "-c", "%u %G %a", root.pearExec]
    running: true
    stdout: StdioCollector {
      onStreamFinished: {
        const t = this.text.trim();
        if (t === "") { root.systemState = "missing"; root.tell(); return; }
        if (t !== "0 pear-client 2755") { root.systemState = "broken"; root.tell(); return; }
        root.compare.running = true;
      }
    }
  }

  // The installed snapshot against this checkout's, exactly as install.sh compares
  // them: $P/VERSION (written by the root step) must name this checkout's version and the
  // sha256 of its SHA256SUMS. Any change anywhere (daemon, pear-exec, policy, units, window)
  // changes SHA256SUMS, so a backend-only update is announced too. Read-only.
  property Process compare: Process {
    command: ["sh", "-c",
      'v=$(sed -n \'s/^ *"version": *"\\([0-9][0-9.]*\\)".*/\\1/p\' "$1/manifest.json" | head -n 1); '
      + 's=$(sha256sum < "$1/SHA256SUMS" | cut -c1-64); '
      + '[ -n "$v" ] && [ "$(cat "$2/VERSION" 2>/dev/null)" = "$(printf \'version=%s\\nsums=%s\' "$v" "$s")" ]',
      "pear-version-check", root.checkout, root.prefix]
    running: false
    onExited: function (code) {
      root.systemState = code === 0 ? "ok" : "outdated";
      root.tell();
    }
  }

  function tell() {
    if (hint === "") return;
    Quickshell.execDetached(["notify-send", "-a", "Pear Passwords",
      systemState === "outdated" ? "Pear Passwords update ready" : "Pear Passwords isn't set up yet",
      hint]);
  }
}
