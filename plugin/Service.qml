pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io

// Shell-side half of Pear Passwords.
//
// The app itself is NOT loaded into omarchy-shell. It runs as its own Quickshell process
// (app/shell.qml), launched from its desktop entry, because plugins inside the shell share
// one QML scene and can reach each other's objects - no place for decrypted passwords.
//
// What this does is make `omarchy plugin add` produce something you can actually open. It
// lays down the window and its launcher by running the repository's own installer in its
// --app-only mode, which installs no virtualenv, no services and needs no privileges. The
// backend is deliberately NOT installed here: the window asks before doing that, because
// building it downloads pinned wheels and that should be a decision, not a side effect of
// enabling a plugin.
QtObject {
  id: root

  readonly property string home: Quickshell.env("HOME")
  readonly property string data: home + "/.local/share/pear-passwords"
  readonly property string checkout: decodeURIComponent(
      Qt.resolvedUrl("..").toString().replace(/^file:\/\//, "").replace(/\/$/, ""))

  // The version this checkout is, so an update re-lays the window instead of leaving the old
  // one in place. Written beside the installed copy by the provisioning run below.
  readonly property string stamp: data + "/app/.plugin-version"

  property bool provisioning: false

  // Is the installed window missing, or older than this checkout?
  property Process check: Process {
    command: ["sh", "-c",
      "test -x " + root.data + "/app/launch.sh && " +
      "test -f " + root.stamp + " && " +
      "cmp -s " + root.stamp + " " + root.checkout + "/manifest.json"]
    running: true
    onExited: function (code) {
      if (code !== 0)
        root.provision.running = true
    }
  }

  // install.sh --app-only: copies app/, links Omarchy's Ui and Commons beside it so the
  // window follows the theme, and writes the desktop entry. User-level, no sudo, no services.
  property Process provision: Process {
    running: false
    command: [root.checkout + "/install.sh", "--app-only"]
    onRunningChanged: root.provisioning = running
    onExited: function (code) {
      if (code === 0) {
        root.stampIt.running = true
        return
      }
      Quickshell.execDetached(["notify-send", "-a", "Pear Passwords",
        "Pear Passwords could not finish setting up",
        "Run ./install.sh in " + root.checkout + " to see what went wrong."])
    }
  }

  property Process stampIt: Process {
    running: false
    command: ["cp", root.checkout + "/manifest.json", root.stamp]
  }
}
