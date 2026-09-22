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
// `omarchy plugin add` only clones files; it never runs an installer. So this service does
// one thing: if the backend has not been installed yet, it says so once, with where to go.
QtObject {
  id: root

  readonly property string home: Quickshell.env("HOME")
  readonly property string backend: home + "/.local/share/pear-passwords/venv/bin/icp"
  readonly property string checkout: decodeURIComponent(
      Qt.resolvedUrl("..").toString().replace(/^file:\/\//, "").replace(/\/$/, ""))

  property Process check: Process {
    command: ["test", "-x", root.backend]
    running: false
    onExited: function (code) {
      if (code !== 0)
        Quickshell.execDetached(["notify-send", "-a", "Pear Passwords",
          "Pear Passwords needs one more step",
          "Run ./install.sh in " + root.checkout + " to set up the app and its launcher."])
    }
  }

  Component.onCompleted: check.running = true
}
