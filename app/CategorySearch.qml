import QtQuick
import QtQuick.Controls
import "categories.js" as Cat

// The list's search box, with the category drop-down and its one tag chip (features spec 3).
//
// Hover the field for 200 ms (or press Alt+Down, or type '#' into an empty query) and a list
// of All, the synced categories and your tags drops down; clicking one puts it in the field as
// a chip before the query, and the list shows only that. Leaving the field and the list for
// 300 ms closes it. Everything here works on the list the daemon sent after the first dialog:
// no grant, no reveal, no dialog. Tag names come from note text another device wrote, so they
// are shown as plain text only.
//
// The window owns the chosen tag (root.catTag) and passes it in as `tag`; this item says when
// it should change (tagPicked) and what the keys it does not handle mean (moveRequested,
// tabbed, submitted).
TextField {
    id: catSearch

    property var entries: []
    property var features: ({})
    property var tag: null

    signal tagPicked(var tag)
    signal moveRequested(int delta)
    signal tabbed()
    signal copyRequested()

    property bool catOpen: false
    property int catCursor: -1
    // Opened by a leading '#': letters typed next go to catFilter, not to the query.
    property bool catTyping: false
    property string catFilter: ""
    // The cursor row was put there by the keyboard: only then do Enter and Space choose it.
    // A row under a resting pointer is tinted but never taken by a key typed into the query.
    property bool catKeyed: false
    readonly property var catRows: Cat.rows(catSearch.entries, catSearch.features, catSearch.catFilter)
    readonly property bool canOpen: catSearch.enabled && catSearch.entries.length > 0
    readonly property alias panel: catPanel
    readonly property alias chipItem: chip
    readonly property alias chipClearItem: chipClear

    leftPadding: chip.visible ? catSearch.padding + chip.width + 8 : catSearch.padding

    function activeRow() {
        for (let i = 0; i < catSearch.catRows.length; i++) {
            const r = catSearch.catRows[i];
            if (r.kind !== "divider" && Cat.sameTag(Cat.tagOf(r), catSearch.tag)) return i;
        }
        return catSearch.firstRow();
    }
    function firstRow() {
        for (let i = 0; i < catSearch.catRows.length; i++)
            if (catSearch.catRows[i].kind !== "divider") return i;
        return -1;
    }
    function openCats(keyboard, typing) {
        if (!catSearch.canOpen) return;
        closeTimer.stop();
        catSearch.catTyping = !!typing;
        catSearch.catFilter = "";
        catSearch.catOpen = true;
        catSearch.catKeyed = !!keyboard;
        catSearch.catCursor = keyboard ? catSearch.activeRow() : -1;
    }
    function closeCats() {
        openTimer.stop();
        closeTimer.stop();
        catSearch.catOpen = false;
        catSearch.catTyping = false;
        catSearch.catFilter = "";
        catSearch.catCursor = -1;
        catSearch.catKeyed = false;
    }
    // Up/Down over the rows: the divider is skipped, the ends hold (no wrap).
    function moveCat(delta) {
        const rows = catSearch.catRows;
        catSearch.catKeyed = true;
        let i = catSearch.catCursor < 0 ? catSearch.activeRow() - delta : catSearch.catCursor;
        for (let j = i + delta; j >= 0 && j < rows.length; j += delta)
            if (rows[j].kind !== "divider") { catSearch.catCursor = j; return; }
        if (catSearch.catCursor < 0) catSearch.catCursor = catSearch.activeRow();
    }
    // All clears the tag, any other row replaces it, and the row already set changes nothing.
    function choose(i) {
        const row = catSearch.catRows[i];
        if (!row || row.kind === "divider") return;
        const t = Cat.tagOf(row);
        catSearch.closeCats();
        catSearch.forceActiveFocus();
        if (!Cat.sameTag(t, catSearch.tag)) catSearch.tagPicked(t);
    }
    function setFilter(text) {
        catSearch.catFilter = text;
        catSearch.catCursor = catSearch.firstRow();
        catSearch.catKeyed = true;
    }
    function hoverChanged() {
        if (hField.hovered || hPopup.hovered) closeTimer.stop();
        else if (catSearch.catOpen && !catSearch.catTyping) closeTimer.restart();
    }

    onActiveFocusChanged: if (!activeFocus) catSearch.closeCats()
    onEnabledChanged: if (!enabled) catSearch.closeCats()
    onCanOpenChanged: if (!canOpen) catSearch.closeCats()

    Timer { id: openTimer; interval: 200; onTriggered: catSearch.openCats(false, false) }
    Timer { id: closeTimer; interval: 300; onTriggered: catSearch.closeCats() }

    HoverHandler {
        id: hField
        onHoveredChanged: {
            if (hovered && !catSearch.catOpen && catSearch.canOpen) openTimer.restart();
            else if (!hovered) openTimer.stop();
            catSearch.hoverChanged();
        }
    }

    Keys.onPressed: function (ev) {
        const k = ev.key;
        if (catSearch.catOpen) {
            if (k === Qt.Key_Escape) { catSearch.closeCats(); ev.accepted = true; return; }
            if (k === Qt.Key_Tab) { catSearch.closeCats(); catSearch.tabbed(); ev.accepted = true; return; }
            if (k === Qt.Key_Down || k === Qt.Key_Up) {
                catSearch.moveCat(k === Qt.Key_Down ? 1 : -1);
                ev.accepted = true;
                return;
            }
            if ((k === Qt.Key_Return || k === Qt.Key_Enter || k === Qt.Key_Space)
                && catSearch.catKeyed && catSearch.catCursor >= 0) {
                catSearch.choose(catSearch.catCursor);
                ev.accepted = true;
                return;
            }
            if (catSearch.catTyping) {
                if (k === Qt.Key_Backspace) {
                    if (catSearch.catFilter === "") catSearch.closeCats();
                    else catSearch.setFilter(catSearch.catFilter.slice(0, -1));
                    ev.accepted = true;
                    return;
                }
                if (ev.text.length === 1 && ev.text.trim().length === 1
                    && !(ev.modifiers & (Qt.ControlModifier | Qt.AltModifier))) {
                    catSearch.setFilter(catSearch.catFilter + ev.text);
                    ev.accepted = true;
                    return;
                }
            }
        } else if (k === Qt.Key_Down && (ev.modifiers & Qt.AltModifier)) {
            catSearch.openCats(true, false);
            ev.accepted = true;
            return;
        } else if (ev.text === "#" && catSearch.text === "" && catSearch.tag === null) {
            catSearch.openCats(true, true);
            ev.accepted = true;
            return;
        }
        // The chip goes with Backspace only when there is nothing of the query to delete
        // before the caret; the query itself is kept.
        if (k === Qt.Key_Backspace && catSearch.tag !== null && catSearch.selectedText === ""
            && (catSearch.text === "" || catSearch.cursorPosition === 0)) {
            catSearch.tagPicked(null);
            ev.accepted = true;
            return;
        }
        if (k === Qt.Key_Down) { catSearch.moveRequested(1); ev.accepted = true; }
        else if (k === Qt.Key_Up) { catSearch.moveRequested(-1); ev.accepted = true; }
        else if (k === Qt.Key_Tab) { catSearch.tabbed(); ev.accepted = true; }
        else if (k === Qt.Key_Return || k === Qt.Key_Enter) { catSearch.copyRequested(); ev.accepted = true; }
        // Esc with the list closed is the window's (clear the query, then the tag, then quit).
    }

    // ---- the chip: before the query, never part of the text
    Rectangle {
        id: chip
        visible: catSearch.tag !== null
        x: catSearch.padding
        anchors.verticalCenter: parent.verticalCenter
        width: chipRow.width + 16
        height: chipLabel.implicitHeight + 6
        radius: 9
        color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
        Row {
            id: chipRow
            x: 8
            anchors.verticalCenter: parent.verticalCenter
            spacing: 5
            Text {
                id: chipLabel
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(implicitWidth, 140)
                text: Cat.chipText(catSearch.tag)
                color: Theme.fg
                font.family: Theme.uiFont
                font.pixelSize: Theme.fBody - 1
                elide: Text.ElideRight
            }
            Item {
                id: chipClear
                anchors.verticalCenter: parent.verticalCenter
                width: 14; height: 14
                Text {
                    textFormat: Text.PlainText
                    anchors.centerIn: parent
                    text: "×"
                    color: hClear.hovered ? Theme.fg : Theme.dim
                    font.family: Theme.uiFont
                    font.pixelSize: Theme.fBody
                }
                HoverHandler { id: hClear; cursorShape: Qt.PointingHandCursor }
                TapHandler { onTapped: { catSearch.closeCats(); catSearch.tagPicked(null); catSearch.forceActiveFocus(); } }
            }
        }
    }

    // ---- the drop-down
    // Drawn in the scene, not as a Popup: a Popup lives in the window's overlay, which the
    // development snapshot cannot grab. It closes as that Popup would (CloseOnEscape |
    // CloseOnPressOutside), and also on Tab, focus leaving the field, the window going
    // inactive and a row being chosen. The window raises the search row (z) so this draws
    // over the list below it.
    MouseArea {
        id: pressCatcher
        parent: catSearch.Window.contentItem
        anchors.fill: parent
        z: 1000000
        enabled: catSearch.catOpen
        visible: catSearch.catOpen
        acceptedButtons: Qt.AllButtons
        // Never takes the press: it closes the list and lets the press through to whatever
        // is under it (a row of the list itself included).
        onPressed: function (m) {
            const p = pressCatcher.mapToItem(catPanel, m.x, m.y);
            if (!catPanel.contains(p)) catSearch.closeCats();
            m.accepted = false;
        }
    }

    Rectangle {
        id: catPanel
        objectName: "catPanel"
        visible: catSearch.catOpen
        x: 0
        y: catSearch.height
        width: Math.max(catSearch.width, 260)
        height: popupCol.implicitHeight + 12
        color: Theme.bg
        border.width: 1
        border.color: Theme.line
        radius: Theme.radius
        // Tag names are someone's note text: no menu of Qt's own on them either.
        ContextMenu.menu: null
        HoverHandler { id: hPopup; onHoveredChanged: catSearch.hoverChanged() }
        Column {
            id: popupCol
            x: 6; y: 6
            width: parent.width - 12
            spacing: 0

            // The filter typed after '#'.
            Text {
                textFormat: Text.PlainText
                visible: catSearch.catTyping
                width: parent.width
                leftPadding: 10
                topPadding: 4
                bottomPadding: 6
                text: "#" + (catSearch.catFilter || "")
                      + (catSearch.catFilter ? "" : "  type to filter, ⏎ to choose")
                color: catSearch.catFilter ? Theme.fg : Theme.dim
                font.family: Theme.uiFont
                font.pixelSize: Theme.fSmall
                elide: Text.ElideRight
            }
            Text {
                textFormat: Text.PlainText
                visible: catSearch.catRows.length === 0
                width: parent.width
                leftPadding: 10
                topPadding: 6
                bottomPadding: 6
                text: "Nothing matches"
                color: Theme.dim
                font.family: Theme.uiFont
                font.pixelSize: Theme.fSmall
            }

            Repeater {
                model: catSearch.catRows
                delegate: Item {
                    id: crow
                    required property var modelData
                    required property int index
                    readonly property bool divider: modelData.kind === "divider"
                    readonly property bool active: !divider
                        && Cat.sameTag(Cat.tagOf(modelData), catSearch.tag)
                    width: popupCol.width
                    height: divider ? 11 : 34

                    Rectangle {
                        visible: crow.divider
                        anchors.verticalCenter: parent.verticalCenter
                        x: 10; width: parent.width - 20; height: 1
                        color: Theme.line
                    }
                    Rectangle {
                        visible: !crow.divider
                        anchors.fill: parent
                        radius: Theme.radius
                        color: crow.active
                            ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.24)
                            : crow.index === catSearch.catCursor ? Theme.selected : "transparent"
                    }
                    HoverHandler {
                        enabled: !crow.divider
                        cursorShape: Qt.PointingHandCursor
                        onHoveredChanged: if (hovered) catSearch.catCursor = crow.index
                    }
                    TapHandler {
                        enabled: !crow.divider
                        onTapped: catSearch.choose(crow.index)
                    }
                    Row {
                        visible: !crow.divider
                        x: 8
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 10
                        // Apple's round tile badge: the category's colour, a white glyph.
                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 22; height: 22; radius: 11
                            color: crow.modelData.tint || Theme.selected
                            opacity: crow.modelData.count > 0 || crow.active ? 1 : 0.45
                            Text {
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                text: crow.modelData.icon || ""
                                color: crow.modelData.tint ? "#ffffff" : Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                                font.bold: crow.modelData.kind === "tag"
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            anchors.verticalCenter: parent.verticalCenter
                            width: popupCol.width - 22 - 10 - 8 - countText.width - 18
                            text: crow.modelData.label
                            color: crow.modelData.count > 0 || crow.active ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            font.weight: crow.active ? Font.DemiBold : Font.Normal
                            elide: Text.ElideRight
                        }
                    }
                    Text {
                        id: countText
                        textFormat: Text.PlainText
                        visible: !crow.divider
                        anchors.right: parent.right
                        anchors.rightMargin: 10
                        anchors.verticalCenter: parent.verticalCenter
                        text: crow.divider ? "" : String(crow.modelData.count)
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                    }
                }
            }
        }
    }
}
