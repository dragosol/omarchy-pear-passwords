"""The notes tag line (features spec 5b): its grammar, and that every edit through it keeps the
bytes it does not own.

The fixtures are stored strings in the shapes real notes take (LF and CRLF notes, a note typed
on an iPhone with a single newline before the line, NBSP and U+2028 in the body, a last line
that is almost a tag line). None of it is user data.
"""

import random
import unicodedata
import unittest

from icp.keychain import tagline as tl

# Real-shape notes, as Apple's Passwords app and Pear write them.
FIXTURES = [
    "",
    "Tags: #work",
    "PIN 4821 for the door\n\nTags: #work #finance",
    "Recovery codes:\r\nabcd-efgh\r\nijkl-mnop\r\n\r\nTags: #bank",
    "typed on an iPhone\nTags: #home",
    "line one still line one with nbsp\n\nTags: #side-project",
    "almost a tag line at the end\nTags: #a,b",
    "Tags: #x\nmore text after it",
    "\n\nleading newlines\n\n",
    "trailing CR\r",
    "Tags: #café #Straße #１２３",
]


class GrammarTests(unittest.TestCase):
    def test_empty_and_only_the_line(self):
        self.assertEqual(tl.split(""), ("", []))
        self.assertEqual(tl.split("Tags: #work"), ("", ["work"]))
        self.assertEqual(tl.split("Tags: #Work #FINANCE"), ("", ["work", "finance"]))

    def test_lf_crlf_trailing_cr_and_trailing_blanks(self):
        self.assertEqual(tl.split("body\n\nTags: #a"), ("body", ["a"]))
        self.assertEqual(tl.split("body\nTags: #a"), ("body", ["a"]))
        self.assertEqual(tl.split("body\r\n\r\nTags: #a"), ("body", ["a"]))
        self.assertEqual(tl.split("body\r\nTags: #a\r"), ("body", ["a"]))
        self.assertEqual(tl.split("body\n\nTags: #a  \t"), ("body", ["a"]))
        self.assertEqual(tl.split("body\n\n  Tags:\t#a\t#b"), ("body", ["a", "b"]))

    def test_label_is_ascii_and_any_case(self):
        for label in ("tags:", "TAGS:", "tAgS:"):
            self.assertEqual(tl.split(f"{label} #a"), ("", ["a"]), label)
        for bad in ("Tag: #a", "Tags #a", "Tags:#a", "Tagś: #a", "Ｔags: #a"):
            self.assertEqual(tl.split(bad), (bad, []), bad)

    def test_only_the_last_line_counts(self):
        raw = "Tags: #x\nmore text after it"
        self.assertEqual(tl.split(raw), (raw, []))

    def test_one_bad_token_makes_the_whole_line_body(self):
        for line in ("Tags: #a,b", "Tags: #", "Tags: work", "Tags: #a work", "Tags: ##work",
                     "Tags: #a#b", "Tags: #a:b", "Tags:", "Tags: ", "Tags: #a #b"):
            raw = "body\n\n" + line
            self.assertEqual(tl.split(raw), (raw, []), line)

    def test_sixteen_tags_and_32_characters(self):
        sixteen = " ".join(f"#t{i}" for i in range(16))
        self.assertEqual(len(tl.split("Tags: " + sixteen)[1]), 16)
        seventeen = sixteen + " #t16"
        self.assertEqual(tl.split("Tags: " + seventeen)[1], [])
        self.assertEqual(tl.split("Tags: #" + "a" * 32)[1], ["a" * 32])
        self.assertEqual(tl.split("Tags: #" + "a" * 33)[1], [])
        self.assertEqual(tl.split("Tags: #a")[1], ["a"])          # one character is a tag

    def test_unicode_normalisation_and_fold(self):
        nfd = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(nfd, "café")
        self.assertEqual(tl.split(f"Tags: #{nfd}")[1], ["café"])          # NFC on read
        self.assertEqual(tl.split("Tags: #café #" + nfd)[1], ["café"])     # one tag
        self.assertEqual(tl.fold("Straße"), tl.fold("STRASSE"))
        self.assertEqual(tl.split("Tags: #Straße #STRASSE")[1], ["straße"])  # first wins
        self.assertEqual(tl.split("Tags: #work #ｗｏｒｋ")[1], ["work"])   # NFKC fold
        self.assertEqual(tl.split("Tags: #ｗｏｒｋ #work")[1], ["ｗｏｒｋ"])
        self.assertEqual(tl.split("Tags: #x-y_z #１２３")[1], ["x-y_z", "１２３"])

    def test_emoji_and_symbols_are_not_tags(self):
        for bad in ("Tags: #🔑", "Tags: #a🔑", "Tags: #€", "Tags: #a.b", "Tags: #a/b"):
            self.assertEqual(tl.split(bad)[1], [], bad)

    def test_canonical_line_and_client_lists(self):
        self.assertEqual(tl.line(["work", "finance"]), "Tags: #work #finance")
        self.assertEqual(tl.line([]), "")
        self.assertEqual(tl.canon_list(["#Work", "finance", "WORK", "#ｗｏｒｋ"]),
                         ["work", "finance"])
        for bad in (["a b"], ["#"], [""], ["a,b"], ["##a"], [1], "work", ["x" * 33],
                    [f"t{i}" for i in range(17)], ["🔑"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                tl.canon_list(bad)


class ComposeTests(unittest.TestCase):
    def test_compose(self):
        self.assertEqual(tl.compose("body", []), "body")
        self.assertEqual(tl.compose("", ["a"]), "Tags: #a")
        self.assertEqual(tl.compose("body", ["a", "b"]), "body\n\nTags: #a #b")
        self.assertEqual(tl.compose("x\r\ny", ["a"]), "x\r\ny\r\n\r\nTags: #a")
        self.assertEqual(tl.compose("x\r\ny\nz", ["a"]), "x\r\ny\nz\n\nTags: #a")

    def test_replace_tags_touches_only_the_line(self):
        raw = "Recovery codes:\r\nabcd-efgh\r\n\r\ntags:\t#Bank  "
        out = tl.replace_tags(raw, ["bank", "work"])
        self.assertEqual(out, "Recovery codes:\r\nabcd-efgh\r\n\r\nTags: #bank #work")
        self.assertEqual(tl.replace_tags("typed on an iPhone\nTags: #home", []),
                         "typed on an iPhone")
        # The single newline an iPhone user typed stays single: it is kept, not recomposed.
        self.assertEqual(tl.replace_tags("typed on an iPhone\nTags: #home", ["x"]),
                         "typed on an iPhone\nTags: #x")
        self.assertEqual(tl.replace_tags("no line yet", ["a"]), "no line yet\n\nTags: #a")
        self.assertEqual(tl.replace_tags("Tags: #a", []), "")

    def test_replace_body_keeps_the_line_bytes(self):
        raw = "old body\n\ntags: #Work"
        self.assertEqual(tl.replace_body(raw, "new body"), "new body\n\ntags: #Work")
        self.assertEqual(tl.replace_body(raw, ""), "tags: #Work")
        self.assertEqual(tl.replace_body("Tags: #a", "now a body"), "now a body\n\nTags: #a")
        self.assertEqual(tl.replace_body("no tags", "other"), "other")
        # A body ending in a newline would merge with a kept single newline: compose's blank
        # line is used instead, and the body still reads back exactly.
        out = tl.replace_body("x\nTags: #a", "y\n")
        self.assertEqual(tl.split(out), ("y\n", ["a"]))

    def test_fixtures_round_trip(self):
        for raw in FIXTURES:
            body, tags = tl.split(raw)
            if tags:
                # Removing the line gives exactly the body; the body is a prefix of the raw.
                self.assertEqual(tl.replace_tags(raw, []), body, repr(raw))
                self.assertTrue(raw.startswith(body), repr(raw))
                # A canonical line is rewritten to itself.
                last = raw[raw.rfind("\n") + 1:]
                if last == tl.line(tags):
                    self.assertEqual(tl.replace_tags(raw, tags), raw, repr(raw))
            else:
                self.assertEqual(body, raw)
                self.assertEqual(tl.replace_tags(tl.replace_tags(raw, ["x"]), []), raw,
                                 repr(raw))


class PropertyTests(unittest.TestCase):
    """Random bodies with leading/trailing newlines, CRLF, lone CR, NBSP, U+2028 and lines that
    are almost tag lines."""

    PIECES = ["a", "b", "\n", "\r", "\r\n", " ", "\t", " ", " ", "é", "#", "x",
              "Tags: #x", "Tags: #a,b", "tags:\t#y #Z", "Tags: #a #a", "Tags:#q"]
    TAGS = ["a", "work", "café", "Straße", "ｗｏｒｋ", "x-y", "1", "#Q_q"]

    def body(self, rnd):
        return "".join(rnd.choice(self.PIECES) for _ in range(rnd.randint(0, 10)))

    def test_properties(self):
        rnd = random.Random(20261008)
        for _ in range(20000):
            b = self.body(rnd)
            t = tl.canon_list([rnd.choice(self.TAGS) for _ in range(rnd.randint(0, 5))])
            raw = tl.compose(b, t)
            if t:
                self.assertEqual(tl.split(raw), (b, t), (b, t))
            body, cur = tl.split(b)
            after = tl.replace_tags(b, t)
            # Everything before the tag line is the original's.
            prefix = body if cur else b
            self.assertTrue(after.startswith(prefix), (b, t))
            if t:
                self.assertEqual(tl.split(after), (prefix, t), (b, t))
            # Removing all tags gives exactly the original body.
            self.assertEqual(tl.replace_tags(b, []), prefix, b)
            if not cur:
                # Adding tags, then removing them, restores the raw notes byte for byte.
                self.assertEqual(tl.replace_tags(tl.replace_tags(b, t), []), b, (b, t))
            elif b[b.rfind("\n") + 1:] == tl.line(cur):
                self.assertEqual(tl.replace_tags(b, cur), b, b)
            # A body edit keeps the tag line and reads back exactly.
            nb = self.body(rnd)
            if cur:
                self.assertEqual(tl.split(tl.replace_body(b, nb)), (nb, cur), (b, nb))

    def test_canon_is_idempotent(self):
        for t in self.TAGS + ["İstanbul", "ǅemal", "Ångström", "ﬁx"]:
            c = tl.canon(t.lstrip("#"))
            if c is not None:
                self.assertEqual(tl.canon(c), c, t)
                self.assertEqual(tl.split(tl.line([c]))[1], [c], t)


if __name__ == "__main__":
    unittest.main()
