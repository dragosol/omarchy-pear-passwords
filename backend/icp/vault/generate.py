"""Generate a strong password in the shape Apple's Passwords app uses.

`xxxxxx-xxxxxx-xxxxxx` - three six-character groups. The point of the shape is that it can be
read off a screen and typed on a phone without losing your place, and the groups are built from
consonant-vowel pairs so each one is a pronounceable nonsense syllable you can actually rehearse.

The honest trade: pronounceable means fewer possibilities per character than random. This lands
around 68 bits, against ~103 for 20 fully random alphanumerics. 68 bits is far beyond anything
an online attacker reaches, and the memorability is what stops someone reusing a password they
already know - which is the threat that actually bites. `entropy_bits()` reports it rather than
leaving the claim vague.
"""

from __future__ import annotations

import math
import secrets

# 'l' and 'o' are left out: against '1' and '0' they are the two that get misread when someone
# reads a password off one screen and types it into another.
CONSONANTS = "bcdfghjkmnpqrstvwxz"
VOWELS = "aeiu"
DIGITS = "23456789"          # no 0/1, same reason
GROUPS = 3
PAIRS_PER_GROUP = 3          # 3 consonant-vowel pairs = 6 characters


def _syllables(rng) -> list:
    return ["".join(rng.choice(CONSONANTS) + rng.choice(VOWELS)
                    for _ in range(PAIRS_PER_GROUP))
            for _ in range(GROUPS)]


def entropy_bits() -> float:
    """Bits of entropy in one generated password, for the shape above."""
    per_pair = math.log2(len(CONSONANTS) * len(VOWELS))
    letters = per_pair * PAIRS_PER_GROUP * GROUPS
    total_chars = GROUPS * PAIRS_PER_GROUP * 2
    digit = math.log2(total_chars) + math.log2(len(DIGITS))   # where it goes, and which digit
    upper = math.log2(total_chars - 1)                        # which remaining letter shifts
    return letters + digit + upper


def generate(rng=None) -> str:
    """A password of the form `hupmyj-8ryTdu-zebqem`.

    Exactly one digit and exactly one uppercase letter, placed at random - the same guarantee
    Apple's generator makes, so the result satisfies sites that demand "a number and a capital"
    without the user having to edit it and weaken it.
    """
    rng = rng or secrets.SystemRandom()
    chars = list("".join(_syllables(rng)))
    n = len(chars)
    digit_at = rng.randrange(n)
    chars[digit_at] = rng.choice(DIGITS)
    upper_at = rng.choice([i for i in range(n) if i != digit_at])
    chars[upper_at] = chars[upper_at].upper()
    joined = "".join(chars)
    size = PAIRS_PER_GROUP * 2
    return "-".join(joined[i:i + size] for i in range(0, n, size))
