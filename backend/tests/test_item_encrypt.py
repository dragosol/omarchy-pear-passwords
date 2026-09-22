"""The encrypt direction for `item` records.

Validated against reality separately: re-encrypting all 1438 live records with their own
IV, AAD and padded length reproduced Apple's stored `data` byte for byte. These tests pin
the parts of that which can be checked without an account.
"""

import os
import unittest

from icp.keychain import crypto as kc


class PaddingTests(unittest.TestCase):
    def test_pads_to_a_multiple_of_twenty(self):
        for n in (0, 1, 19, 20, 21, 457, 752):
            with self.subTest(n=n):
                self.assertEqual(len(kc._apply_iso7816_padding(b"x" * n)) % kc.ITEM_PAD_BLOCK, 0)

    def test_aligned_plaintext_gains_a_whole_block(self):
        # Otherwise the last byte of real data could be mistaken for the 0x80 marker.
        self.assertEqual(len(kc._apply_iso7816_padding(b"x" * 20)), 40)

    def test_marker_then_zeroes(self):
        p = kc._apply_iso7816_padding(b"x" * 17)
        self.assertEqual(p[17], 0x80)
        self.assertEqual(set(p[18:]), {0x00})

    def test_pad_to_sets_an_exact_length(self):
        self.assertEqual(len(kc._apply_iso7816_padding(b"x" * 457, pad_to=480)), 480)

    def test_pad_to_refuses_a_plaintext_that_will_not_fit(self):
        for target in (480, 479, 1):
            with self.subTest(target=target):
                with self.assertRaises(kc.KeychainCryptoError):
                    kc._apply_iso7816_padding(b"y" * 480, pad_to=target)


class ItemRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(64)
        self.iv = os.urandom(16)
        self.aad = [b"uuid", b"\x02" + b"\x00" * 7]

    def test_round_trip_for_every_length_class(self):
        for n in (0, 1, 15, 16, 17, 19, 20, 21, 457, 752, 2251):
            with self.subTest(n=n):
                msg = os.urandom(n)
                blob = kc.encrypt_item(self.key, msg, self.aad, iv=self.iv)
                self.assertEqual(kc.decrypt_item(self.key, blob, self.aad), msg)

    def test_layout_is_iv_then_siv(self):
        blob = kc.encrypt_item(self.key, b"x" * 457, self.aad, iv=self.iv, pad_to=480)
        self.assertEqual(blob[:16], self.iv)
        self.assertEqual(len(blob), 16 + 16 + 480)   # iv || tag || ciphertext

    def test_deterministic_given_the_same_iv(self):
        # This is what makes reproducing a stored record a usable correctness oracle.
        a = kc.encrypt_item(self.key, b"same", self.aad, iv=self.iv)
        b = kc.encrypt_item(self.key, b"same", self.aad, iv=self.iv)
        self.assertEqual(a, b)

    def test_aad_is_authenticated(self):
        blob = kc.encrypt_item(self.key, b"secretish", self.aad, iv=self.iv)
        with self.assertRaises(Exception):
            kc.decrypt_item(self.key, blob, [b"uuid", b"tampered"])

    def test_iv_must_be_sixteen_bytes(self):
        with self.assertRaises(kc.KeychainCryptoError):
            kc.encrypt_item(self.key, b"x", self.aad, iv=b"short")


if __name__ == "__main__":
    unittest.main()
