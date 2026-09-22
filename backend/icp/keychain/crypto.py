"""iCloud Keychain decryption: SF-ECIES (P-384 / X9.63-KDF / AES-256-GCM) and AES-256-SIV
key unwrap. See RESEARCH.md "keychain/crypto.py"."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV

from ..errors import AppleError


class KeychainCryptoError(AppleError):
    pass


def x963_kdf(secret: bytes, shared_info: bytes, length: int,
             hashfn=hashlib.sha256) -> bytes:
    out = bytearray()
    counter = 1
    while len(out) < length:
        out += hashfn(secret + counter.to_bytes(4, "big") + shared_info).digest()
        counter += 1
    return bytes(out[:length])


def ecies_decrypt(private_key: ec.EllipticCurvePrivateKey, ephemeral_sender_pub: bytes,
                  ciphertext: bytes, auth_code: bytes) -> bytes:
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        private_key.curve, ephemeral_sender_pub)
    secret = private_key.exchange(ec.ECDH(), eph_pub)
    derived = x963_kdf(secret, ephemeral_sender_pub, 48)
    key, iv = derived[:32], derived[32:48]
    return AESGCM(key).decrypt(iv, ciphertext + auth_code, None)


def ecies_decrypt_sf(private_key: ec.EllipticCurvePrivateKey, ies: dict) -> bytes:
    """Decrypt an Apple `IESCiphertext` dict (unarchived from a TLKShare `wrappedkey`)."""
    eph = bytes(ies["SFEphemeralSenderPublicKeyExternaRepresentation"])
    ct = bytes(ies["SFCiphertext"])
    tag = bytes(ies["SFIESAuthenticationCode"])
    # SecurityFoundation appends 97+16 bytes of junk to the stored ciphertext; trim it.
    real_ct = ct[:-(97 + 16)] if len(ct) > 97 + 16 else ct
    return ecies_decrypt(private_key, eph, real_ct, tag)


def siv_unwrap(key64: bytes, wrapped: bytes, associated_data=None) -> bytes:
    return AESSIV(key64).decrypt(wrapped, list(associated_data or []))


def _strip_iso7816_padding(data: bytes) -> bytes:
    ptr = len(data)
    while ptr > 0:
        ptr -= 1
        if data[ptr] == 0x00:
            continue
        if data[ptr] == 0x80:
            return data[:ptr]
        raise KeychainCryptoError("bad ISO-7816-4 padding")
    return data


def siv_wrap(key64: bytes, plaintext: bytes, associated_data=None) -> bytes:
    """Inverse of siv_unwrap. AES-SIV is deterministic, so the same key + AAD + plaintext
    always reproduce the same bytes - which is what makes a re-encrypt round trip checkable
    against the record Apple already stored."""
    return AESSIV(key64).encrypt(plaintext, list(associated_data or []))


ITEM_PAD_BLOCK = 20
"""Apple pads item plaintext to a multiple of 20 bytes, not a cipher block.

Derived empirically: across 1438 live records every padded length was a multiple of 20
(280, 300, ... up to 2260 for a 2251-byte plaintext). Against 1438 records the padded length
was either exactly the next multiple of 20 (1276) or that plus one extra block (162) - never
anything else, so some Apple producer emits a spare block. Both are valid padding and decrypt
identically, but it means we cannot always predict Apple's choice: when rewriting an existing
record, pass pad_to=<its current padded length> and the ciphertext reproduces exactly.
Getting this wrong still decrypts locally - _strip_iso7816_padding does not care how much
padding there is - so it would pass every round-trip test we wrote and only show up as a
record other Apple devices format differently from us."""


def _apply_iso7816_padding(data: bytes, block: int = ITEM_PAD_BLOCK, *,
                           pad_to: int | None = None) -> bytes:
    """0x80 then 0x00s out to a block boundary. Always adds at least the 0x80, so a plaintext
    that is already aligned gains a whole block - otherwise the trailing byte would be
    ambiguous with real data on the way back out.

    pad_to overrides the block rule with an exact target length, used when rewriting an
    existing record so the ciphertext keeps the size Apple gave it. That both reproduces
    unchanged records byte for byte and stops an edit from advertising itself as a
    length change on the wire."""
    if pad_to is not None:
        if pad_to <= len(data):
            raise KeychainCryptoError(
                f"pad_to={pad_to} cannot hold a {len(data)}-byte plaintext plus its marker")
        return data + b"\x80" + b"\x00" * (pad_to - len(data) - 1)
    marked = len(data) + 1                       # the 0x80 marker is part of what gets rounded
    blocks = max(2, -(-marked // block))         # rustpush enforces a two-block minimum
    return data + b"\x80" + b"\x00" * (blocks * block - marked)


def encrypt_item(item_key64: bytes, plaintext: bytes, aad_values=None, *, iv: bytes,
                 pad_to: int | None = None) -> bytes:
    """Build an `item` record's `data` (= iv(16) || SIV(tag||ciphertext)), mirroring
    decrypt_item. The IV is passed in rather than generated here so a caller can reproduce an
    existing record exactly; new records must pass os.urandom(16)."""
    if len(iv) != 16:
        raise KeychainCryptoError(f"item IV must be 16 bytes, got {len(iv)}")
    headers = [iv] + list(aad_values or [])
    return iv + siv_wrap(item_key64, _apply_iso7816_padding(plaintext, pad_to=pad_to), headers)


def decrypt_item(item_key64: bytes, data: bytes, aad_values=None) -> bytes:
    """Decrypt an `item` record's `data` (= randomIV(16) || SIV(tag||ciphertext)). The leading
    random IV is prepended as the first associated-data element."""
    iv = data[:16]
    headers = [iv] + list(aad_values or [])
    plaintext = siv_unwrap(item_key64, data[16:], headers)
    return _strip_iso7816_padding(plaintext)
