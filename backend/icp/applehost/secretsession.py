"""Server half of Apple's `SecretSession` PAKE, so their iCloud Passwords extension can pair
with us instead of with iCloud for Windows.

Transcribed from the shipped extension's `background.js`; see docs/apple-extension-protocol.md.
It is SRP-6a over the 3072-bit group with SHA-256, but the hash inputs and padding are specific
enough that textbook SRP will not interoperate. The exact rules, as the client computes them:

    I           random 128-bit identity, echoed as TID on every message
    x           SHA256( s || SHA256(I_str + ":" + P) )        P = the pairing PIN
    v           g**x mod N
    k           SHA256( hex( N_str + pad(g_str) ) )           N unpadded, g padded
    u           SHA256( hex( pad(A_str) + pad(B_str) ) )      both padded
    S(client)   (B - k*v) ** (a + u*x) mod N
    S(server)   (A * v**u) ** b mod N
    K           SHA256( S )
    M1          SHA256( (SHA256(N) xor SHA256(pad(g))) || SHA256(I_str) || s || A || B || K )
    HAMK        SHA256( A || M1 || K )

`pad` left-pads the hex form to the modulus width (768 hex chars). Note k hashes N *unpadded*
but g padded - an asymmetry that looks like a bug in their implementation and which we have to
reproduce exactly, because interoperability is the whole point.

Wire encoding is hex; sjcl's hex codec strips a leading `0x`, so values arrive with and without
it and both are accepted. We are the SRP **server**: we pick the PIN and display it, mirroring
what iCloud for Windows does.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets

# RFC 5054 group 15 (3072-bit), which is what sjcl's srp 3072 group uses.
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
N = int(N_HEX, 16)
G = 5
MODULUS_HEX_LEN = len(N_HEX)          # 768

MSG0, MSG1, MSG2, MSG3 = 0, 1, 2, 3
SRP_OLD_VERIFICATION, SRP_RFC_VERIFICATION = 0, 1


class SecretSessionError(Exception):
    pass


def _h(*chunks: bytes) -> bytes:
    d = hashlib.sha256()
    for c in chunks:
        d.update(c)
    return d.digest()


def _unhex(value: str) -> bytes:
    """Parse a wire hex string. sjcl's codec strips `0x` and whitespace, so we do too, and an
    odd-length string is left-padded rather than rejected."""
    s = "".join(value.split()).lower().replace("0x", "")
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def _pad_hex(value: int) -> str:
    """Hex, left-padded to the modulus width - `_padToModulusLength` in the client."""
    return format(value, "x").rjust(MODULUS_HEX_LEN, "0")


def _int_bytes(value: int) -> bytes:
    """Minimal big-endian bytes, matching how sjcl renders a bn to bits."""
    h = format(value, "x")
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)


def compute_k() -> int:
    return int.from_bytes(_h(_unhex(N_HEX + _pad_hex(G))), "big")


def compute_u(A: int, B: int) -> int:
    return int.from_bytes(_h(_unhex(_pad_hex(A) + _pad_hex(B))), "big")


def compute_x(salt: bytes, identity_str: str, pin: str) -> int:
    inner = _h(f"{identity_str}:{pin}".encode())
    return int.from_bytes(_h(salt + inner), "big")


def compute_M(identity_str: str, salt: bytes, A: int, B: int, K: bytes) -> tuple[bytes, bytes]:
    """(M1, HAMK). The client sends M1; we answer with HAMK so it can verify us."""
    hn = _h(_unhex(N_HEX))
    hg = _h(_unhex(_pad_hex(G)))
    xored = bytes(a ^ b for a, b in zip(hn, hg))
    m1 = _h(xored, _h(identity_str.encode()), salt,
            _int_bytes(A), _int_bytes(B), K)
    hamk = _h(_int_bytes(A), m1, K)
    return m1, hamk


class SecretSessionServer:
    """One pairing. `pin` is what we display and the user types into the extension."""

    def __init__(self, pin: str, *, salt: bytes | None = None, b: int | None = None):
        self.pin = pin
        self.salt = salt if salt is not None else secrets.token_bytes(16)
        self.b = b if b is not None else int.from_bytes(secrets.token_bytes(32), "big") % N
        self.identity_str: str | None = None
        self.A: int | None = None
        self.B: int | None = None
        self.K: bytes | None = None
        self.protocol = SRP_RFC_VERIFICATION
        self._m1: bytes | None = None

    # ------------------------------------------------------------------ handshake

    def handle_msg0(self, msg: dict) -> dict:
        """MSG0 {TID, MSG:0, A, VER, PROTO} -> MSG1 {s, B, VER, PROTO}."""
        if "TID" not in msg or "A" not in msg:
            raise SecretSessionError("MSG0 missing TID or A")
        # TID is the identity rendered by the client; x hashes that exact string, so it is kept
        # verbatim rather than re-encoded from the integer.
        self.identity_str = str(msg["TID"])
        self.A = int.from_bytes(_unhex(str(msg["A"])), "big")
        if self.A % N == 0:
            raise SecretSessionError("A % N == 0")

        offered = msg.get("PROTO")
        if isinstance(offered, list) and SRP_RFC_VERIFICATION in offered:
            self.protocol = SRP_RFC_VERIFICATION
        elif isinstance(offered, list) and offered:
            self.protocol = SRP_OLD_VERIFICATION

        x = compute_x(self.salt, self.identity_str, self.pin)
        v = pow(G, x, N)
        self.B = (compute_k() * v + pow(G, self.b, N)) % N

        S = pow(self.A * pow(v, compute_u(self.A, self.B), N), self.b, N)
        self.K = _h(_int_bytes(S))
        self._m1, self._hamk = compute_M(self.identity_str, self.salt, self.A, self.B, self.K)

        return {"TID": self.identity_str, "MSG": MSG1, "VER": "1.0",
                "PROTO": self.protocol,
                "s": self.salt.hex(), "B": format(self.B, "x")}

    def handle_msg2(self, msg: dict) -> dict:
        """MSG2 {TID, MSG:2, M} -> MSG3 {ErrCode:0, HAMK}. A wrong PIN fails here."""
        if self.K is None:
            raise SecretSessionError("MSG2 before MSG0")
        if self.protocol == SRP_RFC_VERIFICATION:
            supplied = _unhex(str(msg.get("M", "")))
            if not secrets.compare_digest(supplied, self._m1):
                raise SecretSessionError("client proof mismatch (wrong PIN)")
        return {"TID": self.identity_str, "MSG": MSG3, "ErrCode": 0,
                "HAMK": self._hamk.hex()}

    # ------------------------------------------------------------------ data channel

    @property
    def enc_key(self) -> bytes:
        """AES key: the leading 128 bits of the session key, per the client's bitSlice."""
        if self.K is None:
            raise SecretSessionError("no session key yet")
        return self.K[:16]

    def encrypt(self, plaintext: str) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = os.urandom(16)
        ct = AESGCM(self.enc_key).encrypt(iv, plaintext.encode(), None)
        return {"TID": self.identity_str, "SDATA": (iv + ct).hex()}

    def decrypt(self, msg: dict) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        blob = _unhex(str(msg.get("SDATA", "")))
        iv, ct = blob[:16], blob[16:]
        return AESGCM(self.enc_key).decrypt(iv, ct, None).decode()

    # ------------------------------------------------------------------ dispatch

    def handle(self, raw: str | dict) -> dict:
        msg = json.loads(raw) if isinstance(raw, str) else raw
        kind = int(msg.get("MSG", -1))
        if kind == MSG0:
            return self.handle_msg0(msg)
        if kind == MSG2:
            return self.handle_msg2(msg)
        raise SecretSessionError(f"unexpected MSG {kind}")
