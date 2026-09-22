"""Trust anchors for Apple's endpoints.

gsa.apple.com is served from Apple's *private* PKI: the chain ends at "Apple Root CA", which is
not in Mozilla's CA program and so is absent from certifi, the bundle requests uses. Apple's
devices ship it; a stock Python does not, so verification legitimately fails.

Upstream's answer was verify=False on every call, which does not just accept this one root - it
accepts anything at all, including a real interceptor's certificate. The narrow fix is to trust
exactly one extra root: certifi's bundle plus Apple Root CA, written to a cache file that
requests can be pointed at.

The bundled PEM is checked against its published SHA-256 on every load, so a swapped file fails
loudly instead of silently widening what we trust:

    B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024

(Published at https://www.apple.com/appleca/AppleIncRootCertificate.cer and confirmed identical
to the root gsa.apple.com actually serves.)
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..errors import AppleError

APPLE_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

_cached: str | None = None


class TrustError(AppleError):
    pass


def _apple_root_pem() -> bytes:
    p = Path(__file__).resolve().parent.parent / "certs" / "apple-root-ca.pem"
    pem = p.read_bytes()
    der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    got = hashlib.sha256(der).hexdigest()
    if got != APPLE_ROOT_SHA256:
        raise TrustError(
            f"{p} is not the expected Apple Root CA (sha256 {got}); refusing to trust it.")
    return pem


def bundle() -> str:
    """Path to a CA bundle of certifi + Apple Root CA. Pass as requests' `verify=`."""
    global _cached
    if _cached and os.path.exists(_cached):
        return _cached

    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    d = Path(base) / "icp"
    d.mkdir(parents=True, exist_ok=True)
    out = d / "ca-bundle.pem"

    data = Path(certifi.where()).read_bytes().rstrip() + b"\n" + _apple_root_pem().rstrip() + b"\n"
    tmp = out.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(out)          # atomic, so a concurrent reader never sees a half-written bundle
    _cached = str(out)
    return _cached
