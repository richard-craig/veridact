"""SD-JWT VC issuance and the Token Status List, as Veridact v0.5 uses them (docs/proposals/0.5-sd-jwt-vc.md §2, §7).

Small and explicit, ES256 only:

  SD-JWT VC          <issuer-signed JWT, typ dc+sd-jwt>~<disclosure>~...~      (no Key Binding JWT: an entry is
                     about a platform, never presented by it)
  disclosure         base64url(JSON [salt, claim name, claim value]); its digest base64url(SHA-256(disclosure))
                     goes in the issuer-signed `_sd` array
  Token Status List  a JWT, typ statuslist+jwt, whose `status_list` is {bits: 2, lst: base64url(zlib(bytes))};
                     entry i is bits (2i, 2i+1) of the byte array, least significant first.
                     0 VALID, 1 INVALID (withdrawn), 2 SUSPENDED
"""

from __future__ import annotations

import hashlib
import json
import secrets
import zlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from veridact_verify import jose

SD_JWT_TYP = "dc+sd-jwt"
STATUS_LIST_TYP = "statuslist+jwt"
BITS = 2
VALID, INVALID, SUSPENDED = 0, 1, 2
STATUS_NAMES = {VALID: "valid", INVALID: "withdrawn", SUSPENDED: "suspended"}
STATUS_VALUES = {v: k for k, v in STATUS_NAMES.items()}


def disclosure(name: str, value: Any) -> tuple[str, str]:
    """(disclosure, digest) for one selectively disclosable claim."""
    d = jose.b64url_encode(json.dumps([secrets.token_urlsafe(16), name, value], separators=(",", ":")).encode())
    return d, jose.b64url_encode(hashlib.sha256(d.encode("ascii")).digest())


def issue(claims: dict[str, Any], key: ec.EllipticCurvePrivateKey, kid: str,
          selectively_disclosable: dict[str, Any] | None = None) -> str:
    """An SD-JWT VC: the issuer-signed JWT, then each disclosure, each followed by '~'."""
    payload = dict(claims)
    disclosures: list[str] = []
    if selectively_disclosable:
        digests = []
        for name, value in selectively_disclosable.items():
            d, h = disclosure(name, value)
            disclosures.append(d)
            digests.append(h)
        payload["_sd"] = sorted(digests)
        payload["_sd_alg"] = "sha-256"
    jwt = jose.sign({"typ": SD_JWT_TYP, "kid": kid}, payload, key)
    return jwt + "~" + "".join(d + "~" for d in disclosures)


def encode_status_list(values: dict[int, int], size: int) -> str:
    raw = bytearray((size * BITS + 7) // 8)
    for idx, value in values.items():
        if not 0 <= idx < size or value not in STATUS_NAMES:
            raise ValueError(f"bad status entry {idx}={value}")
        byte, shift = divmod(idx * BITS, 8)
        raw[byte] = (raw[byte] & ~(0b11 << shift)) | (value << shift)
    return jose.b64url_encode(zlib.compress(bytes(raw), 9))


def decode_status(lst: str, idx: int, bits: int = BITS) -> int:
    raw = zlib.decompress(jose.b64url_decode(lst))
    byte, shift = divmod(idx * bits, 8)
    if byte >= len(raw):
        raise ValueError("status index outside the list")
    return (raw[byte] >> shift) & ((1 << bits) - 1)


def status_list_token(uri: str, iss: str, values: dict[int, int], size: int, key: ec.EllipticCurvePrivateKey,
                      kid: str, iat: int, ttl: int) -> str:
    payload = {"iss": iss, "sub": uri, "iat": iat, "exp": iat + max(ttl * 2, 600), "ttl": ttl,
               "status_list": {"bits": BITS, "lst": encode_status_list(values, size)}}
    return jose.sign({"typ": STATUS_LIST_TYP, "kid": kid}, payload, key)
