"""Minimal compact JWS for Veridact: ES256 only.

Veridact signs everything with ES256 (P-256), so this module accepts exactly that
algorithm and nothing else. Refusing every other ``alg`` up front closes the usual
JOSE algorithm-confusion attacks ("none", HS256 with a public key, and so on).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ALG = "ES256"
_COORD = 32  # P-256 coordinate / signature half length in bytes


class JoseError(ValueError):
    """Raised for malformed or unverifiable JWS input."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or any(c in text for c in "=+/ \n"):
        raise JoseError("not base64url without padding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as err:
        raise JoseError("invalid base64url") from err


@dataclass(frozen=True)
class CompactJws:
    """A parsed, not yet verified, compact JWS."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes
    signature: bytes
    raw: str

    @property
    def kid(self) -> str | None:
        kid = self.header.get("kid")
        return kid if isinstance(kid, str) else None

    @property
    def typ(self) -> str | None:
        typ = self.header.get("typ")
        return typ if isinstance(typ, str) else None


def parse(token: str, *, max_length: int = 64 * 1024) -> CompactJws:
    """Parse a compact JWS with a JSON object payload. Does not verify it."""
    if not isinstance(token, str) or len(token) > max_length:
        raise JoseError("token missing or too long")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("not a compact JWS")
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise JoseError("header or payload is not JSON") from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("header and payload must be JSON objects")
    if header.get("alg") != ALG:
        raise JoseError(f"alg must be {ALG}")
    if "crit" in header:
        raise JoseError("crit header parameters are not supported")
    return CompactJws(
        header=header,
        payload=payload,
        signing_input=f"{h_b64}.{p_b64}".encode("ascii"),
        signature=b64url_decode(s_b64),
        raw=token,
    )


def verify(jws: CompactJws, key: ec.EllipticCurvePublicKey) -> None:
    """Verify an ES256 signature; raise JoseError on failure."""
    if not isinstance(key.curve, ec.SECP256R1):
        raise JoseError("ES256 requires a P-256 key")
    if len(jws.signature) != 2 * _COORD:
        raise JoseError("ES256 signature must be 64 bytes")
    r = int.from_bytes(jws.signature[:_COORD], "big")
    s = int.from_bytes(jws.signature[_COORD:], "big")
    try:
        key.verify(encode_dss_signature(r, s), jws.signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as err:
        raise JoseError("signature does not verify") from err


def sign(header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey) -> str:
    """Produce a compact ES256 JWS. Used by test tooling and vbot."""
    header = {**header, "alg": ALG}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign(f"{h_b64}.{p_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(_COORD, "big") + s.to_bytes(_COORD, "big")
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


# --- key encodings -----------------------------------------------------------

_P256_MULTICODEC = b"\x80\x24"  # varint(0x1200), p256-pub
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(text: str) -> bytes:
    num = 0
    for ch in text:
        idx = _B58.find(ch)
        if idx < 0:
            raise JoseError("invalid base58btc")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


def _b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise JoseError("expected a public EC P-256 JWK")
    x = b64url_decode(jwk.get("x", ""))
    y = b64url_decode(jwk.get("y", ""))
    if len(x) != _COORD or len(y) != _COORD:
        raise JoseError("bad P-256 coordinates")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as err:
        raise JoseError("point not on curve") from err


def key_to_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    nums = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(nums.x.to_bytes(_COORD, "big")),
        "y": b64url_encode(nums.y.to_bytes(_COORD, "big")),
    }


def key_from_multikey(multibase: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(multibase, str) or not multibase.startswith("z"):
        raise JoseError("Multikey must be base58btc multibase")
    raw = _b58decode(multibase[1:])
    if not raw.startswith(_P256_MULTICODEC):
        raise JoseError("Multikey is not p256-pub")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[2:])
    except ValueError as err:
        raise JoseError("invalid P-256 point") from err


def key_to_multikey(key: ec.EllipticCurvePublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    point = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return "z" + _b58encode(_P256_MULTICODEC + point)


def key_from_verification_method(vm: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Extract a P-256 key from a Multikey or JsonWebKey verification method."""
    vm_type = vm.get("type")
    if vm_type == "Multikey" and "publicKeyMultibase" in vm:
        return key_from_multikey(vm["publicKeyMultibase"])
    if vm_type in ("JsonWebKey", "JsonWebKey2020") and isinstance(vm.get("publicKeyJwk"), dict):
        return key_from_jwk(vm["publicKeyJwk"])
    raise JoseError(f"unsupported verification method type {vm_type!r}")
