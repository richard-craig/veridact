"""ACME message handling (RFC 8555 section 6), ES256 only.

Every POST is a flattened JWS whose protected header carries ``nonce``, ``url`` and
either ``jwk`` (new-account) or ``kid`` (the account URL). Like the verifier, this
refuses every algorithm except ES256 before anything else is parsed.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable

from veridact_verify import jose

ERR = "urn:ietf:params:acme:error:"


class AcmeProblem(Exception):
    """An ACME problem document (RFC 8555 section 6.7)."""

    def __init__(self, kind: str, detail: str, status: int = 400, **extra: Any):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail
        self.status = status
        self.extra = extra

    def body(self) -> dict[str, Any]:
        return {"type": ERR + self.kind, "detail": self.detail, "status": self.status, **self.extra}


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint of a P-256 JWK, base64url."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                           separators=(",", ":"), sort_keys=True)
    return jose.b64url_encode(hashlib.sha256(canonical.encode()).digest())


def key_authorization(token: str, jwk: dict[str, str]) -> str:
    return f"{token}.{jwk_thumbprint(jwk)}"


def dns01_txt_value(token: str, jwk: dict[str, str]) -> str:
    return jose.b64url_encode(hashlib.sha256(key_authorization(token, jwk).encode()).digest())


class NonceStore:
    """Replay nonces: single use, short lived. One process; Month 2 moves this to Redis."""

    def __init__(self, ttl: float = 600.0, clock: Callable[[], float] = time.time,
                 max_live: int = 200_000):
        self.ttl = ttl
        self.clock = clock
        self.max_live = max_live
        self._live: dict[str, float] = {}

    def issue(self) -> str:
        now = self.clock()
        if len(self._live) >= self.max_live:
            self._live = {n: e for n, e in self._live.items() if e > now}
        nonce = secrets.token_urlsafe(18)
        self._live[nonce] = now + self.ttl
        return nonce

    def consume(self, nonce: str) -> bool:
        exp = self._live.pop(nonce, None)
        return exp is not None and exp > self.clock()


@dataclass
class SignedRequest:
    protected: dict[str, Any]
    payload: dict[str, Any] | None  # None for POST-as-GET
    jwk: dict[str, str] | None
    kid: str | None
    nonce: str
    url: str


def parse_flattened(body: bytes) -> tuple[dict[str, Any], jose.CompactJws, bytes]:
    """Parse a flattened JWS. Returns (protected header, jws for verification, raw payload)."""
    try:
        outer = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcmeProblem("malformed", "body is not JSON") from None
    if not isinstance(outer, dict) or set(outer) - {"protected", "payload", "signature", "header"}:
        raise AcmeProblem("malformed", "expected a flattened JWS")
    if "header" in outer:
        raise AcmeProblem("malformed", "unprotected header not allowed")
    p64, b64, s64 = outer.get("protected"), outer.get("payload"), outer.get("signature")
    if not all(isinstance(v, str) for v in (p64, b64, s64)):
        raise AcmeProblem("malformed", "protected, payload and signature are required")
    try:
        protected = json.loads(jose.b64url_decode(p64))
        raw_payload = jose.b64url_decode(b64) if b64 else b""
        signature = jose.b64url_decode(s64)
    except (jose.JoseError, json.JSONDecodeError, UnicodeDecodeError):
        raise AcmeProblem("malformed", "bad base64url or JSON in JWS") from None
    if not isinstance(protected, dict):
        raise AcmeProblem("malformed", "protected header must be an object")
    if protected.get("alg") != jose.ALG:
        raise AcmeProblem("badSignatureAlgorithm", "only ES256 is accepted",
                          algorithms=[jose.ALG])
    jws = jose.CompactJws(header=protected, payload={},
                          signing_input=f"{p64}.{b64}".encode("ascii"),
                          signature=signature, raw="")
    return protected, jws, raw_payload


def verify_request(
    body: bytes,
    expected_url: str,
    nonces: NonceStore,
    account_key: Callable[[str], dict[str, str] | None],
    *,
    require_jwk: bool = False,
) -> SignedRequest:
    """Verify a signed ACME request.

    ``account_key(kid)`` returns the account's JWK for a ``kid`` URL, or None.
    """
    protected, jws, raw_payload = parse_flattened(body)
    nonce, url = protected.get("nonce"), protected.get("url")
    if not isinstance(url, str) or url != expected_url:
        raise AcmeProblem("unauthorized", "url in protected header does not match the request", 401)
    if not isinstance(nonce, str) or not nonces.consume(nonce):
        raise AcmeProblem("badNonce", "nonce is missing, unknown or used")
    jwk, kid = protected.get("jwk"), protected.get("kid")
    if (jwk is None) == (kid is None):
        raise AcmeProblem("malformed", "exactly one of jwk and kid is required")
    if require_jwk and jwk is None:
        raise AcmeProblem("malformed", "this request must carry jwk")
    if not require_jwk and kid is None:
        raise AcmeProblem("malformed", "this request must carry the account kid")
    if jwk is not None:
        if not isinstance(jwk, dict):
            raise AcmeProblem("malformed", "jwk must be an object")
        key_jwk = jwk
    else:
        found = account_key(kid) if isinstance(kid, str) else None
        if found is None:
            raise AcmeProblem("accountDoesNotExist", "no such account", 400)
        key_jwk = found
    try:
        key = jose.key_from_jwk(key_jwk)
        jose.verify(jws, key)
    except jose.JoseError as err:
        raise AcmeProblem("malformed", f"signature: {err}", 400) from None
    payload: dict[str, Any] | None
    if raw_payload == b"":
        payload = None
    else:
        try:
            payload = json.loads(raw_payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise AcmeProblem("malformed", "payload is not JSON") from None
        if not isinstance(payload, dict):
            raise AcmeProblem("malformed", "payload must be an object")
    public_jwk = {k: key_jwk[k] for k in ("kty", "crv", "x", "y")}
    return SignedRequest(protected, payload, public_jwk, kid if isinstance(kid, str) else None,
                         nonce, url)
