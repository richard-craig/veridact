"""SD-JWT (RFC 9901) and SD-JWT VC, as Veridact uses them.

    <issuer-signed JWT>~<disclosure>~...~<disclosure>~              an SD-JWT
    <issuer-signed JWT>~<disclosure>~...~<disclosure>~<KB-JWT>      an SD-JWT+KB (a presentation)

A disclosure is base64url(JSON [salt, name, value]) for an object property, or
base64url(JSON [salt, value]) for an array element. The issuer-signed JWT carries the
SHA-256 digest of each disclosure in an ``_sd`` array (or ``{"...": digest}`` in an
array), so a holder can leave a disclosure out without breaking the signature.

Everything is ES256, like the rest of Veridact (see ``jose``). This module is small on
purpose: it implements exactly the parts of RFC 9901 Veridact needs, and refuses
anything else (other ``_sd_alg`` values, duplicate or unreferenced disclosures,
disclosures that would overwrite a signed claim).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

from . import jose

SD_ALG = "sha-256"
SD_JWT_TYP = "dc+sd-jwt"
KB_TYP = "kb+jwt"
MAX_LENGTH = 128 * 1024
_RESERVED = {"_sd", "_sd_alg", "..."}
# Claims that must never be selectively disclosable (RFC 9901 and SD-JWT VC).
NEVER_DISCLOSABLE = {"iss", "vct", "iat", "nbf", "exp", "cnf", "status", "sub", "jti", "_sd", "_sd_alg"}


class SdJwtError(ValueError):
    """Malformed or inconsistent SD-JWT."""


def _digest(text: str) -> str:
    return jose.b64url_encode(hashlib.sha256(text.encode("ascii")).digest())


@dataclass(frozen=True)
class Disclosure:
    raw: str  # the base64url string, exactly as it travels
    salt: str
    name: str | None  # None for an array element
    value: Any

    @property
    def digest(self) -> str:
        return _digest(self.raw)

    @classmethod
    def create(cls, name: str | None, value: Any, *, salt: str | None = None) -> "Disclosure":
        salt = salt or jose.b64url_encode(secrets.token_bytes(16))
        array = [salt, value] if name is None else [salt, name, value]
        raw = jose.b64url_encode(json.dumps(array, separators=(",", ":"), ensure_ascii=False).encode())
        return cls(raw, salt, name, value)

    @classmethod
    def parse(cls, raw: str) -> "Disclosure":
        try:
            array = json.loads(jose.b64url_decode(raw))
        except (jose.JoseError, json.JSONDecodeError, UnicodeDecodeError) as err:
            raise SdJwtError("disclosure is not base64url JSON") from err
        if not isinstance(array, list) or len(array) not in (2, 3) or not isinstance(array[0], str):
            raise SdJwtError("disclosure must be [salt, name, value] or [salt, value]")
        if len(array) == 3:
            name = array[1]
            if not isinstance(name, str) or name in _RESERVED:
                raise SdJwtError("disclosure claim name is missing or reserved")
            return cls(raw, array[0], name, array[2])
        return cls(raw, array[0], None, array[1])


# -- issuing ---------------------------------------------------------------------------


def issue(header: dict[str, Any], payload: dict[str, Any], disclosable: dict[str, Any],
          sign, *, decoys: int = 0) -> str:
    """Sign an SD-JWT. ``disclosable`` holds the top-level claims to make selectively
    disclosable; ``sign(header, payload) -> compact JWS`` does the signing (a Signer, an
    HSM or a test key). Returns the SD-JWT with every disclosure attached."""
    clash = set(disclosable) & (set(payload) | NEVER_DISCLOSABLE)
    if clash:
        raise SdJwtError(f"claims cannot be both plain and disclosable: {sorted(clash)}")
    disclosures = [Disclosure.create(name, value) for name, value in disclosable.items()]
    digests = [d.digest for d in disclosures]
    digests += [_digest(jose.b64url_encode(secrets.token_bytes(24))) for _ in range(decoys)]
    body = dict(payload)
    if digests:
        body["_sd"] = sorted(digests)  # sorted, so order reveals nothing
        body["_sd_alg"] = SD_ALG
    jwt = sign({"typ": SD_JWT_TYP, **header}, body)
    return serialize(jwt, [d.raw for d in disclosures])


def serialize(jwt: str, disclosures: Iterable[str], kb_jwt: str | None = None) -> str:
    parts = [jwt, *disclosures]
    return "~".join(parts) + "~" + (kb_jwt or "")


# -- parsing ----------------------------------------------------------------------------


@dataclass(frozen=True)
class SdJwt:
    """A parsed, not yet verified, SD-JWT (with or without a KB-JWT)."""

    jws: jose.CompactJws
    disclosures: tuple[Disclosure, ...]
    kb_jwt: str | None

    @property
    def presented(self) -> str:
        """The SD-JWT without the KB-JWT: the input to ``sd_hash``."""
        return serialize(self.jws.raw, [d.raw for d in self.disclosures])

    @property
    def sd_hash(self) -> str:
        return _digest(self.presented)

    def claims(self) -> dict[str, Any]:
        """The payload with every presented disclosure applied (RFC 9901 section 7.1)."""
        return resolve(self.jws.payload, self.disclosures)

    def disclosed_names(self) -> set[str]:
        return {d.name for d in self.disclosures if d.name is not None}

    def select(self, names: Iterable[str]) -> "SdJwt":
        """Keep only the named top-level disclosures (what a holder sends)."""
        keep = set(names)
        return SdJwt(self.jws, tuple(d for d in self.disclosures if d.name in keep), None)


def parse(text: str) -> SdJwt:
    if not isinstance(text, str) or len(text) > MAX_LENGTH:
        raise SdJwtError("SD-JWT missing or too long")
    if "~" not in text:
        raise SdJwtError("not an SD-JWT: no ~ separator")
    parts = text.split("~")
    jwt, middle, last = parts[0], parts[1:-1], parts[-1]
    try:
        jws = jose.parse(jwt, max_length=MAX_LENGTH)
    except jose.JoseError as err:
        raise SdJwtError(f"issuer-signed JWT: {err}") from err
    if any(not d for d in middle):
        raise SdJwtError("empty disclosure")
    disclosures = tuple(Disclosure.parse(d) for d in middle)
    if len({d.raw for d in disclosures}) != len(disclosures):
        raise SdJwtError("a disclosure appears twice")
    return SdJwt(jws, disclosures, last or None)


def resolve(payload: dict[str, Any], disclosures: Iterable[Disclosure]) -> dict[str, Any]:
    alg = payload.get("_sd_alg", SD_ALG)
    if alg != SD_ALG:
        raise SdJwtError(f"_sd_alg must be {SD_ALG}")
    by_digest: dict[str, Disclosure] = {}
    for d in disclosures:
        if d.digest in by_digest:
            raise SdJwtError("two disclosures with one digest")
        by_digest[d.digest] = d
    used: set[str] = set()
    seen_digests: set[str] = set()

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                if key in ("_sd", "_sd_alg"):
                    continue
                out[key] = walk(value)
            sd = node.get("_sd", [])
            if not isinstance(sd, list) or not all(isinstance(x, str) for x in sd):
                raise SdJwtError("_sd must be an array of digests")
            for digest in sd:
                if digest in seen_digests:
                    raise SdJwtError("a digest appears twice")
                seen_digests.add(digest)
                disclosure = by_digest.get(digest)
                if disclosure is None:
                    continue  # withheld, or a decoy
                if disclosure.name is None:
                    raise SdJwtError("array-element disclosure referenced from _sd")
                if disclosure.name in out:
                    raise SdJwtError(f"disclosure would overwrite claim {disclosure.name!r}")
                used.add(digest)
                out[disclosure.name] = walk(disclosure.value)
            return out
        if isinstance(node, list):
            items = []
            for item in node:
                if isinstance(item, dict) and set(item) == {"..."}:
                    digest = item["..."]
                    if not isinstance(digest, str) or digest in seen_digests:
                        raise SdJwtError("bad or repeated array digest")
                    seen_digests.add(digest)
                    disclosure = by_digest.get(digest)
                    if disclosure is None:
                        continue
                    if disclosure.name is not None:
                        raise SdJwtError("object disclosure referenced from an array")
                    used.add(digest)
                    items.append(walk(disclosure.value))
                else:
                    items.append(walk(item))
            return items
        return node

    claims = walk(payload)
    unreferenced = set(by_digest) - used
    if unreferenced:
        raise SdJwtError("a disclosure is not referenced by the signed payload")
    return claims


# -- key binding --------------------------------------------------------------------------


def key_binding_jwt(sd_jwt: SdJwt | str, *, aud: str, nonce: str, iat: int, sign,
                    extra: dict[str, Any] | None = None) -> str:
    """Make the KB-JWT for a presentation and return the whole SD-JWT+KB.
    ``sign(header, payload) -> compact JWS`` signs with the holder's ``cnf`` key."""
    parsed = parse(sd_jwt) if isinstance(sd_jwt, str) else sd_jwt
    payload = {"aud": aud, "nonce": nonce, "iat": iat, "sd_hash": parsed.sd_hash, **(extra or {})}
    kb = sign({"typ": KB_TYP}, payload)
    return serialize(parsed.jws.raw, [d.raw for d in parsed.disclosures], kb)


def present(sd_jwt: str, *, disclose: Iterable[str] | None, aud: str, nonce: str, iat: int,
            sign, extra: dict[str, Any] | None = None) -> str:
    """Select disclosures (``None`` keeps them all) and add the KB-JWT."""
    parsed = parse(sd_jwt)
    if disclose is not None:
        parsed = parsed.select(disclose)
    return key_binding_jwt(parsed, aud=aud, nonce=nonce, iat=iat, sign=sign, extra=extra)


def key_signer(key):
    """A ``sign`` callable for a private key held in memory."""
    return lambda header, payload: jose.sign(header, payload, key)
