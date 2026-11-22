"""HTTPS identifiers and the public documents behind them (specification v0.5, Identifiers).

    issuer     https://veridact.net/issuers/org-2026b
               keys: JWT VC Issuer Metadata at https://veridact.net/.well-known/jwt-vc-issuer/issuers/org-2026b
    operator   https://operator.example
               keys: https://operator.example/.well-known/veridact-operator.json
    agent      https://operator.example/agents/a7f3k2   (a Client ID Metadata Document)
               keys: the document's jwks

Credential types are named by ``vct`` URIs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import jose
from .fetch import ArtefactCache, Fetcher, FetchError

VCT_BASE = "https://veridact.net/vct/"
VCT_OPERATOR = VCT_BASE + "operator/v1"
VCT_APPROVER = VCT_BASE + "approver/v1"
VCT_DELEGATION = VCT_BASE + "delegation/v1"
VCT_AGENT = VCT_BASE + "agent/v1"
VCT_KNOWN_ASSISTANT = VCT_BASE + "known-assistant/v1"
CLIENT_ATTESTATION_TYP = "oauth-client-attestation+jwt"
ISSUER_METADATA_WELL_KNOWN = "/.well-known/jwt-vc-issuer"
OPERATOR_METADATA_PATH = "/.well-known/veridact-operator.json"
AUTH_METHOD_ATTESTATION = "attest_jwt_client_auth_dpop"
_HOST = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$")


class IdentifierError(ValueError):
    pass


class MetadataUnavailable(IdentifierError):
    """The document could not be fetched (as opposed to fetched and found invalid)."""


def check_https_url(url: Any, *, what: str = "identifier", allow_path: bool = True) -> str:
    """An identifier is an https URL with a lowercase host, no query, fragment or user info."""
    if not isinstance(url, str) or len(url) > 2048:
        raise IdentifierError(f"{what} must be an https URL")
    parts = urlsplit(url)
    if (parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment
            or "@" in parts.netloc or not _HOST.match(parts.netloc)):
        raise IdentifierError(f"{what} must be https://host[/path], lowercase, no query or fragment")
    if not allow_path and parts.path not in ("", "/"):
        raise IdentifierError(f"{what} must be an origin, with no path")
    if parts.path.endswith("/") and parts.path != "/":
        raise IdentifierError(f"{what} must not end with /")
    return url.rstrip("/") if not allow_path else url


def host_of(url: str) -> str:
    return urlsplit(url).netloc


def issuer_metadata_url(issuer: str) -> str:
    """draft-ietf-oauth-sd-jwt-vc: the well-known segment goes between host and path."""
    parts = urlsplit(issuer)
    return f"https://{parts.netloc}{ISSUER_METADATA_WELL_KNOWN}{parts.path.rstrip('/')}"


def operator_metadata_url(operator: str) -> str:
    return f"https://{host_of(operator)}{OPERATOR_METADATA_PATH}"


def operator_url(domain: str) -> str:
    return f"https://{domain}"


def jwks_keys(raw: Any, *, what: str) -> dict[str, dict[str, Any]]:
    """Read ``{"keys": [...]}`` into thumbprint -> public JWK (the kid, if any, is kept)."""
    keys = raw.get("keys") if isinstance(raw, dict) else None
    if not isinstance(keys, list) or not keys:
        raise IdentifierError(f"{what} jwks must hold keys")
    out: dict[str, dict[str, Any]] = {}
    for jwk in keys:
        if not isinstance(jwk, dict):
            raise IdentifierError(f"{what} jwks entries must be objects")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue  # other key types are not Veridact's concern
        try:
            jose.key_from_jwk({k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y")})
            out[jose.jwk_thumbprint(jwk)] = jwk
        except jose.JoseError as err:
            raise IdentifierError(f"{what}: {err}") from None
    if not out:
        raise IdentifierError(f"{what} has no P-256 keys")
    return out


def public_jwk(jwk: dict[str, Any]) -> dict[str, str]:
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}


# -- JWT VC Issuer Metadata ------------------------------------------------------------------


@dataclass(frozen=True)
class IssuerMetadata:
    issuer: str
    keys: dict[str, dict[str, Any]]  # kid -> public JWK

    def key(self, kid: str):
        jwk = self.keys.get(kid)
        if jwk is None:
            raise IdentifierError(f"kid {kid!r} is not in the issuer's metadata")
        return jose.key_from_jwk(public_jwk(jwk))


def parse_issuer_metadata(issuer: str, body: bytes) -> IssuerMetadata:
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise IdentifierError("issuer metadata is not JSON") from err
    if not isinstance(doc, dict) or doc.get("issuer") != issuer:
        raise IdentifierError("issuer metadata names a different issuer")
    jwks = doc.get("jwks")
    if not isinstance(jwks, dict):
        raise IdentifierError("issuer metadata must embed jwks (jwks_uri is not accepted)")
    by_thumb = jwks_keys(jwks, what="issuer metadata")
    by_kid = {}
    for jwk in by_thumb.values():
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            raise IdentifierError("every issuer key needs a kid")
        by_kid[kid] = jwk
    return IssuerMetadata(issuer, by_kid)


def issuer_metadata_document(issuer: str, keys: dict[str, Any]) -> dict[str, Any]:
    """kid -> public key (cryptography) or JWK, as the issuer publishes it."""
    jwks = []
    for kid, key in keys.items():
        jwk = dict(key) if isinstance(key, dict) else jose.key_to_jwk(key)
        jwks.append({**public_jwk(jwk), "kid": kid, "use": "sig", "alg": "ES256"})
    return {"issuer": issuer, "jwks": {"keys": jwks}}


class IssuerMetadataCache:
    """Fetches and caches JWT VC Issuer Metadata, with bounded stale use."""

    def __init__(self, fetcher: Fetcher, cache: ArtefactCache, *, ttl: float = 300.0,
                 max_stale: float = 4 * 3600.0):
        self.fetcher = fetcher
        self.cache = cache
        self.ttl = ttl
        self.max_stale = max_stale

    async def get(self, issuer: str) -> IssuerMetadata:
        url = issuer_metadata_url(issuer)

        async def load() -> IssuerMetadata:
            try:
                body = await self.fetcher.fetch(url)
            except FetchError as err:
                raise MetadataUnavailable(str(err)) from err
            return parse_issuer_metadata(issuer, body)

        return (await self.cache.get("issuer:" + url, load, ttl=self.ttl,
                                     max_stale=self.max_stale)).value


# -- Client ID Metadata Documents (agents) -----------------------------------------------------


def client_metadata_document(client_id: str, keys: list[dict[str, Any]], *,
                             name: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """An agent's CIMD (draft-ietf-oauth-client-id-metadata-document)."""
    doc: dict[str, Any] = {
        "client_id": client_id,
        "jwks": {"keys": [{**public_jwk(k), "kid": jose.jwk_thumbprint(k), "use": "sig", "alg": "ES256"}
                          for k in keys]},
        "token_endpoint_auth_methods_supported": [AUTH_METHOD_ATTESTATION, "private_key_jwt"],
        "token_endpoint_auth_method": AUTH_METHOD_ATTESTATION,
        "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "dpop_bound_access_tokens": True,
        "software_id": "veridact-agent",
    }
    if name:
        doc["client_name"] = name
    doc.update(extra or {})
    return doc


def parse_client_metadata(client_id: str, body: bytes) -> dict[str, dict[str, Any]]:
    """Check a CIMD and return its keys (thumbprint -> JWK). ``client_id`` must equal the
    URL it was fetched from, compared as a plain string."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise IdentifierError("client metadata is not JSON") from err
    if not isinstance(doc, dict) or doc.get("client_id") != client_id:
        raise IdentifierError("client_id in the document does not equal its URL")
    return jwks_keys(doc.get("jwks"), what="client metadata")


# -- operators -----------------------------------------------------------------------------------


def operator_metadata_document(operator: str, keys: list[dict[str, Any]],
                               agents: list[str] | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "operator": operator,
        "jwks": {"keys": [{**public_jwk(k), "kid": jose.jwk_thumbprint(k), "use": "sig", "alg": "ES256"}
                          for k in keys]},
    }
    if agents:
        doc["agents"] = agents
    return doc


def parse_operator_metadata(operator: str, body: bytes) -> dict[str, dict[str, Any]]:
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise IdentifierError("operator metadata is not JSON") from err
    if not isinstance(doc, dict) or doc.get("operator") != operator:
        raise IdentifierError("operator metadata names a different operator")
    return jwks_keys(doc.get("jwks"), what="operator metadata")
