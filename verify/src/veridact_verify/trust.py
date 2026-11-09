"""The trust registry: a JWS-signed trust list, rooted in governance keys.

The governance keys are the one thing a relying party configures by hand. They are
pinned as JWKs, never resolved, so compromising a DID host or a CDN cannot change
whom the relying party trusts.

The trust list schema here is a v0.2 proposal; see
docs/proposals/0.2-verifier-gaps.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import jose
from .fetch import ArtefactCache, Fetcher

TRUST_LIST_TYP = "trust-list+jwt"
DEFAULT_TRUST_LIST_URL = "https://trust.veridact.net/trust-list.jwt"
DEFAULT_TIER_ORDER = ("domain", "organisation")


class TrustListError(Exception):
    pass


@dataclass(frozen=True)
class IssuerKey:
    kid: str
    not_before: int
    not_after: int


@dataclass(frozen=True)
class AccreditedIssuer:
    did: str
    tiers: frozenset[str]
    credential_types: frozenset[str]
    keys: tuple[IssuerKey, ...]

    def key(self, kid: str) -> IssuerKey | None:
        for k in self.keys:
            if k.kid == kid:
                return k
        return None


@dataclass(frozen=True)
class TrustPolicy:
    tier_order: tuple[str, ...] = DEFAULT_TIER_ORDER
    agent_credential_max_lifetime: int = 24 * 3600
    presentation_max_lifetime: int = 120
    operator_credential_max_lifetime: dict[str, int] = field(
        default_factory=lambda: {"domain": 90 * 86400, "organisation": 366 * 86400}
    )
    delegation_max_lifetime: int = 90 * 86400

    def tier_rank(self, tier: str) -> int:
        try:
            return self.tier_order.index(tier)
        except ValueError:
            return -1


@dataclass(frozen=True)
class TrustList:
    version: str
    issued_at: int
    expires_at: int
    issuers: dict[str, AccreditedIssuer]
    policy: TrustPolicy
    scopes: frozenset[str]

    def issuer(self, did: str) -> AccreditedIssuer | None:
        return self.issuers.get(did)


def _int(obj: dict, name: str) -> int:
    value = obj.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TrustListError(f"{name} must be an integer")
    return value


def parse_trust_list(payload: dict[str, Any]) -> TrustList:
    issuers: dict[str, AccreditedIssuer] = {}
    for entry in payload.get("issuers", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise TrustListError("issuer entry needs an id")
        keys = tuple(
            IssuerKey(k["kid"], _int(k, "notBefore"), _int(k, "notAfter"))
            for k in entry.get("keys", [])
            if isinstance(k, dict) and isinstance(k.get("kid"), str)
        )
        issuers[entry["id"]] = AccreditedIssuer(
            did=entry["id"],
            tiers=frozenset(entry.get("tiers", [])),
            credential_types=frozenset(entry.get("credentialTypes", [])),
            keys=keys,
        )
    raw_policy = payload.get("policy", {}) or {}
    defaults = TrustPolicy()
    policy = TrustPolicy(
        tier_order=tuple(raw_policy.get("tierOrder", defaults.tier_order)),
        agent_credential_max_lifetime=int(
            raw_policy.get("agentCredentialMaxLifetime", defaults.agent_credential_max_lifetime)
        ),
        presentation_max_lifetime=int(
            raw_policy.get("presentationMaxLifetime", defaults.presentation_max_lifetime)
        ),
        operator_credential_max_lifetime=dict(
            raw_policy.get(
                "operatorCredentialMaxLifetime", defaults.operator_credential_max_lifetime
            )
        ),
        delegation_max_lifetime=int(
            raw_policy.get("delegationMaxLifetime", defaults.delegation_max_lifetime)
        ),
    )
    return TrustList(
        version=str(payload.get("version", "")),
        issued_at=_int(payload, "iat"),
        expires_at=_int(payload, "exp"),
        issuers=issuers,
        policy=policy,
        scopes=frozenset(payload.get("scopes", [])),
    )


def verify_trust_list(token: str, governance_keys: dict[str, dict]) -> TrustList:
    """Verify a trust list JWS against pinned governance JWKs (kid -> JWK)."""
    try:
        jws = jose.parse(token.strip())
    except jose.JoseError as err:
        raise TrustListError(f"malformed trust list: {err}") from err
    if jws.typ != TRUST_LIST_TYP:
        raise TrustListError("trust list typ must be " + TRUST_LIST_TYP)
    jwk = governance_keys.get(jws.kid or "")
    if jwk is None:
        raise TrustListError("trust list signed by an unknown governance key")
    try:
        jose.verify(jws, jose.key_from_jwk(jwk))
    except jose.JoseError as err:
        raise TrustListError(f"trust list signature: {err}") from err
    return parse_trust_list(jws.payload)


class TrustRegistry:
    """Loads, verifies and caches the trust list (default: one hour)."""

    def __init__(
        self,
        fetcher: Fetcher,
        cache: ArtefactCache,
        governance_keys: dict[str, dict],
        *,
        url: str = DEFAULT_TRUST_LIST_URL,
        ttl: float = 3600.0,
    ):
        if not governance_keys:
            raise ValueError("at least one pinned governance key is required")
        self.fetcher = fetcher
        self.cache = cache
        self.governance_keys = dict(governance_keys)
        self.url = url
        self.ttl = ttl
        self._newest_iat = 0

    async def _load(self) -> TrustList:
        body = await self.fetcher.fetch(self.url)
        trust_list = verify_trust_list(body.decode("ascii", errors="strict"), self.governance_keys)
        # Refuse rollback to an older, still-signed list (for example from a stale mirror).
        if trust_list.issued_at < self._newest_iat:
            raise TrustListError("trust list is older than one already seen")
        self._newest_iat = trust_list.issued_at
        return trust_list

    async def current(self) -> TrustList:
        # A stale trust list may be used until its own exp, never beyond.
        cached = await self.cache.get(
            "trust:" + self.url, self._load, ttl=self.ttl, max_stale=float("inf")
        )
        trust_list = cached.value
        if self.cache.clock() >= trust_list.expires_at:
            raise TrustListError("trust list has expired and cannot be refreshed")
        return trust_list
