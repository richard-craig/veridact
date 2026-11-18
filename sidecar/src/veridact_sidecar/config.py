"""Relying-party configuration shared by the sidecar and the sandbox."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from veridact_verify import (
    FallbackFetcher,
    HttpFetcher,
    MirrorFetcher,
    Payment,
    RelyingPartyPolicy,
    Request,
    RoutedFetcher,
    Risk,
    Verifier,
)
from veridact_verify.fetch import Fetcher
from veridact_verify.trust import DEFAULT_TRUST_LIST_URL


class ConfigError(ValueError):
    pass


@dataclass
class VerifierConfig:
    audience: str
    # The trust anchor: governance key id -> public JWK. Pin these like a root CA.
    governance_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    trust_list_url: str = DEFAULT_TRUST_LIST_URL
    min_tier: str = "domain"
    allowed_operators: list[str] | None = None
    allowed_scopes: list[str] | None = None
    require_operator_status: bool = True
    mirror_url: str | None = None
    # Development only: host=base_url routes (see RoutedFetcher).
    routes: dict[str, str] = field(default_factory=dict)
    did_ttl: float = 300.0
    status_ttl: float = 300.0
    trust_ttl: float = 3600.0

    def __post_init__(self) -> None:
        if not self.audience.startswith("https://"):
            raise ConfigError("audience must be your API's https origin")
        if not self.governance_keys:
            raise ConfigError("governance_keys is required: it is the trust anchor")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VerifierConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(f"unknown config keys: {sorted(unknown)}")
        return cls(**raw)

    @classmethod
    def from_file(cls, path: str | Path) -> "VerifierConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))

    @classmethod
    def from_env(cls, prefix: str = "VERIDACT_") -> "VerifierConfig":
        """VERIDACT_CONFIG=path, or VERIDACT_AUDIENCE + VERIDACT_GOVERNANCE_KEYS (JSON) + …"""
        path = os.environ.get(prefix + "CONFIG")
        if path:
            return cls.from_file(path)
        raw: dict[str, Any] = {"audience": os.environ.get(prefix + "AUDIENCE", "")}
        keys = os.environ.get(prefix + "GOVERNANCE_KEYS")
        raw["governance_keys"] = json.loads(keys) if keys else {}
        for name in ("trust_list_url", "min_tier", "mirror_url"):
            value = os.environ.get(prefix + name.upper())
            if value:
                raw[name] = value
        routes = os.environ.get(prefix + "ROUTES")
        if routes:
            raw["routes"] = dict(r.split("=", 1) for r in routes.split(","))
        return cls.from_dict(raw)

    def fetcher(self) -> Fetcher:
        origin: Fetcher = RoutedFetcher(self.routes) if self.routes else HttpFetcher()
        if self.mirror_url:
            return FallbackFetcher([MirrorFetcher(self.mirror_url, HttpFetcher()), origin])
        return origin

    def build(self, **kwargs: Any) -> Verifier:
        policy = RelyingPartyPolicy(
            audience=self.audience,
            min_tier=self.min_tier,
            allowed_operators=frozenset(self.allowed_operators) if self.allowed_operators else None,
            allowed_scopes=frozenset(self.allowed_scopes) if self.allowed_scopes else None,
            require_operator_status=self.require_operator_status,
        )
        kwargs.setdefault("fetcher", self.fetcher())
        return Verifier(policy, governance_keys=self.governance_keys,
                        trust_list_url=self.trust_list_url, did_ttl=self.did_ttl,
                        status_ttl=self.status_ttl, trust_ttl=self.trust_ttl, **kwargs)


def parse_request(raw: dict[str, Any] | None) -> Request:
    """A verification Request from JSON: {scopes, risk, minTier, payment}."""
    raw = raw or {}
    scopes = raw.get("scopes") or []
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise ConfigError("scopes must be a list of strings")
    try:
        risk = Risk(raw.get("risk", "medium"))
    except ValueError:
        raise ConfigError("risk must be low, medium or high") from None
    payment = None
    if raw.get("payment") is not None:
        p = raw["payment"]
        if not isinstance(p, dict):
            raise ConfigError("payment must be an object")
        try:
            payment = Payment(amount=Decimal(str(p["amount"])), currency=str(p["currency"]),
                              spent_today=Decimal(str(p.get("spentToday", "0"))))
        except (KeyError, InvalidOperation):
            raise ConfigError("payment needs amount, currency and optional spentToday as decimals") from None
    min_tier = raw.get("minTier")
    if min_tier is not None and not isinstance(min_tier, str):
        raise ConfigError("minTier must be a string")
    return Request(scopes=frozenset(scopes), risk=risk, payment=payment, min_tier=min_tier)


def decision_body(decision, *, include_log: bool = True) -> dict[str, Any]:
    """Everything a relying party's own code needs from a decision."""
    body: dict[str, Any] = {
        **decision.public(),
        "allowed": decision.allowed,
        "agent": decision.agent,
        "operator": decision.operator,
        "operatorDomains": decision.operator_domains,
        "tier": decision.tier,
        "accountableRole": decision.accountable_role,
        "scopesGranted": decision.scopes_granted,
        "agentKeyId": decision.agent_key_id,
        "agentCredentialExpires": decision.agent_credential_expires,
        "flags": decision.flags,
    }
    if "intent" in decision.context:
        body["intent"] = decision.context["intent"]
    if include_log:
        body["log"] = decision.log_record()
    return body
