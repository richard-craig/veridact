"""Issuer configuration.

Everything an operator of this issuer can change lives here. The defaults describe a
staging issuer at Domain tier, which is what Month 1 ships.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCOPES = ("fs:claims:read-status", "fs:quotes:create", "fs:payments:initiate")


@dataclass
class IssuerConfig:
    # Canonical public origin, signed into every URL the issuer publishes.
    # Must be https: verifiers refuse anything else.
    base_url: str = "https://staging.veridact.test"
    data_dir: str = "./issuer-data"
    # "staging" or "production". Delegations name their environment, and an issuer
    # refuses a delegation made for another one.
    environment: str = "staging"
    # The issuer identifier is {base_url}/issuers/{issuer_name} (specification v0.5).
    issuer_name: str = "staging-2026a"
    tiers: tuple[str, ...] = ("domain",)
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    # Scopes each tier may receive. Absent tier: every scope in the taxonomy.
    tier_scopes: dict[str, list[str]] = field(default_factory=dict)
    agent_credential_default_lifetime: int = 8 * 3600
    agent_credential_max_lifetime: int = 24 * 3600
    operator_credential_lifetime: dict[str, int] = field(
        default_factory=lambda: {"domain": 90 * 86400, "organisation": 366 * 86400})
    delegation_max_lifetime: int = 90 * 86400
    # Single payments above this need a second, different approver (spec: Delegation).
    two_person_threshold: str = "1000.00"
    two_person_currency: str = "ZAR"
    # Key epochs: how long the issuer's credential signing key may sign.
    signing_key_lifetime: int = 90 * 86400
    # Staging only: the issuer also signs and serves the trust list with a staging
    # governance key. In production the governance authority does this, with keys
    # held apart from every issuer.
    publish_trust_list: bool = True
    trust_list_lifetime: int = 7 * 86400
    # Known-assistant entries (specification v0.5, section 6) and their lifetime.
    known_assistant_lifetime: int = 90 * 86400
    # Development: host=base_url routes for fetching operator domains (see RoutedFetcher).
    routes: dict[str, str] = field(default_factory=dict)
    # Per-account limits per hour, so a compromised account cannot flood the log.
    orders_per_hour: int = 300
    terms_of_service: str = "https://veridact.net/staging-terms"

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme != "https" or not parts.hostname or parts.path:
            raise ValueError("base_url must be an https origin, such as https://staging.veridact.net")
        if self.environment not in ("staging", "production"):
            raise ValueError("environment must be staging or production")
        if self.environment == "production" and self.publish_trust_list:
            raise ValueError("a production issuer must not sign its own trust list")
        self.tiers = tuple(self.tiers)
        self.scopes = tuple(self.scopes)

    # -- derived -------------------------------------------------------------------

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).netloc

    @property
    def issuer_url(self) -> str:
        """The issuer identifier: the iss of everything it signs."""
        return f"{self.base_url}/issuers/{self.issuer_name}"

    @property
    def agent_hosting_url(self) -> str:
        """Veridact-hosted agents: {agent_hosting_url}/{operator slug}/{agent id}, each a CIMD."""
        return f"{self.base_url}/agents"

    @property
    def trust_list_url(self) -> str:
        return f"{self.base_url}/trust-list.jwt"

    def scopes_for_tier(self, tier: str) -> set[str]:
        allowed = self.tier_scopes.get(tier)
        return set(self.scopes) if allowed is None else set(allowed) & set(self.scopes)

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    # -- loading -------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path, **overrides: Any) -> "IssuerConfig":
        raw = json.loads(Path(path).read_text())
        return cls.from_dict({**raw, **overrides})

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "IssuerConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**raw)
