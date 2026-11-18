"""Bridge configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from veridact_sidecar import VerifierConfig


@dataclass
class KeycloakConfig:
    # Keycloak's base URL as the bridge reaches it, e.g. https://sso.bank.example (or http://keycloak:8080)
    url: str
    realm: str
    # The confidential client the bridge uses for the JWT Authorization Grant.
    client_id: str
    client_secret: str
    # Alias of the "JWT Authorization Grant" identity provider whose issuer is this bridge.
    idp_alias: str = "veridact"
    # A client whose service account may manage users (realm-management: manage-users, view-users).
    # Leave unset to require agents to be provisioned in Keycloak beforehand.
    admin_client_id: str | None = None
    admin_client_secret: str | None = None
    # Keycloak's public token endpoint as agents must sign it in DPoP proofs (htu). Defaults to the
    # token endpoint under ``url``; set it when Keycloak's frontend URL differs.
    public_token_endpoint: str | None = None

    @property
    def realm_url(self) -> str:
        return f"{self.url.rstrip('/')}/realms/{self.realm}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.realm_url}/protocol/openid-connect/token"

    @property
    def dpop_htu(self) -> str:
        return self.public_token_endpoint or self.token_endpoint

    @property
    def admin_url(self) -> str:
        return f"{self.url.rstrip('/')}/admin/realms/{self.realm}"


@dataclass
class BridgeConfig:
    # The bridge's own https origin. It is the iss of the assertions it signs (configure the same
    # value as the Keycloak identity provider's Issuer) and the aud agents sign presentations for.
    base_url: str
    verifier: VerifierConfig
    keycloak: KeycloakConfig
    # Keycloak's issuer for this realm, as Keycloak names itself (assertion aud). Defaults to
    # keycloak.realm_url; set it when Keycloak's frontend URL differs from keycloak.url.
    keycloak_issuer: str | None = None
    assertion_lifetime: int = 60
    # Bind every access token to the agent's Veridact key with DPoP (spec: pattern A).
    require_dpop: bool = True
    # Create the agent's Keycloak user on its first verified presentation.
    provision_agents: bool = True
    data_dir: str = "./bridge-data"
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme != "https" or parts.path:
            raise ValueError("base_url must be the bridge's https origin")
        if self.verifier.audience != self.base_url:
            raise ValueError("verifier.audience must equal base_url: agents sign presentations for it")
        if not 10 <= self.assertion_lifetime <= 300:
            raise ValueError("assertion_lifetime must be 10 to 300 seconds (Keycloak caps it at 5 minutes)")

    @property
    def assertion_audience(self) -> str:
        return self.keycloak_issuer or self.keycloak.realm_url

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BridgeConfig":
        raw = dict(raw)
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        verifier = dict(raw.pop("verifier"))
        verifier.setdefault("audience", str(raw.get("base_url", "")).rstrip("/"))
        return cls(verifier=VerifierConfig.from_dict(verifier),
                   keycloak=KeycloakConfig(**raw.pop("keycloak")), **raw)

    @classmethod
    def from_file(cls, path: str | Path) -> "BridgeConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))
