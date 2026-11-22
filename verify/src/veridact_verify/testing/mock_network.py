"""A mock Veridact network (specification v0.5): governance, an issuer, an operator and an agent.

Everything a relying party would read is published into a StaticFetcher, at the URLs
the real artefacts would have. Every builder accepts ``mutate`` hooks so tests and
conformance vectors can produce precisely broken inputs.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .. import jose, sdjwt, status
from ..fetch import StaticFetcher
from ..identifiers import (
    CLIENT_ATTESTATION_TYP,
    VCT_AGENT,
    VCT_KNOWN_ASSISTANT,
    VCT_OPERATOR,
    issuer_metadata_document,
    issuer_metadata_url,
)

# Fixed clock for reproducible vectors: 2026-11-09T08:00:00Z
NOW = 1794211200

AUDIENCE = "https://api.bank.example"
TRUST_LIST_URL = "https://trust.veridact.example/trust-list.jwt"
GOV_KID = "gov-test-2026a"
SCOPES = ["fs:claims:read-status", "fs:quotes:create", "fs:payments:initiate"]
CLAUDE_CIMD = "https://claude.ai/oauth/claude-client-metadata.json"

Mutate = Callable[[dict], None] | None


@dataclass
class Issuer:
    id: str
    kid: str
    key: ec.EllipticCurvePrivateKey

    @property
    def jkt(self) -> str:
        return jose.jwk_thumbprint(jose.key_to_jwk(self.key.public_key()))

    def sign(self, header: dict, payload: dict) -> str:
        return jose.sign({**header, "kid": self.kid}, payload, self.key)


@dataclass
class Holder:
    id: str
    key: ec.EllipticCurvePrivateKey

    @property
    def jwk(self) -> dict[str, str]:
        return jose.key_to_jwk(self.key.public_key())

    @property
    def jkt(self) -> str:
        return jose.jwk_thumbprint(self.jwk)


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@dataclass
class MockNetwork:
    fetcher: StaticFetcher = field(default_factory=StaticFetcher)
    tier: str = "organisation"

    def __post_init__(self) -> None:
        self.governance_key = _key()
        self.issuer = Issuer("https://veridact.example/issuers/org-2026b", "org-2026b-3", _key())
        self.rogue_issuer = Issuer("https://rogue.example/issuers/x", "x-1", _key())
        self.operator = Holder("https://operator.example", _key())
        self.agent = Holder("https://operator.example/agents/a7f3k2", _key())
        self.operator_credential_id = f"urn:uuid:{uuid.UUID(int=1)}"
        self.agent_status_url = "https://status.veridact.example/org/agents/7"
        self.operator_status_url = "https://status.veridact.example/org/operators/2"
        self.assistant_status_url = "https://status.veridact.example/org/assistants/1"
        self.status_values: dict[str, dict[int, int]] = {
            self.agent_status_url: {}, self.operator_status_url: {}, self.assistant_status_url: {}}
        for issuer in (self.issuer, self.rogue_issuer):
            self.publish_issuer_metadata(issuer)
        self.publish_trust_list()
        for url in self.status_values:
            self.publish_status_list(url)

    # -- governance and issuers ---------------------------------------------------------

    @property
    def governance_keys(self) -> dict[str, dict]:
        return {GOV_KID: jose.key_to_jwk(self.governance_key.public_key())}

    def publish_issuer_metadata(self, issuer: Issuer, mutate: Mutate = None) -> None:
        doc = issuer_metadata_document(issuer.id, {issuer.kid: issuer.key.public_key()})
        if mutate:
            mutate(doc)
        import json
        self.fetcher.put(issuer_metadata_url(issuer.id), json.dumps(doc))

    def trust_list_payload(self) -> dict[str, Any]:
        return {
            "iss": "https://trust.veridact.example",
            "version": "2026.11.1",
            "iat": NOW - 86400,
            "exp": NOW + 7 * 86400,
            "issuers": [
                {
                    "id": self.issuer.id,
                    "tiers": ["domain", "organisation"],
                    "vcts": [VCT_AGENT, VCT_OPERATOR, VCT_KNOWN_ASSISTANT],
                    "keys": [{"kid": self.issuer.kid, "jkt": self.issuer.jkt,
                              "notBefore": NOW - 60 * 86400, "notAfter": NOW + 30 * 86400}],
                }
            ],
            "scopes": SCOPES,
            "policy": {
                "tierOrder": ["domain", "organisation"],
                "agentCredentialMaxLifetime": 86400,
                "presentationMaxLifetime": 120,
                "operatorCredentialMaxLifetime": {"domain": 90 * 86400, "organisation": 366 * 86400},
                "knownAssistantMaxLifetime": 90 * 86400,
            },
        }

    def publish_trust_list(self, mutate: Mutate = None, *, key=None) -> str:
        payload = self.trust_list_payload()
        if mutate:
            mutate(payload)
        token = jose.sign({"typ": "trust-list+jwt", "kid": GOV_KID}, payload, key or self.governance_key)
        self.fetcher.put(TRUST_LIST_URL, token)
        return token

    # -- status lists ---------------------------------------------------------------------

    def publish_status_list(self, url: str, *, signer: Issuer | None = None,
                            mutate: Mutate = None, iat: int = NOW - 60) -> str:
        entries = status.empty()
        for index, value in self.status_values[url].items():
            status.put(entries, index, value)
        signer = signer or self.issuer
        payload = status.status_list_payload(url, signer.id, bytes(entries), iat)
        if mutate:
            mutate(payload)
        token = signer.sign({"typ": status.STATUS_LIST_TYP}, payload)
        self.fetcher.put(url, token)
        return token

    def set_status(self, url: str, index: int, value: int = status.INVALID) -> None:
        self.status_values[url][index] = value
        self.publish_status_list(url)

    def revoke(self, url: str, index: int) -> None:
        self.set_status(url, index, status.INVALID)

    # -- credentials ----------------------------------------------------------------------

    def agent_claims(self, *, valid_from: int, lifetime: int, status_index: int,
                     scopes: list[str] | None, limits: dict | None) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "iss": self.issuer.id,
            "vct": VCT_AGENT,
            "jti": f"urn:uuid:{uuid.UUID(int=status_index + 1000)}",
            "sub": self.agent.id,
            "iat": valid_from, "nbf": valid_from, "exp": valid_from + lifetime,
            "operator": self.operator.id,
            "operator_credential": self.operator_credential_id,
            "operator_status": status.ref_claim(17, self.operator_status_url),
            "tier": self.tier,
            "scopes": scopes if scopes is not None else ["fs:claims:read-status", "fs:quotes:create"],
            "accountable_role": "Head of Digital Claims",
            "cnf": {"jwk": self.agent.jwk},
            "cnf_event": "veridact-log-2026/000000456",
            "status": status.ref_claim(status_index, self.agent_status_url),
        }
        if limits is not None:
            claims["limits"] = limits
        return claims

    def agent_credential(self, *, mutate: Mutate = None, signer: Issuer | None = None,
                         header: dict | None = None, valid_from: int = NOW - 3600,
                         lifetime: int = 8 * 3600, status_index: int = 48213,
                         scopes: list[str] | None = None, limits: dict | None = None,
                         disclosable: dict | None = None) -> str:
        """The Agent Credential as the issuer hands it over: an SD-JWT with every disclosure."""
        signer = signer or self.issuer
        claims = self.agent_claims(valid_from=valid_from, lifetime=lifetime,
                                   status_index=status_index, scopes=scopes, limits=limits)
        claims["iss"] = signer.id
        if disclosable is None:
            disclosable = {"operator_legal_name": "Operator Example (Pty) Ltd",
                           "operator_registration": "2019/123456/07",
                           "operator_jurisdiction": "ZA"}
        if mutate:
            mutate(claims)
        return sdjwt.issue(header or {}, claims, disclosable, signer.sign, decoys=2)

    def operator_credential(self, *, mutate: Mutate = None, signer: Issuer | None = None,
                            valid_from: int = NOW - 8 * 86400, lifetime: int = 365 * 86400) -> str:
        signer = signer or self.issuer
        claims = {
            "iss": signer.id, "vct": VCT_OPERATOR, "jti": self.operator_credential_id,
            "sub": self.operator.id, "iat": valid_from, "nbf": valid_from, "exp": valid_from + lifetime,
            "tier": self.tier, "domains": ["operator.example"], "log_entry": "veridact-log-2026/000000123",
            "cnf": {"jwk": self.operator.jwk},
            "status": status.ref_claim(17, self.operator_status_url),
        }
        if mutate:
            mutate(claims)
        return sdjwt.issue({}, claims, {"legal_name": "Operator Example (Pty) Ltd",
                                        "registration": "2019/123456/07", "jurisdiction": "ZA"},
                           signer.sign)

    # -- presentations ----------------------------------------------------------------------

    def presentation(self, nonce: str, *, credential: str | None = None,
                     disclose: list[str] | None = None, aud: str | list[str] = AUDIENCE,
                     iat: int = NOW - 5, mutate: Mutate = None, header: dict | None = None,
                     key: ec.EllipticCurvePrivateKey | None = None) -> str:
        """An SD-JWT+KB. ``disclose`` None keeps every disclosure."""
        parsed = sdjwt.parse(credential or self.agent_credential())
        if disclose is not None:
            parsed = parsed.select(disclose)
        payload = {"aud": aud, "nonce": nonce, "iat": iat, "sd_hash": parsed.sd_hash}
        if mutate:
            mutate(payload)
        kb = jose.sign({"typ": sdjwt.KB_TYP, **(header or {})}, payload, key or self.agent.key)
        return sdjwt.serialize(parsed.jws.raw, [d.raw for d in parsed.disclosures], kb)

    # -- pattern C and known assistants ----------------------------------------------------------

    def client_attestation(self, *, mutate: Mutate = None, signer: Issuer | None = None,
                           valid_from: int = NOW - 3600, lifetime: int = 8 * 3600,
                           status_index: int = 48213, limits: dict | None = None) -> str:
        signer = signer or self.issuer
        claims = {
            "iss": signer.id, "sub": self.agent.id, "iat": valid_from, "exp": valid_from + lifetime,
            "cnf": {"jwk": self.agent.jwk},
            "status": status.ref_claim(status_index, self.agent_status_url),
            "veridact": {
                "operator": self.operator.id, "tier": self.tier,
                "scopes": ["fs:claims:read-status", "fs:quotes:create"],
                "accountable_role": "Head of Digital Claims",
                "operator_status": status.ref_claim(17, self.operator_status_url),
                "credential": f"urn:uuid:{uuid.UUID(int=status_index + 1000)}",
                **({"limits": limits} if limits else {}),
            },
        }
        if mutate:
            mutate(claims)
        return signer.sign({"typ": CLIENT_ATTESTATION_TYP}, claims)

    def known_assistant(self, *, mutate: Mutate = None, signer: Issuer | None = None,
                        valid_from: int = NOW - 86400, lifetime: int = 30 * 86400,
                        status_index: int = 3) -> str:
        signer = signer or self.issuer
        claims = {
            "iss": signer.id, "vct": VCT_KNOWN_ASSISTANT, "jti": f"urn:uuid:{uuid.UUID(int=77)}",
            "sub": CLAUDE_CIMD, "iat": valid_from, "nbf": valid_from, "exp": valid_from + lifetime,
            "client_metadata_urls": [CLAUDE_CIMD, "https://claude.ai/oauth/claude-code-client-metadata.json"],
            "operator": {"name": "Anthropic PBC", "jurisdiction": "US", "verified": "2026-11-01"},
            "redirect_hosts": ["claude.ai", "claude.com"],
            "token_endpoint_auth": {"method": "none"},
            "max_level": "approved_payer",
            "status": status.ref_claim(status_index, self.assistant_status_url),
        }
        if mutate:
            mutate(claims)
        return sdjwt.issue({}, claims, {}, signer.sign)

    def snapshot(self) -> dict[str, str]:
        """All published artefacts, url -> text."""
        return {url: body.decode() for url, body in copy.deepcopy(self.fetcher.files).items()}
