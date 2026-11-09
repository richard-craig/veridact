"""A mock Veridact network: governance, an issuer, an operator and an agent.

Everything a relying party would read is published into a StaticFetcher, at the
URLs the real artefacts would have. Every builder accepts ``mutate`` hooks so tests
and conformance vectors can produce precisely broken inputs.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from did_webvh.askar import AskarSigningKey
from did_webvh.const import SCID_PLACEHOLDER
from did_webvh.history import did_base_url
from did_webvh.provision import provision_did

from .. import jose
from ..fetch import StaticFetcher
from ..status import MIN_LIST_BITS, encode_bitstring

# Fixed clock for reproducible vectors: 2026-11-09T08:00:00Z
NOW = 1794211200
DID_TIME = datetime(2026, 11, 1, tzinfo=timezone.utc)

VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://veridact.net/ns/v1"]
DID_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]
AUDIENCE = "https://api.bank.example"
TRUST_LIST_URL = "https://trust.veridact.example/trust-list.jwt"
GOV_KID = "gov-test-2026a"
SCOPES = ["fs:claims:read-status", "fs:quotes:create", "fs:payments:initiate"]

Mutate = Callable[[dict], None] | None


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Party:
    """A DID with one P-256 signing key, published as a did:webvh log."""

    did: str
    key: ec.EllipticCurvePrivateKey
    kid: str
    log: str
    update_key: Any = None

    @property
    def log_url(self) -> str:
        return did_base_url(self.did) + "did.jsonl"


def make_party(domain_path: str, relationship: str, *, key_fragment: str = "key-1",
               extra_keys: dict[str, ec.EllipticCurvePrivateKey] | None = None) -> Party:
    update_key = AskarSigningKey.generate("ed25519")
    key = ec.generate_private_key(ec.SECP256R1())
    placeholder = f"did:webvh:{SCID_PLACEHOLDER}:{domain_path}"
    keys = {key_fragment: key, **(extra_keys or {})}
    doc = {
        "@context": DID_CONTEXT,
        "id": placeholder,
        "verificationMethod": [
            {
                "id": f"{placeholder}#{frag}",
                "type": "Multikey",
                "controller": placeholder,
                "publicKeyMultibase": jose.key_to_multikey(k.public_key()),
            }
            for frag, k in keys.items()
        ],
        relationship: [f"{placeholder}#{frag}" for frag in keys],
    }
    state = provision_did(doc, params={"updateKeys": [update_key.multikey]}, timestamp=DID_TIME)
    state.proofs.append(state.create_proof(update_key, timestamp=state.timestamp))
    did = state.document_id
    return Party(did, key, f"{did}#{key_fragment}", state.history_json() + "\n", update_key)


@dataclass
class MockNetwork:
    fetcher: StaticFetcher = field(default_factory=StaticFetcher)
    tier: str = "organisation"

    def __post_init__(self) -> None:
        self.governance_key = ec.generate_private_key(ec.SECP256R1())
        self.issuer = make_party("veridact.example:issuers:org-2026b", "assertionMethod",
                                 key_fragment="key-3")
        self.rogue_issuer = make_party("rogue.example:issuers:x", "assertionMethod")
        self.operator = make_party("operator.example", "assertionMethod")
        self.agent = make_party("operator.example:agents:a7f3k2", "authentication")
        self.operator_domain = "operator.example"
        self.operator_credential_id = f"urn:uuid:{uuid.UUID(int=1)}"
        self.agent_status_url = "https://status.veridact.example/org/2026-11/7"
        self.operator_status_url = "https://status.veridact.example/operators/2026-11/1"
        self.revoked: dict[str, set[int]] = {self.agent_status_url: set(),
                                            self.operator_status_url: set()}
        for party in (self.issuer, self.rogue_issuer, self.operator, self.agent):
            self.fetcher.put(party.log_url, party.log)
        self.publish_trust_list()
        for url in self.revoked:
            self.publish_status_list(url)

    # -- governance --------------------------------------------------------------

    @property
    def governance_keys(self) -> dict[str, dict]:
        return {GOV_KID: jose.key_to_jwk(self.governance_key.public_key())}

    def trust_list_payload(self) -> dict[str, Any]:
        return {
            "iss": "https://trust.veridact.example",
            "version": "2026.11.1",
            "iat": NOW - 86400,
            "exp": NOW + 7 * 86400,
            "issuers": [
                {
                    "id": self.issuer.did,
                    "tiers": ["domain", "organisation"],
                    "credentialTypes": ["VeridactAgentCredential", "VeridactOperatorCredential"],
                    "keys": [{"kid": self.issuer.kid, "notBefore": NOW - 60 * 86400,
                              "notAfter": NOW + 30 * 86400}],
                }
            ],
            "scopes": SCOPES,
            "policy": {
                "tierOrder": ["domain", "organisation"],
                "agentCredentialMaxLifetime": 86400,
                "presentationMaxLifetime": 120,
                "operatorCredentialMaxLifetime": {"domain": 90 * 86400,
                                                  "organisation": 366 * 86400},
            },
        }

    def publish_trust_list(self, mutate: Mutate = None, *, key=None) -> str:
        payload = self.trust_list_payload()
        if mutate:
            mutate(payload)
        token = jose.sign({"typ": "trust-list+jwt", "kid": GOV_KID}, payload,
                          key or self.governance_key)
        self.fetcher.put(TRUST_LIST_URL, token)
        return token

    # -- status lists ------------------------------------------------------------

    def publish_status_list(self, url: str, *, signer: Party | None = None,
                            mutate: Mutate = None) -> str:
        bits = bytearray(MIN_LIST_BITS // 8)
        for index in self.revoked[url]:
            bits[index // 8] |= 0x80 >> (index % 8)
        signer = signer or self.issuer
        payload = {
            "@context": VC_CONTEXT[:1],
            "id": url,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": signer.did,
            "validFrom": iso(NOW - 600),
            "iat": NOW - 600,
            "credentialSubject": {
                "id": url + "#list",
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encode_bitstring(bytes(bits)),
            },
        }
        if mutate:
            mutate(payload)
        token = jose.sign({"typ": "vc+jwt", "kid": signer.kid}, payload, signer.key)
        self.fetcher.put(url, token)
        return token

    def revoke(self, url: str, index: int) -> None:
        self.revoked[url].add(index)
        self.publish_status_list(url)

    # -- credentials ---------------------------------------------------------------

    def _sign_vc(self, payload: dict, signer: Party, mutate: Mutate, header: dict | None = None) -> str:
        if mutate:
            mutate(payload)
        hdr = {"typ": "vc+jwt", "kid": signer.kid, **(header or {})}
        return jose.sign(hdr, payload, signer.key)

    def operator_credential(self, *, mutate: Mutate = None, signer: Party | None = None,
                            header: dict | None = None, valid_from: int = NOW - 8 * 86400,
                            lifetime: int = 365 * 86400) -> str:
        signer = signer or self.issuer
        payload = {
            "@context": VC_CONTEXT,
            "id": self.operator_credential_id,
            "type": ["VerifiableCredential", "VeridactOperatorCredential"],
            "issuer": signer.did,
            "validFrom": iso(valid_from),
            "validUntil": iso(valid_from + lifetime),
            "iat": valid_from,
            "exp": valid_from + lifetime,
            "credentialSubject": {
                "id": self.operator.did,
                "domains": [self.operator_domain],
                "tier": self.tier,
                "legalEntity": {"name": "Operator Example (Pty) Ltd",
                                "cipcNumber": "2019/123456/07"},
                "transparencyLogEntry": "veridact-log-2026/000000123",
            },
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "17",
                "statusListCredential": self.operator_status_url,
            },
        }
        return self._sign_vc(payload, signer, mutate, header)

    def agent_credential(self, *, mutate: Mutate = None, signer: Party | None = None,
                         header: dict | None = None, valid_from: int = NOW - 3600,
                         lifetime: int = 8 * 3600, status_index: int = 48213,
                         scopes: list[str] | None = None,
                         limits: dict | None = None) -> str:
        signer = signer or self.issuer
        subject = {
            "id": self.agent.did,
            "operator": self.operator.did,
            "operatorCredential": self.operator_credential_id,
            "tier": self.tier,
            "scopes": scopes if scopes is not None else ["fs:claims:read-status", "fs:quotes:create"],
            "accountableRole": "Head of Digital Claims",
            "cnf": {"kid": self.agent.kid},
        }
        if limits is not None:
            subject["limits"] = limits
        payload = {
            "@context": VC_CONTEXT,
            "id": f"urn:uuid:{uuid.UUID(int=status_index + 1000)}",
            "type": ["VerifiableCredential", "VeridactAgentCredential"],
            "issuer": signer.did,
            "validFrom": iso(valid_from),
            "validUntil": iso(valid_from + lifetime),
            "iat": valid_from,
            "exp": valid_from + lifetime,
            "credentialSubject": subject,
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": str(status_index),
                "statusListCredential": self.agent_status_url,
            },
        }
        return self._sign_vc(payload, signer, mutate, header)

    # -- presentations -------------------------------------------------------------

    def presentation(self, nonce: str, *, credentials: list[str] | None = None,
                     aud: str | list[str] = AUDIENCE, iat: int = NOW - 5, lifetime: int = 60,
                     mutate: Mutate = None, header: dict | None = None,
                     key: ec.EllipticCurvePrivateKey | None = None) -> str:
        if credentials is None:
            credentials = [self.agent_credential(), self.operator_credential()]
        payload = {
            "@context": VC_CONTEXT[:1],
            "type": ["VerifiablePresentation"],
            "holder": self.agent.did,
            "verifiableCredential": [
                {"@context": VC_CONTEXT[:1], "type": "EnvelopedVerifiableCredential",
                 "id": "data:application/vc+jwt," + c}
                for c in credentials
            ],
            "aud": aud,
            "nonce": nonce,
            "iat": iat,
            "exp": iat + lifetime,
        }
        if mutate:
            mutate(payload)
        hdr = {"typ": "vp+jwt", "kid": self.agent.kid, **(header or {})}
        return jose.sign(hdr, payload, key or self.agent.key)

    def snapshot(self) -> dict[str, str]:
        """All published artefacts, url -> text."""
        return {url: body.decode() for url, body in copy.deepcopy(self.fetcher.files).items()}
