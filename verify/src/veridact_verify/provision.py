"""Creating did:webvh DIDs with P-256 signing keys.

Shared by the issuer and by vbot, so every Veridact DID is built the same way: a
did:webvh 1.0 log whose document lists P-256 Multikeys under the relationships
the spec requires, and whose updates are authorised by an Ed25519 update key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from did_webvh.askar import AskarSigningKey
from did_webvh.const import SCID_PLACEHOLDER
from did_webvh.core.hash_utils import HashInfo
from did_webvh.history import did_base_url
from did_webvh.provision import provision_did

from . import jose

DID_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]


@dataclass
class ProvisionedDid:
    did: str
    log: str  # did.jsonl contents, newline-terminated

    @property
    def log_url(self) -> str:
        return did_base_url(self.did) + "did.jsonl"


def new_update_key() -> AskarSigningKey:
    return AskarSigningKey.generate("ed25519")


def update_key_to_jwk(key: AskarSigningKey) -> dict[str, Any]:
    """Private JWK of an Ed25519 update key, for storage in a secret store."""
    return json.loads(key.key.get_jwk_secret())


def update_key_from_jwk(jwk: dict[str, Any]) -> AskarSigningKey:
    return AskarSigningKey.from_jwk(json.dumps(jwk))


def next_key_hash(key: AskarSigningKey, hash_name: str = "sha2-256") -> str:
    """The pre-rotation commitment to ``key``, for the nextKeyHashes parameter."""
    return HashInfo.from_name(hash_name).formatted_hash(key.multikey.encode("utf-8"))


def provision(
    domain_path: str,
    keys: dict[str, ec.EllipticCurvePublicKey],
    relationships: dict[str, list[str]],
    update_key: AskarSigningKey,
    *,
    next_update_key: AskarSigningKey | None = None,
    timestamp: datetime | None = None,
    service: list[dict[str, Any]] | None = None,
) -> ProvisionedDid:
    """Create a did:webvh log for ``did:webvh:{SCID}:{domain_path}``.

    ``keys`` maps fragments ("key-1") to P-256 public keys. ``relationships`` maps
    verification relationships ("authentication", "assertionMethod") to fragments.
    With ``next_update_key``, the log pre-rotates: it commits to that key's hash, so a
    stolen current update key cannot take over the identifier.
    """
    placeholder = f"did:webvh:{SCID_PLACEHOLDER}:{domain_path}"
    doc: dict[str, Any] = {
        "@context": DID_CONTEXT,
        "id": placeholder,
        "verificationMethod": [
            {
                "id": f"{placeholder}#{frag}",
                "type": "Multikey",
                "controller": placeholder,
                "publicKeyMultibase": jose.key_to_multikey(key),
            }
            for frag, key in keys.items()
        ],
    }
    for relationship, frags in relationships.items():
        unknown = set(frags) - set(keys)
        if unknown:
            raise ValueError(f"{relationship} names unknown keys {sorted(unknown)}")
        doc[relationship] = [f"{placeholder}#{frag}" for frag in frags]
    if service:
        doc["service"] = service
    params: dict[str, Any] = {"updateKeys": [update_key.multikey]}
    if next_update_key is not None:
        params["nextKeyHashes"] = [next_key_hash(next_update_key)]
    ts = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
    state = provision_did(doc, params=params, timestamp=ts)
    state.proofs.append(state.create_proof(update_key, timestamp=state.timestamp))
    return ProvisionedDid(state.document_id, state.history_json() + "\n")
