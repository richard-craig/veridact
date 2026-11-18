"""Issuer keys and identity.

Month 1 keeps software keys on disk (mode 0600) behind a ``Signer`` interface.
Month 2 swaps in AWS KMS / CloudHSM: the spec requires HSM-backed, non-exportable
credential signing keys before any production listing.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from veridact_verify import jose, provision

from .config import IssuerConfig

SIGNING_FRAGMENT = "key-1"


class Signer(Protocol):
    """Signs compact ES256 JWS. A KMS or HSM implementation keeps the key inside."""

    kid: str

    def sign(self, header: dict[str, Any], payload: dict[str, Any]) -> str: ...

    def public_key(self) -> ec.EllipticCurvePublicKey: ...


@dataclass
class SoftwareSigner:
    kid: str
    key: ec.EllipticCurvePrivateKey

    def sign(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        return jose.sign({**header, "kid": self.kid}, payload, self.key)

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.key.public_key()


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _load_or_create_ec(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"{path} is not a P-256 key")
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    _write_secret(path, key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return key


@dataclass
class IssuerIdentity:
    """The issuer DID, its signing key and, in staging, the governance key."""

    did: str
    did_log: str
    signer: Signer
    key_not_before: int
    key_not_after: int
    governance_kid: str | None = None
    governance_key: ec.EllipticCurvePrivateKey | None = None

    @property
    def governance_jwks(self) -> dict[str, dict[str, str]]:
        if self.governance_key is None or self.governance_kid is None:
            return {}
        return {self.governance_kid: jose.key_to_jwk(self.governance_key.public_key())}


def load_or_create_identity(config: IssuerConfig, *, now: float | None = None) -> IssuerIdentity:
    """Load the issuer identity from ``data_dir/keys``, creating it on first run."""
    now = int(now if now is not None else time.time())
    keys_dir = config.data_path / "keys"
    meta_path = keys_dir / "identity.json"
    signing_key = _load_or_create_ec(keys_dir / "credential-signing.pem")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("issuerDidPath") != config.issuer_did_path:
            raise ValueError(
                f"data_dir holds the identity for {meta.get('issuerDidPath')}, "
                f"not {config.issuer_did_path}; use a new data_dir")
    else:
        update_key = provision.new_update_key()
        next_update_key = provision.new_update_key()
        made = provision.provision(
            config.issuer_did_path,
            {SIGNING_FRAGMENT: signing_key.public_key()},
            {"assertionMethod": [SIGNING_FRAGMENT]},
            update_key,
            next_update_key=next_update_key,
        )
        _write_secret(keys_dir / "did-update-keys.json", json.dumps({
            "current": provision.update_key_to_jwk(update_key),
            "next": provision.update_key_to_jwk(next_update_key),
        }).encode())
        meta = {
            "issuerDidPath": config.issuer_did_path,
            "did": made.did,
            "keyNotBefore": now,
            "keyNotAfter": now + config.signing_key_lifetime,
        }
        (keys_dir / "did.jsonl").write_text(made.log)
        meta_path.write_text(json.dumps(meta, indent=2))
    did = meta["did"]
    did_log = (keys_dir / "did.jsonl").read_text()
    identity = IssuerIdentity(
        did=did,
        did_log=did_log,
        signer=SoftwareSigner(f"{did}#{SIGNING_FRAGMENT}", signing_key),
        key_not_before=meta["keyNotBefore"],
        key_not_after=meta["keyNotAfter"],
    )
    if config.publish_trust_list:
        identity.governance_key = _load_or_create_ec(keys_dir / "staging-governance.pem")
        identity.governance_kid = f"veridact-{config.environment}-governance-1"
    return identity
