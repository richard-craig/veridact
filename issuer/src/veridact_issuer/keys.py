"""Issuer keys and identity.

Software keys on disk (mode 0600) sit behind a ``Signer`` interface; production swaps in
an HSM or cloud KMS (the specification requires non-exportable credential signing keys
before any production listing).

Since v0.5 the issuer is an HTTPS identifier, ``{base_url}/issuers/{name}``. Its keys are
published as JWT VC Issuer Metadata and pinned, by thumbprint, in the trust list.
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
from veridact_verify import jose
from veridact_verify.identifiers import issuer_metadata_document

from .config import IssuerConfig


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
    """The issuer identifier, its signing key and, in staging, the governance key."""

    id: str
    signer: Signer
    key_not_before: int
    key_not_after: int
    governance_kid: str | None = None
    governance_key: ec.EllipticCurvePrivateKey | None = None

    @property
    def jkt(self) -> str:
        return jose.jwk_thumbprint(jose.key_to_jwk(self.signer.public_key()))

    def metadata(self) -> dict[str, Any]:
        """JWT VC Issuer Metadata (draft-ietf-oauth-sd-jwt-vc)."""
        return issuer_metadata_document(self.id, {self.signer.kid: self.signer.public_key()})

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
        if "issuerDidPath" in meta:
            raise ValueError("data_dir holds a v0.4 (did:webvh) issuer; v0.5 is a clean cut: use a new data_dir")
        if meta.get("issuer") != config.issuer_url:
            raise ValueError(f"data_dir holds the identity for {meta.get('issuer')}, "
                             f"not {config.issuer_url}; use a new data_dir")
    else:
        meta = {
            "issuer": config.issuer_url,
            "kid": f"{config.issuer_name}-1",
            "keyNotBefore": now,
            "keyNotAfter": now + config.signing_key_lifetime,
        }
        keys_dir.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(meta, indent=2))
    identity = IssuerIdentity(
        id=meta["issuer"],
        signer=SoftwareSigner(meta["kid"], signing_key),
        key_not_before=meta["keyNotBefore"],
        key_not_after=meta["keyNotAfter"],
    )
    if config.publish_trust_list:
        identity.governance_key = _load_or_create_ec(keys_dir / "staging-governance.pem")
        identity.governance_kid = f"veridact-{config.environment}-governance-1"
    return identity
