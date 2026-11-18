"""Key custody for vbot.

The spec allows software keys at Domain tier only; from Organisation tier up, agent
keys must be non-exportable (cloud KMS, TPM or HSM). ``KeyStore`` is the seam those
backends plug into. Month 1 ships the software store: PEM files, mode 0600.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from veridact_verify import jose, provision


class Key(Protocol):
    def sign(self, header: dict[str, Any], payload: dict[str, Any]) -> str: ...

    def public_key(self) -> ec.EllipticCurvePublicKey: ...


class SoftwareKey:
    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self._key = key

    def sign(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        return jose.sign(header, payload, self._key)

    def sign_bytes(self, data: bytes) -> bytes:
        """Raw ES256 (r||s) over ``data``, for the flattened JWS that ACME uses."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._key.public_key()

    @property
    def jwk(self) -> dict[str, str]:
        return jose.key_to_jwk(self.public_key())


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


class SoftwareKeyStore:
    """Keys as files under ``{home}/keys``. Domain tier only."""

    custody = "software"

    def __init__(self, home: Path):
        self.dir = home / "keys"

    def _path(self, name: str, ext: str) -> Path:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"bad key name {name!r}")
        return self.dir / f"{name}.{ext}"

    def get_or_create(self, name: str) -> SoftwareKey:
        path = self._path(name, "pem")
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ValueError(f"{path} is not a P-256 key")
            return SoftwareKey(key)
        key = ec.generate_private_key(ec.SECP256R1())
        _write_secret(path, key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        return SoftwareKey(key)

    def get(self, name: str) -> SoftwareKey:
        if not self._path(name, "pem").exists():
            raise KeyError(name)
        return self.get_or_create(name)

    def save_update_keys(self, name: str, current, nxt) -> None:
        """DID update keys (Ed25519): the current one and the pre-rotated next one."""
        _write_secret(self._path(name, "update.json"), json.dumps({
            "current": provision.update_key_to_jwk(current),
            "next": provision.update_key_to_jwk(nxt),
        }).encode())
