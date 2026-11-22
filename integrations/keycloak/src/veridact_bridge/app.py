"""Veridact token exchange for Keycloak (specification v0.5: patterns A and C).

Pattern A, token exchange:

    agent ──POST /token (no subject_token)──────────▶ bridge
          ◀─400 use_veridact_nonce, Veridact-Nonce: n
    agent ──POST /token subject_token=<SD-JWT+KB for n>, DPoP: <proof for Keycloak's token endpoint>──▶ bridge
             bridge: verify the presentation (all eight checks), check the DPoP key is the cnf key,
                     sign a 60-second assertion, provision the agent's Keycloak user if new
             bridge ──jwt-bearer grant + the agent's DPoP proof──▶ Keycloak
          ◀─Keycloak's response: a DPoP-bound access token with the granted scopes

Pattern C, attestation-based client authentication (attest_jwt_client_auth_dpop):

    agent ──POST /token grant_type=client_credentials, client_id=<agent URL>,
            OAuth-Client-Attestation: <Client Attestation>, DPoP: <proof>──▶ bridge
             bridge: check the attestation names this client and is bound to the DPoP key, then
                     as pattern A

Keycloak never sees the presentation, and the bridge never issues an access token: Keycloak
does, under the policies the bank already runs. The bridge's key signs only the short-lived
assertions Keycloak's "JWT Authorization Grant" identity provider is configured to trust.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from veridact_verify import PublicCode, Request, Verifier, jose

from .config import BridgeConfig
from .keycloak import Keycloak, KeycloakError, agent_username

log = logging.getLogger("veridact.bridge")

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
SD_JWT_KB_TOKEN_TYPE = "urn:veridact:params:oauth:token-type:sd-jwt-kb"
CLIENT_CREDENTIALS = "client_credentials"
ATTESTATION_HEADER = "OAuth-Client-Attestation"
AGENT_ACTOR_PROFILE = "ai_agent"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


jwk_thumbprint = jose.jwk_thumbprint


def load_signing_key(data_dir: str) -> ec.EllipticCurvePrivateKey:
    path = Path(data_dir) / "bridge-signing.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return key


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400,
                 headers: dict[str, str] | None = None):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status
        self.headers = headers or {}

    def response(self) -> web.Response:
        return web.json_response({"error": self.error, "error_description": self.description},
                                 status=self.status, headers={**NO_STORE, **self.headers})


class Bridge:
    def __init__(self, config: BridgeConfig, *, verifier: Verifier | None = None,
                 keycloak: Keycloak | None = None, signing_key: ec.EllipticCurvePrivateKey | None = None,
                 clock=time.time):
        self.config = config
        self.clock = clock
        self.verifier = verifier or config.verifier.build()
        self.keycloak = keycloak or Keycloak(config.keycloak)
        self.key = signing_key or load_signing_key(config.data_dir)
        self.jwk = {**jose.key_to_jwk(self.key.public_key()), "use": "sig", "alg": "ES256"}
        self.kid = jwk_thumbprint(self.jwk)
        self.jwk["kid"] = self.kid

    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.config.base_url,
            "token_endpoint": f"{self.config.base_url}/token",
            "jwks_uri": f"{self.config.base_url}/.well-known/jwks.json",
            "grant_types_supported": [TOKEN_EXCHANGE, CLIENT_CREDENTIALS],
            "subject_token_types_supported": [SD_JWT_KB_TOKEN_TYPE],
            "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth_dpop"],
            "veridact_audience": self.config.verifier.audience,
            "veridact_disclose": sorted(self.config.verifier.required_disclosures),
            # Agents sign DPoP proofs for Keycloak's token endpoint: the bridge forwards them unchanged.
            "dpop_htu": self.config.keycloak.dpop_htu,
            "dpop_required": self.config.require_dpop,
        }

    def nonce_error(self, request_spec: Request) -> OAuthError:
        nonce, _ = self.verifier.challenge(request_spec)
        return OAuthError("use_veridact_nonce", "sign a presentation for the Veridact-Nonce header value",
                          headers={"Veridact-Nonce": nonce})

    async def exchange(self, form: dict[str, str], dpop: str | None,
                       attestation: str | None = None) -> tuple[int, dict[str, Any], dict[str, str]]:
        grant = form.get("grant_type")
        requested = sorted(set((form.get("scope") or "").split()))
        spec = Request(scopes=frozenset(requested))
        if grant == CLIENT_CREDENTIALS and attestation:
            # Pattern C: the DPoP proof is the attestation's proof of possession, so it is required.
            if not dpop:
                raise OAuthError("invalid_dpop_proof", "attest_jwt_client_auth_dpop needs a DPoP proof")
            client_id = form.get("client_id")
            if not client_id:
                raise OAuthError("invalid_client", "client_id is required")
            decision = await self.verifier.verify_client_attestation(
                attestation, client_id=client_id, dpop_jkt=self._dpop_jkt(dpop), request=spec)
        elif grant == TOKEN_EXCHANGE:
            presentation = form.get("subject_token")
            if not presentation:
                raise self.nonce_error(spec)
            if form.get("subject_token_type") != SD_JWT_KB_TOKEN_TYPE:
                raise OAuthError("invalid_request", f"subject_token_type must be {SD_JWT_KB_TOKEN_TYPE}")
            if self.config.require_dpop and not dpop:
                raise OAuthError("invalid_dpop_proof", "a DPoP proof made with the agent's Veridact key is required")
            decision = await self.verifier.verify(presentation, spec)
        else:
            raise OAuthError("unsupported_grant_type",
                             f"use {TOKEN_EXCHANGE}, or {CLIENT_CREDENTIALS} with {ATTESTATION_HEADER}")
        record = decision.log_record()
        if not decision.allowed:
            log.info(json.dumps({"bridge": "deny", **record}))
            code = decision.public_code
            if code is PublicCode.CHALLENGE_REQUIRED and grant == TOKEN_EXCHANGE:
                raise self.nonce_error(spec)
            if code is PublicCode.SCOPE_NOT_HELD:
                raise OAuthError("invalid_scope", code.value)
            if code is PublicCode.VERIFICATION_UNAVAILABLE:
                raise OAuthError("temporarily_unavailable", code.value, 503)
            raise OAuthError("invalid_grant", code.value if code else "AUTH_FAILED")

        jkt = None
        if dpop:
            jkt = self._dpop_key_is_agent_key(dpop, decision.agent_key_id)

        assert decision.agent is not None
        if self.config.provision_agents:
            try:
                await self.keycloak.ensure_agent(decision.agent, {
                    "veridactOperator": [decision.operator or ""],
                    "veridactOperatorDomains": decision.operator_domains,
                    "veridactTier": [decision.tier or ""],
                    "veridactAccountableRole": [decision.accountable_role or ""],
                })
            except KeycloakError as err:
                log.error("agent provisioning failed: %s", err)
                raise OAuthError("temporarily_unavailable", "cannot provision the agent", 503) from None

        now = int(self.clock())
        expires = min(now + self.config.assertion_lifetime,
                      decision.agent_credential_expires or now + self.config.assertion_lifetime)
        claims: dict[str, Any] = {
            "iss": self.config.base_url,
            "sub": decision.agent,
            "aud": self.config.assertion_audience,
            "iat": now,
            "exp": expires,
            "jti": str(uuid.uuid4()),
            "preferred_username": agent_username(decision.agent),
            "scope": " ".join(decision.scopes_granted),
            # The agent acts as itself here; act names it the way draft-mcguinness-oauth-actor-profile
            # does, so a token that later carries a customer as sub keeps the same actor shape.
            "act": {"sub": decision.agent, "sub_profile": AGENT_ACTOR_PROFILE},
            "veridact": {
                "operator": decision.operator,
                "operatorDomains": decision.operator_domains,
                "tier": decision.tier,
                "accountableRole": decision.accountable_role,
                "agentKeyId": decision.agent_key_id,
                "agentCredential": decision.agent_credential_id,
                "limits": decision.limits,
            },
        }
        if jkt:
            claims["cnf"] = {"jkt": jkt}
        assertion = jose.sign({"typ": "JWT", "kid": self.kid}, claims, self.key)
        result = await self.keycloak.jwt_bearer(assertion, claims["scope"] or None, dpop)
        log.info(json.dumps({"bridge": "allow" if result.status == 200 else "keycloak-refused",
                             "keycloakStatus": result.status, **record}))
        body = dict(result.body)
        if result.status == 200:
            body.setdefault("issued_token_type", ACCESS_TOKEN_TYPE)
        return result.status, body, result.headers

    @staticmethod
    def _dpop_jkt(dpop: str) -> str:
        try:
            header = json.loads(jose.b64url_decode(dpop.split(".")[0]))
            return jwk_thumbprint(header["jwk"])
        except (ValueError, KeyError, TypeError, jose.JoseError, IndexError):
            raise OAuthError("invalid_dpop_proof", "DPoP proof has no usable jwk header") from None

    def _dpop_key_is_agent_key(self, dpop: str, agent_jkt: str | None) -> str:
        """The DPoP proof must be made with the agent's Veridact key (the credential's cnf), so the
        access token is bound to that key. Keycloak checks the proof itself."""
        proof_jkt = self._dpop_jkt(dpop)
        if not agent_jkt:
            raise OAuthError("invalid_dpop_proof", "no agent key to compare")
        if agent_jkt != proof_jkt:
            raise OAuthError("invalid_dpop_proof", "the DPoP key is not the agent's Veridact key")
        return proof_jkt


def create_app(bridge: Bridge) -> web.Application:
    app = web.Application(client_max_size=128 * 1024)
    app["bridge"] = bridge

    async def token(request: web.Request) -> web.Response:
        if request.content_type != "application/x-www-form-urlencoded":
            return OAuthError("invalid_request", "use application/x-www-form-urlencoded").response()
        form = {k: v for k, v in (await request.post()).items() if isinstance(v, str)}
        try:
            status, body, headers = await bridge.exchange(form, request.headers.get("DPoP"),
                                                          request.headers.get(ATTESTATION_HEADER))
        except OAuthError as err:
            return err.response()
        return web.json_response(body, status=status, headers={**NO_STORE, **headers})

    async def jwks(request: web.Request) -> web.Response:
        return web.json_response({"keys": [bridge.jwk]},
                                 headers={"Cache-Control": "public, max-age=300"})

    async def metadata(request: web.Request) -> web.Response:
        return web.json_response(bridge.metadata())

    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    app.add_routes([
        web.post("/token", token),
        web.get("/.well-known/jwks.json", jwks),
        web.get("/.well-known/veridact-bridge", metadata),
        web.get("/healthz", healthz),
    ])

    async def close(app: web.Application):
        await bridge.keycloak.close()
        fetcher_close = getattr(bridge.verifier.fetcher, "close", None)
        if fetcher_close:
            await fetcher_close()
    app.on_cleanup.append(close)
    return app
