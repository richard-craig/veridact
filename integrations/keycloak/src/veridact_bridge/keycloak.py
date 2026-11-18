"""Talking to Keycloak: the JWT Authorization Grant, and agent provisioning.

Keycloak's JWT Authorization Grant (RFC 7523, supported from 26.6) requires the
assertion's subject to be an existing user linked to the identity provider. The bridge
therefore gives each agent a Keycloak user the first time a presentation from it
verifies: username ``agent-<hash of the DID>``, linked to the identity provider with
the agent DID as the federated user id.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

from .config import KeycloakConfig

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class KeycloakError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"Keycloak {status}: {detail}")
        self.status = status


def agent_username(did: str) -> str:
    """A stable Keycloak username for an agent DID (DIDs are too long and full of colons)."""
    digest = hashlib.sha256(did.encode()).digest()
    return "agent-" + base64.b32encode(digest).decode().rstrip("=").lower()[:26]


@dataclass
class TokenResult:
    status: int
    body: dict[str, Any]
    headers: dict[str, str]


class Keycloak:
    def __init__(self, config: KeycloakConfig, session: aiohttp.ClientSession | None = None):
        self.config = config
        self._session = session
        self._admin_token: tuple[str, float] | None = None
        self._provisioned: dict[str, str] = {}  # agent DID -> user id

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()

    # -- the grant -----------------------------------------------------------------

    async def jwt_bearer(self, assertion: str, scope: str | None, dpop: str | None) -> TokenResult:
        form = {"grant_type": JWT_BEARER, "assertion": assertion,
                "client_id": self.config.client_id, "client_secret": self.config.client_secret}
        if scope:
            form["scope"] = scope
        headers = {"Accept": "application/json"}
        if dpop:
            headers["DPoP"] = dpop
        async with self.session.post(self.config.token_endpoint, data=form, headers=headers) as resp:
            try:
                body = await resp.json(content_type=None)
            except ValueError:
                body = {"error": "server_error", "error_description": f"Keycloak returned {resp.status}"}
            passthrough = {k: v for k, v in resp.headers.items() if k.lower() in ("dpop-nonce",)}
            return TokenResult(resp.status, body, passthrough)

    # -- provisioning -------------------------------------------------------------

    async def _admin(self) -> str:
        if self._admin_token and self._admin_token[1] > time.time() + 30:
            return self._admin_token[0]
        if not self.config.admin_client_id:
            raise KeycloakError(0, "no admin client configured")
        form = {"grant_type": "client_credentials", "client_id": self.config.admin_client_id,
                "client_secret": self.config.admin_client_secret or ""}
        async with self.session.post(self.config.token_endpoint, data=form) as resp:
            body = await resp.json(content_type=None)
            if resp.status != 200:
                raise KeycloakError(resp.status, str(body.get("error_description", body)))
        self._admin_token = (body["access_token"], time.time() + int(body.get("expires_in", 60)))
        return self._admin_token[0]

    async def _call(self, method: str, path: str, json_body: Any = None,
                    params: dict[str, str] | None = None) -> tuple[int, Any, dict[str, str]]:
        token = await self._admin()
        async with self.session.request(method, self.config.admin_url + path, json=json_body,
                                        params=params,
                                        headers={"Authorization": f"Bearer {token}"}) as resp:
            text = await resp.text()
            try:
                body = await resp.json(content_type=None) if text else None
            except ValueError:
                body = text
            return resp.status, body, dict(resp.headers)

    async def ensure_agent(self, did: str, attributes: dict[str, list[str]]) -> str:
        """Return the Keycloak user id for an agent DID, creating and linking it if needed."""
        if did in self._provisioned:
            return self._provisioned[did]
        username = agent_username(did)
        status, users, _ = await self._call("GET", "/users",
                                            params={"username": username, "exact": "true"})
        if status != 200:
            raise KeycloakError(status, f"user search failed: {users}")
        if users:
            user_id = users[0]["id"]
            await self._check_link(user_id, did)
        else:
            status, body, headers = await self._call("POST", "/users", {
                "username": username, "enabled": True, "attributes": attributes})
            if status != 201:
                raise KeycloakError(status, f"cannot create agent user: {body}")
            user_id = headers["Location"].rstrip("/").rsplit("/", 1)[1]
            status, body, _ = await self._call(
                "POST", f"/users/{user_id}/federated-identity/{self.config.idp_alias}",
                {"identityProvider": self.config.idp_alias, "userId": did, "userName": username})
            if status not in (200, 201, 204):
                raise KeycloakError(status, f"cannot link agent user: {body}")
        self._provisioned[did] = user_id
        return user_id

    async def _check_link(self, user_id: str, did: str) -> None:
        status, links, _ = await self._call("GET", f"/users/{user_id}/federated-identity")
        if status != 200:
            raise KeycloakError(status, f"cannot read federated identities: {links}")
        for link in links or []:
            if link.get("identityProvider") == self.config.idp_alias:
                if link.get("userId") != did:
                    raise KeycloakError(409, "username belongs to another agent")
                return
        status, body, _ = await self._call(
            "POST", f"/users/{user_id}/federated-identity/{self.config.idp_alias}",
            {"identityProvider": self.config.idp_alias, "userId": did, "userName": agent_username(did)})
        if status not in (200, 201, 204):
            raise KeycloakError(status, f"cannot link agent user: {body}")
