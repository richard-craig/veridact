"""Configure a Keycloak (26.6+) realm for the Veridact bridge, through the admin REST API.

    python -m veridact_bridge.setup_realm --keycloak https://sso.bank.example --realm bank \\
        --admin-user admin --admin-password … \\
        --bridge-issuer https://auth.bank.example \\
        --jwks-url https://auth.bank.example/.well-known/jwks.json

Creates (or updates):
  - an identity provider of type "jwt-authorization-grant" (alias "veridact") trusting the
    bridge's issuer and JWKS, ES256 only, assertions of at most 5 minutes, no reuse;
  - a confidential client "veridact-bridge" allowed to use the JWT Authorization Grant with
    that provider, with one optional client scope per Veridact scope;
  - a confidential client "veridact-admin" whose service account may create and link agent
    users (manage-users, view-users, query-users), for the bridge's provisioning;
  - the realm user profile's unmanaged-attribute policy set to ADMIN_EDIT, so the bridge can
    record each agent's operator, domains, tier and accountable role on its user.

Prints the bridge's "keycloak" config block, client secrets included.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
from typing import Any

import aiohttp

DEFAULT_SCOPES = ("fs:claims:read-status", "fs:quotes:create", "fs:payments:initiate")


class Admin:
    def __init__(self, session: aiohttp.ClientSession, base: str, token: str, realm: str):
        self.session, self.base, self.token, self.realm = session, base.rstrip("/"), token, realm

    async def call(self, method: str, path: str, body: Any = None, *, ok=(200, 201, 204),
                   realm_scoped: bool = True) -> Any:
        url = f"{self.base}/admin/realms/{self.realm}{path}" if realm_scoped else f"{self.base}/admin{path}"
        async with self.session.request(method, url, json=body,
                                        headers={"Authorization": f"Bearer {self.token}"}) as resp:
            text = await resp.text()
            if resp.status not in ok:
                raise RuntimeError(f"{method} {path}: {resp.status} {text[:300]}")
            return json.loads(text) if text else None


async def admin_token(session: aiohttp.ClientSession, base: str, user: str, password: str) -> str:
    async with session.post(f"{base.rstrip('/')}/realms/master/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "admin-cli", "username": user,
            "password": password}) as resp:
        body = await resp.json(content_type=None)
        if resp.status != 200:
            raise RuntimeError(f"admin login failed: {body}")
        return body["access_token"]


async def configure(*, keycloak: str, realm: str, admin_user: str, admin_password: str,
                    bridge_issuer: str, jwks_url: str, idp_alias: str = "veridact",
                    scopes: tuple[str, ...] = DEFAULT_SCOPES, create_realm: bool = True,
                    ssl_required: str = "external") -> dict[str, Any]:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        token = await admin_token(session, keycloak, admin_user, admin_password)
        kc = Admin(session, keycloak, token, realm)

        if create_realm:
            async with session.get(f"{keycloak.rstrip('/')}/realms/{realm}") as resp:
                exists = resp.status == 200
            if not exists:
                await kc.call("POST", "/realms", {"realm": realm, "enabled": True,
                                                  "sslRequired": ssl_required}, realm_scoped=False)

        # Let the bridge write agent attributes (operator, domains, tier, role) on agent users.
        profile = await kc.call("GET", "/users/profile")
        if profile.get("unmanagedAttributePolicy") not in ("ENABLED", "ADMIN_EDIT"):
            profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"
            await kc.call("PUT", "/users/profile", profile)

        # The trust: assertions from the bridge, verified with its JWKS.
        idp = {
            "alias": idp_alias, "displayName": "Veridact", "providerId": "jwt-authorization-grant",
            "enabled": True, "hideOnLogin": True,
            "config": {
                "issuer": bridge_issuer,
                "useJwksUrl": "true",
                "jwksUrl": jwks_url,
                "jwtAuthorizationGrantEnabled": "true",
                "jwtAuthorizationGrantAssertionSignatureAlg": "ES256",
                "jwtAuthorizationGrantMaxAllowedAssertionExpiration": "300",
                "jwtAuthorizationGrantAssertionReuseAllowed": "false",
                "jwtAuthorizationGrantAllowedClockSkew": "5",
                "jwtAuthorizationGrantLimitAccessTokenExp": "false",
            },
        }
        existing = await kc.call("GET", "/identity-provider/instances")
        if any(i["alias"] == idp_alias for i in existing):
            await kc.call("PUT", f"/identity-provider/instances/{idp_alias}", idp)
        else:
            await kc.call("POST", "/identity-provider/instances", idp)

        # One optional client scope per Veridact scope, so granted scopes land in the token.
        known = {s["name"]: s["id"] for s in await kc.call("GET", "/client-scopes")}
        for name in scopes:
            if name not in known:
                await kc.call("POST", "/client-scopes", {
                    "name": name, "protocol": "openid-connect",
                    "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"}})
        known = {s["name"]: s["id"] for s in await kc.call("GET", "/client-scopes")}

        async def client(client_id: str, rep: dict[str, Any]) -> tuple[str, str]:
            found = await kc.call("GET", f"/clients?clientId={client_id}")
            secret = secrets.token_urlsafe(32)
            rep = {"clientId": client_id, "enabled": True, "publicClient": False,
                   "clientAuthenticatorType": "client-secret", "secret": secret,
                   "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                   "implicitFlowEnabled": False, "protocol": "openid-connect", **rep}
            if found:
                uuid_ = found[0]["id"]
                await kc.call("PUT", f"/clients/{uuid_}", {**found[0], **rep})
            else:
                await kc.call("POST", "/clients", rep)
                uuid_ = (await kc.call("GET", f"/clients?clientId={client_id}"))[0]["id"]
            return uuid_, secret

        bridge_uuid, bridge_secret = await client("veridact-bridge", {
            "serviceAccountsEnabled": False,
            "attributes": {"oauth2.jwt.authorization.grant.enabled": "true",
                           "oauth2.jwt.authorization.grant.idp": idp_alias},
        })
        for name in scopes:
            await kc.call("PUT", f"/clients/{bridge_uuid}/optional-client-scopes/{known[name]}")

        admin_uuid, admin_secret = await client("veridact-admin", {"serviceAccountsEnabled": True})
        sa = await kc.call("GET", f"/clients/{admin_uuid}/service-account-user")
        rm = (await kc.call("GET", "/clients?clientId=realm-management"))[0]["id"]
        roles = [r for r in await kc.call("GET", f"/clients/{rm}/roles")
                 if r["name"] in ("manage-users", "view-users", "query-users")]
        await kc.call("POST", f"/users/{sa['id']}/role-mappings/clients/{rm}", roles)

        return {"url": keycloak, "realm": realm, "client_id": "veridact-bridge",
                "client_secret": bridge_secret, "idp_alias": idp_alias,
                "admin_client_id": "veridact-admin", "admin_client_secret": admin_secret}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m veridact_bridge.setup_realm", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keycloak", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--bridge-issuer", required=True)
    parser.add_argument("--jwks-url", required=True)
    parser.add_argument("--idp-alias", default="veridact")
    parser.add_argument("--scope", action="append")
    parser.add_argument("--no-create-realm", action="store_true")
    args = parser.parse_args(argv)
    result = asyncio.run(configure(
        keycloak=args.keycloak, realm=args.realm, admin_user=args.admin_user,
        admin_password=args.admin_password, bridge_issuer=args.bridge_issuer, jwks_url=args.jwks_url,
        idp_alias=args.idp_alias, scopes=tuple(args.scope or DEFAULT_SCOPES),
        create_realm=not args.no_create_realm))
    print(json.dumps({"keycloak": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
