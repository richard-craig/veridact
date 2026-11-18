"""A stand-in for one Keycloak 26.6 realm, faithful to the rules the bridge depends on.

Modelled on Keycloak's JWTAuthorizationGrantType, JWTAuthorizationGrantValidator and
DPoPUtil (release/26.6): confidential client with the grant enabled and the identity
provider allowed; assertion iss matches the identity provider; signature checked with the
provider's JWKS; aud is the realm issuer or token endpoint; exp required and at most 5
minutes away; jti single use; the subject must be an existing user linked to the provider;
a DPoP header binds the access token (cnf.jkt). Plus the admin endpoints the bridge uses.

The real thing runs in CI (e2e/test_keycloak_real.py).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field

from aiohttp import web
from veridact_verify import jose
from veridact_verify.fetch import Fetcher


def thumbprint(jwk: dict) -> str:
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"),
                           sort_keys=True)
    return jose.b64url_encode(hashlib.sha256(canonical.encode()).digest())


@dataclass
class FakeKeycloak:
    realm: str
    idp_alias: str
    idp_issuer: str
    idp_jwks_url: str
    fetcher: Fetcher
    clients: dict[str, str] = field(default_factory=lambda: {"veridact-bridge": "bridge-secret",
                                                              "veridact-admin": "admin-secret"})
    users: dict[str, dict] = field(default_factory=dict)  # id -> {username, links: {alias: userId}}
    used_jti: set[str] = field(default_factory=set)
    used_dpop_jti: set[str] = field(default_factory=set)
    base: str = ""

    @property
    def issuer(self) -> str:
        return f"{self.base}/realms/{self.realm}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    def error(self, description: str, error: str = "invalid_grant") -> web.Response:
        return web.json_response({"error": error, "error_description": description}, status=400)

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_post(f"/realms/{self.realm}/protocol/openid-connect/token", self.token)
        admin = f"/admin/realms/{self.realm}"
        app.router.add_get(admin + "/users", self.find_users)
        app.router.add_post(admin + "/users", self.create_user)
        app.router.add_get(admin + "/users/{id}/federated-identity", self.links)
        app.router.add_post(admin + "/users/{id}/federated-identity/{alias}", self.link)
        return app

    async def token(self, request: web.Request) -> web.Response:
        form = await request.post()
        if self.clients.get(form.get("client_id", "")) != form.get("client_secret"):
            return web.json_response({"error": "unauthorized_client"}, status=401)
        if form["grant_type"] == "client_credentials":
            if form["client_id"] != "veridact-admin":
                return self.error("not allowed", "unauthorized_client")
            return web.json_response({"access_token": "admin-" + uuid.uuid4().hex, "expires_in": 300,
                                      "token_type": "Bearer"})
        if form["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer":
            return self.error("unsupported", "unsupported_grant_type")
        if form["client_id"] != "veridact-bridge":
            return self.error("JWT Authorization Grant is not supported for the requested client")
        try:
            jws = jose.parse(form["assertion"])
        except (KeyError, jose.JoseError):
            return self.error("The provided assertion is not a valid JWT")
        claims = jws.payload
        if claims.get("iss") != self.idp_issuer:
            return self.error("No Identity Provider for provided issuer")
        jwks = json.loads(await self.fetcher.fetch(self.idp_jwks_url))["keys"]
        key = next((k for k in jwks if k.get("kid") == jws.kid), None)
        try:
            jose.verify(jws, jose.key_from_jwk({k: key[k] for k in ("kty", "crv", "x", "y")}))
        except (TypeError, jose.JoseError):
            return self.error("Invalid signature")
        now = time.time()
        if "exp" not in claims or claims["exp"] < now:
            return self.error("Token is not active")
        if claims["exp"] - now > 300:
            return self.error("Token exp claim is too far from current time")
        if claims.get("jti") in self.used_jti or not claims.get("jti"):
            return self.error("Token reuse detected")
        self.used_jti.add(claims["jti"])
        if claims.get("aud") not in (self.issuer, self.token_endpoint):
            return self.error("Invalid token audience")
        user_id = next((uid for uid, u in self.users.items()
                        if u["links"].get(self.idp_alias) == claims.get("sub")), None)
        if user_id is None:
            return self.error("User not found")
        token_type, cnf = "Bearer", None
        proof = request.headers.get("DPoP")
        if proof:
            try:
                pj = jose.parse(proof)
                jwk = pj.header["jwk"]
                jose.verify(pj, jose.key_from_jwk(jwk))
            except (KeyError, jose.JoseError):
                return self.error("DPoP proof is invalid", "invalid_request")
            p = pj.payload
            if (pj.typ != "dpop+jwt" or p.get("htm") != "POST" or p.get("htu") != self.token_endpoint
                    or abs(p.get("iat", 0) - now) > 60 or p.get("jti") in self.used_dpop_jti):
                return self.error("DPoP proof is invalid", "invalid_request")
            self.used_dpop_jti.add(p["jti"])
            token_type, cnf = "DPoP", {"jkt": thumbprint(jwk)}
        access = {"iss": self.issuer, "sub": user_id, "azp": "veridact-bridge",
                  "preferred_username": self.users[user_id]["username"],
                  "scope": form.get("scope", ""), "exp": int(now) + 300}
        if cnf:
            access["cnf"] = cnf
        token = jose.b64url_encode(json.dumps({"alg": "none"}).encode()) + "." + \
            jose.b64url_encode(json.dumps(access).encode()) + "."
        return web.json_response({"access_token": token, "token_type": token_type, "expires_in": 300,
                                  "scope": form.get("scope", "")})

    def _admin_ok(self, request: web.Request) -> bool:
        return request.headers.get("Authorization", "").startswith("Bearer admin-")

    async def find_users(self, request: web.Request) -> web.Response:
        if not self._admin_ok(request):
            return web.Response(status=401)
        name = request.query.get("username")
        return web.json_response([{"id": uid, "username": u["username"]}
                                  for uid, u in self.users.items() if u["username"] == name])

    async def create_user(self, request: web.Request) -> web.Response:
        if not self._admin_ok(request):
            return web.Response(status=401)
        rep = await request.json()
        if any(u["username"] == rep["username"] for u in self.users.values()):
            return web.json_response({"errorMessage": "User exists"}, status=409)
        uid = str(uuid.uuid4())
        self.users[uid] = {"username": rep["username"], "attributes": rep.get("attributes", {}),
                           "links": {}}
        return web.Response(status=201, headers={"Location": f"{request.url}/{uid}"})

    async def links(self, request: web.Request) -> web.Response:
        user = self.users.get(request.match_info["id"])
        return web.json_response([{"identityProvider": a, "userId": v, "userName": user["username"]}
                                  for a, v in user["links"].items()])

    async def link(self, request: web.Request) -> web.Response:
        if not self._admin_ok(request):
            return web.Response(status=401)
        rep = await request.json()
        self.users[request.match_info["id"]]["links"][request.match_info["alias"]] = rep["userId"]
        return web.Response(status=204)
