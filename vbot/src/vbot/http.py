"""Calling a Veridact-protected API (spec: Verification, pattern B).

The API answers 401 with ``WWW-Authenticate: Veridact realm=…, nonce=…``. vbot signs a
presentation (an SD-JWT+KB) for that nonce and retries with
``Authorization: Veridact sd-jwt="…"``. A ``disclose`` parameter in the challenge names the
selectively disclosable claims the API needs; vbot discloses those and nothing else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from veridact_verify.fetch import parse_routes, route_url

from .core import Vbot

_PARAM = re.compile(r'(\w+)="([^"]*)"')


def parse_challenge(header: str | None) -> dict[str, str] | None:
    """Parameters of a ``Veridact`` WWW-Authenticate challenge, or None."""
    if not header:
        return None
    for challenge in re.split(r",\s*(?=Veridact\b)", header):
        scheme, _, rest = challenge.strip().partition(" ")
        if scheme.lower() == "veridact":
            params = dict(_PARAM.findall(rest))
            return params if params.get("nonce") else None
    return None


def audience_for(url: str) -> str:
    """The aud an agent signs for: the API's origin."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass
class CallResult:
    status: int
    headers: dict[str, str]
    body: bytes
    challenge: dict[str, str] | None

    def json(self) -> Any:
        import json
        return json.loads(self.body)


async def call(bot: Vbot, url: str, *, agent_id: str, method: str = "GET",
               json_body: Any = None, routes: dict[str, str] | None = None,
               session: aiohttp.ClientSession | None = None) -> CallResult:
    routes = parse_routes(routes if routes is not None else bot.state.get("routes"))
    own = session is None
    session = session or aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30),
                                               headers={"User-Agent": "vbot/0.1"})
    target = route_url(url, routes)
    try:
        async with session.request(method, target, json=json_body) as resp:
            body = await resp.read()
            challenge = parse_challenge(resp.headers.get("WWW-Authenticate"))
            if resp.status != 401 or challenge is None:
                return CallResult(resp.status, dict(resp.headers), body, None)
        disclose = challenge.get("disclose", "").split()
        auth = bot.authorization(agent_id, aud=audience_for(url), nonce=challenge["nonce"], disclose=disclose)
        async with session.request(method, target, json=json_body,
                                   headers={"Authorization": auth}) as resp:
            return CallResult(resp.status, dict(resp.headers), await resp.read(), challenge)
    finally:
        if own:
            await session.close()


# -- pattern A: token exchange --------------------------------------------------------------

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
SD_JWT_KB_TOKEN_TYPE = "urn:veridact:params:oauth:token-type:sd-jwt-kb"


def dpop_proof(bot: Vbot, agent_id: str, *, method: str, url: str,
               access_token: str | None = None) -> str:
    """A DPoP proof (RFC 9449) made with the agent's Veridact key."""
    import hashlib
    import time
    import uuid

    from veridact_verify import jose

    key = bot.keys.get(f"agent-{agent_id}")
    claims = {"jti": str(uuid.uuid4()), "htm": method.upper(), "htu": url.split("?")[0].split("#")[0],
              "iat": int(time.time())}
    if access_token:
        claims["ath"] = jose.b64url_encode(hashlib.sha256(access_token.encode()).digest())
    return key.sign({"typ": "dpop+jwt", "jwk": jose.key_to_jwk(key.public_key())}, claims)


@dataclass
class TokenResult:
    status: int
    body: dict[str, Any]

    @property
    def access_token(self) -> str | None:
        return self.body.get("access_token")


async def exchange(bot: Vbot, bridge_url: str, *, agent_id: str, scopes: list[str] | None = None,
                   routes: dict[str, str] | None = None,
                   session: aiohttp.ClientSession | None = None) -> TokenResult:
    """Trade a presentation for an access token at a Veridact token-exchange endpoint.

    ``bridge_url`` is the endpoint's origin; its metadata says where the token endpoint is and
    which URL DPoP proofs must name.
    """
    routes = parse_routes(routes if routes is not None else bot.state.get("routes"))
    own = session is None
    session = session or aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30),
                                               headers={"User-Agent": "vbot/0.1"})
    try:
        meta_url = bridge_url.rstrip("/") + "/.well-known/veridact-bridge"
        async with session.get(route_url(meta_url, routes)) as resp:
            if resp.status != 200:
                return TokenResult(resp.status, {"error": "no bridge metadata"})
            meta = await resp.json(content_type=None)
        token_url = route_url(meta["token_endpoint"], routes)
        form = {"grant_type": TOKEN_EXCHANGE}
        if scopes:
            form["scope"] = " ".join(scopes)
        async with session.post(token_url, data=form) as resp:
            nonce = resp.headers.get("Veridact-Nonce")
            if not nonce:
                return TokenResult(resp.status, await resp.json(content_type=None))
        disclose = meta.get("veridact_disclose")
        presentation = bot.presentation(agent_id, aud=meta["veridact_audience"], nonce=nonce,
                                        disclose=disclose if isinstance(disclose, list) else [])
        form.update(subject_token=presentation, subject_token_type=SD_JWT_KB_TOKEN_TYPE)
        headers = {"DPoP": dpop_proof(bot, agent_id, method="POST", url=meta["dpop_htu"])}
        async with session.post(token_url, data=form, headers=headers) as resp:
            return TokenResult(resp.status, await resp.json(content_type=None))
    finally:
        if own:
            await session.close()
