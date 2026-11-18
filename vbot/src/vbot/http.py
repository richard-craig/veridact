"""Calling a Veridact-protected API (spec: Verification, pattern B).

The API answers 401 with ``WWW-Authenticate: Veridact realm=…, nonce=…``. vbot signs a
presentation for that nonce and retries with ``Authorization: Veridact vp="…"``.
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
        auth = bot.authorization(agent_id, aud=audience_for(url), nonce=challenge["nonce"])
        async with session.request(method, target, json=json_body,
                                   headers={"Authorization": auth}) as resp:
            return CallResult(resp.status, dict(resp.headers), await resp.read(), challenge)
    finally:
        if own:
            await session.close()
