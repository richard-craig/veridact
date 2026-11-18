"""A small ACME-A client (RFC 8555 plus the Veridact profile).

Requests are signed for the issuer's canonical URLs. ``routes`` lets development
setups send the bytes somewhere else (https://staging.veridact.test -> http://localhost:8080)
without changing what is signed.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Any, Callable

import aiohttp
from veridact_verify import jose
from veridact_verify.fetch import parse_routes, route_url

from .keys import SoftwareKey

JOSE = "application/jose+json"
PayloadFn = Callable[[str], dict[str, Any] | None]


class AcmeError(Exception):
    def __init__(self, status: int, problem: dict[str, Any]):
        self.status = status
        self.problem = problem
        kind = str(problem.get("type", "")).rsplit(":", 1)[-1]
        super().__init__(f"{kind or status}: {problem.get('detail', problem)}")

    @property
    def kind(self) -> str:
        return str(self.problem.get("type", "")).rsplit(":", 1)[-1]


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        return json.loads(self.body)


class AcmeClient:
    def __init__(self, directory_url: str, account_key: SoftwareKey, *,
                 routes: dict[str, str] | None = None, account_url: str | None = None,
                 session: aiohttp.ClientSession | None = None):
        self.directory_url = directory_url
        self.key = account_key
        self.routes = parse_routes(routes)
        self.account_url = account_url
        self._session = session
        self._own_session = session is None
        self._dir: dict[str, Any] | None = None
        self._nonce: str | None = None

    async def __aenter__(self) -> "AcmeClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        if self._own_session and self._session is not None:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30), headers={"User-Agent": "vbot/0.1"})
        return self._session

    def _route(self, url: str) -> str:
        return route_url(url, self.routes)

    async def directory(self) -> dict[str, Any]:
        if self._dir is None:
            async with self.session.get(self._route(self.directory_url)) as resp:
                if resp.status != 200:
                    raise AcmeError(resp.status, {"detail": f"directory returned {resp.status}"})
                self._dir = await resp.json(content_type=None)
        return self._dir

    async def _fresh_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        directory = await self.directory()
        async with self.session.head(self._route(directory["newNonce"])) as resp:
            return resp.headers["Replay-Nonce"]

    def _jws(self, url: str, nonce: str, payload: dict[str, Any] | None, use_jwk: bool) -> bytes:
        protected: dict[str, Any] = {"alg": "ES256", "nonce": nonce, "url": url}
        if use_jwk:
            protected["jwk"] = self.key.jwk
        else:
            if not self.account_url:
                raise RuntimeError("no account: register first")
            protected["kid"] = self.account_url
        p64 = jose.b64url_encode(json.dumps(protected, separators=(",", ":")).encode())
        b64 = "" if payload is None else jose.b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode())
        sig = self.key.sign_bytes(f"{p64}.{b64}".encode("ascii"))
        return json.dumps({"protected": p64, "payload": b64,
                           "signature": jose.b64url_encode(sig)}).encode()

    async def post(self, url: str, payload: dict[str, Any] | None | PayloadFn = None, *,
                   use_jwk: bool = False, expect: tuple[int, ...] = (200, 201)) -> Response:
        """Signed POST. ``payload`` may be a function of the nonce (for key-binding proofs).

        Retries once on badNonce, as RFC 8555 section 6.5 expects.
        """
        for attempt in (1, 2):
            nonce = await self._fresh_nonce()
            body_payload = payload(nonce) if callable(payload) else payload
            data = self._jws(url, nonce, body_payload, use_jwk)
            async with self.session.post(self._route(url), data=data,
                                         headers={"Content-Type": JOSE}) as resp:
                body = await resp.read()
                headers = {k: v for k, v in resp.headers.items()}
                self._nonce = resp.headers.get("Replay-Nonce")
                if resp.status in expect:
                    return Response(resp.status, headers, body)
                try:
                    problem = json.loads(body)
                except ValueError:
                    problem = {"detail": body.decode(errors="replace")[:200]}
                error = AcmeError(resp.status, problem)
                if error.kind == "badNonce" and attempt == 1:
                    continue
                raise error
        raise AssertionError("unreachable")

    # -- account ------------------------------------------------------------------

    async def register(self, contact: list[str] | None = None, *, agree_tos: bool = True) -> str:
        directory = await self.directory()
        payload: dict[str, Any] = {"termsOfServiceAgreed": agree_tos}
        if contact:
            payload["contact"] = contact
        resp = await self.post(directory["newAccount"], payload, use_jwk=True)
        self.account_url = resp.headers["Location"]
        self.account = resp.json()
        return self.account_url

    async def account_info(self) -> dict[str, Any]:
        assert self.account_url
        return (await self.post(self.account_url, None)).json()

    # -- orders -------------------------------------------------------------------

    async def new_order(self, identifier: dict[str, str], *, tier: str | None = None,
                        lifetime: int | None = None) -> tuple[str, dict[str, Any]]:
        directory = await self.directory()
        payload: dict[str, Any] = {"identifiers": [identifier]}
        if tier:
            payload["tier"] = tier
        if lifetime:
            payload["lifetime"] = lifetime
        resp = await self.post(directory["newOrder"], payload)
        return resp.headers["Location"], resp.json()

    async def get(self, url: str) -> dict[str, Any]:
        return (await self.post(url, None)).json()

    async def respond(self, challenge_url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return (await self.post(challenge_url, payload or {})).json()

    async def wait_ready(self, order_url: str, timeout: float = 30) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            order = await self.get(order_url)
            if order["status"] in ("ready", "valid", "invalid"):
                return order
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError(f"order still {order['status']}")
            await asyncio.sleep(1)

    async def finalize(self, order: dict[str, Any], key_binding: Callable[[str], str]) -> dict[str, Any]:
        """``key_binding(nonce)`` returns the key-binding JWT for this request's nonce."""
        url = order["finalize"]
        return (await self.post(url, lambda nonce: {"keyBinding": key_binding(nonce)})).json()

    async def download(self, credential_url: str) -> tuple[str, dict[str, Any]]:
        resp = await self.post(credential_url, None)
        receipt_b64 = resp.headers.get("Veridact-Log-Receipt", "")
        receipt = json.loads(base64.urlsafe_b64decode(receipt_b64 + "=" * (-len(receipt_b64) % 4))) \
            if receipt_b64 else {}
        return resp.body.decode(), receipt

    async def revoke(self, credential: str, reason: str = "unspecified") -> None:
        directory = await self.directory()
        await self.post(directory["revokeCred"], {"credential": credential, "reason": reason})

    async def renewal_info(self, credential_id: str) -> dict[str, Any]:
        directory = await self.directory()
        url = f"{directory['renewalInfo']}/{credential_id.removeprefix('urn:uuid:')}"
        async with self.session.get(self._route(url)) as resp:
            if resp.status != 200:
                raise AcmeError(resp.status, {"detail": "renewal-info unavailable"})
            return await resp.json(content_type=None)

    async def upload_did(self, agent_id: str, did_log: str) -> str:
        directory = await self.directory()
        resp = await self.post(f"{directory['veridactDidHosting']}/{agent_id}", {"log": did_log})
        return resp.json()["did"]
