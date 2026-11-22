"""The Veridact verifier as an HTTP sidecar, for stacks that are not Python.

    POST /v1/challenge   {"scopes": [...], "risk": "low", "minTier": "domain", "realm": "claims-api"}
                      -> {"nonce": "...", "wwwAuthenticate": "Veridact realm=..., nonce=..."}
    POST /v1/verify      {"authorization": "Veridact sd-jwt=\"...\"" | "presentation": "<SD-JWT+KB>",
                          "scopes": [...], "risk": "...", "disclose": [...],
                          "payment": {"amount", "currency", "spentToday"}}
                      -> {"decision": "allow"|"deny"|"ask_person"|"challenge", "code": ..., "public": {...},
                          "agent", "operator", "scopesGranted", "agentKeyId", "disclosed", ..., "log": {...}}
    POST /v1/client-attestation
                         {"attestation": "<Client Attestation>", "clientId": "...", "dpopJkt": "...",
                          "scopes": [...], ...}   (pattern C: check the DPoP proof yourself first)
    POST /v1/known-assistant
                         {"entry": "<known-assistant SD-JWT VC>", "clientId": "..."}
                      -> {"decision", ..., "operator": "<verified operator name>", "maxLevel": ...}
    GET  /healthz

The response's ``public`` object is what you may pass back to the caller. Everything else,
``log`` above all, stays in your logs. Run it next to your gateway or authorisation server,
bound to localhost or a private network: it trusts whoever can reach it.
"""

from __future__ import annotations

import hmac
import json
import logging
import time

from aiohttp import web
from veridact_verify import Verifier

from .config import ConfigError, VerifierConfig, decision_body, parse_request

log = logging.getLogger("veridact.sidecar")
MAX_BODY = 128 * 1024


def create_app(config: VerifierConfig, *, verifier: Verifier | None = None,
               api_token: str | None = None) -> web.Application:
    verifier = verifier or config.build()
    app = web.Application(client_max_size=MAX_BODY)
    app["verifier"] = verifier

    @web.middleware
    async def guard(request: web.Request, handler):
        if api_token and request.path != "/healthz":
            supplied = request.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {api_token}".encode()):
                return web.json_response({"error": "unauthorized"}, status=401)
        try:
            return await handler(request)
        except ConfigError as err:
            return web.json_response({"error": str(err)}, status=400)

    app.middlewares.append(guard)

    async def body(request: web.Request) -> dict:
        try:
            data = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ConfigError("body must be JSON") from None
        if not isinstance(data, dict):
            raise ConfigError("body must be a JSON object")
        return data

    async def challenge(request: web.Request) -> web.Response:
        data = await body(request)
        realm = data.get("realm")
        nonce, header = verifier.challenge(parse_request(data),
                                           realm=realm if isinstance(realm, str) else None)
        return web.json_response({"nonce": nonce, "wwwAuthenticate": header})

    async def verify(request: web.Request) -> web.Response:
        data = await body(request)
        vp = data.get("presentation")
        if vp is None:
            vp = Verifier.presentation_from_authorization(data.get("authorization"))
        if not isinstance(vp, str) or not vp:
            raise ConfigError("give presentation (an SD-JWT+KB) or authorization (the header value)")
        started = time.perf_counter()
        decision = await verifier.verify(vp, parse_request(data))
        return respond(decision, started)

    def respond(decision, started: float, **extra) -> web.Response:
        record = decision.log_record()
        record["ms"] = round((time.perf_counter() - started) * 1000, 1)
        log.info(json.dumps(record))
        return web.json_response({**decision_body(decision), **extra, "public": decision.public()})

    def text(data: dict, name: str) -> str:
        value = data.get(name)
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{name} is required")
        return value

    async def client_attestation(request: web.Request) -> web.Response:
        data = await body(request)
        started = time.perf_counter()
        decision = await verifier.verify_client_attestation(
            text(data, "attestation"), client_id=text(data, "clientId"), dpop_jkt=text(data, "dpopJkt"),
            request=parse_request(data))
        return respond(decision, started)

    async def known_assistant(request: web.Request) -> web.Response:
        data = await body(request)
        started = time.perf_counter()
        decision = await verifier.verify_known_assistant(text(data, "entry"), client_id=text(data, "clientId"))
        ctx = decision.context
        return respond(decision, started, platform=ctx.get("platform"), maxLevel=ctx.get("maxLevel"),
                       operatorDetails=ctx.get("operator"))

    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "audience": config.audience})

    app.add_routes([
        web.post("/v1/challenge", challenge),
        web.post("/v1/verify", verify),
        web.post("/v1/client-attestation", client_attestation),
        web.post("/v1/known-assistant", known_assistant),
        web.get("/healthz", healthz),
    ])

    async def close(app: web.Application):
        fetcher_close = getattr(verifier.fetcher, "close", None)
        if fetcher_close:
            await fetcher_close()
    app.on_cleanup.append(close)
    return app
