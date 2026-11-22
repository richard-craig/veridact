"""Veridact Insurance: a sandbox relying party for trying agents against.

    GET  /claims/{id}/status   fs:claims:read-status   low risk
    POST /quotes               fs:quotes:create        medium risk
    POST /payments             fs:payments:initiate    high risk, delegation limits apply

A real relying party returns only the public decision. The sandbox also returns the
full explanation (``explain``) and a hint, because its job is to teach. Never copy
that part into production: it tells an attacker which check failed.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from aiohttp import web
from veridact_sidecar import VerifierConfig
from veridact_verify import Outcome, Payment, PublicCode, Request, Risk, Verifier

CLAIMS = {
    "CLM-1001": {"status": "approved", "payout": "4200.00", "currency": "ZAR"},
    "CLM-1002": {"status": "in_review", "assessor": "Assessment team B"},
    "CLM-1003": {"status": "awaiting_documents", "missing": ["police case number"]},
}

HINTS = {
    PublicCode.CHALLENGE_REQUIRED: "Fetch a new challenge: the nonce was missing, used or expired.",
    PublicCode.CREDENTIAL_EXPIRED: "Renew: `vbot issue`, or leave `vbot run` going.",
    PublicCode.ISSUER_UNTRUSTED: "This sandbox trusts the staging trust list only.",
    PublicCode.TIER_TOO_LOW: "This route needs a higher tier.",
    PublicCode.OPERATOR_NOT_ALLOWED: "This relying party has not onboarded your operator.",
    PublicCode.SCOPE_NOT_HELD: "Delegate the scope: `vbot delegate --scope ...`, then `vbot issue`.",
    PublicCode.LIMIT_PER_PAYMENT: "Over the per-payment limit: a person must approve this one.",
    PublicCode.LIMIT_PER_DAY: "Over the daily limit: a person must approve this one.",
    PublicCode.VERIFICATION_UNAVAILABLE: "Something the verifier needs could not be fetched. Retry.",
    PublicCode.AUTH_FAILED: "A signature, binding or status check failed (revoked credentials land "
                            "here too). See explain.detail.",
}

STATUS = {
    PublicCode.CHALLENGE_REQUIRED: 401,
    PublicCode.CREDENTIAL_EXPIRED: 401,
    PublicCode.AUTH_FAILED: 401,
    PublicCode.VERIFICATION_UNAVAILABLE: 503,
}


class Ledger:
    """What each agent has paid today. A relying party keeps this; the verifier keeps no money state."""

    def __init__(self) -> None:
        self._spent: dict[tuple[str, str, str], Decimal] = defaultdict(Decimal)

    @staticmethod
    def _day() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def spent(self, agent: str, currency: str) -> Decimal:
        return self._spent[(agent, currency, self._day())]

    def add(self, agent: str, currency: str, amount: Decimal) -> None:
        self._spent[(agent, currency, self._day())] += amount


def create_app(config: VerifierConfig, *, verifier: Verifier | None = None,
               realm: str = "veridact-insurance-sandbox") -> web.Application:
    verifier = verifier or config.build()
    ledger = Ledger()
    app = web.Application(client_max_size=32 * 1024)
    app["verifier"] = verifier
    app["ledger"] = ledger

    def challenge_response(request_spec: Request, status: int = 401,
                           extra: dict[str, Any] | None = None) -> web.Response:
        _, header = verifier.challenge(request_spec, realm=realm)
        body = {"decision": "challenge", "code": "CHALLENGE_REQUIRED",
                "hint": "Sign a presentation for this nonce and retry with Authorization: Veridact sd-jwt=\"...\". "
                        "`vbot call <url>` does it for you.", **(extra or {})}
        return web.json_response(body, status=status, headers={"WWW-Authenticate": header})

    async def guarded(request: web.Request, spec: Request,
                      payment_of: Any = None) -> tuple[Any, web.Response | None]:
        vp = Verifier.presentation_from_authorization(request.headers.get("Authorization"))
        if vp is None:
            return None, challenge_response(spec)
        if payment_of is not None:
            spec = Request(scopes=spec.scopes, risk=spec.risk, min_tier=spec.min_tier,
                           payment=payment_of)
        started = time.perf_counter()
        decision = await verifier.verify(vp, spec)
        explain = {**decision.log_record(), "ms": round((time.perf_counter() - started) * 1000, 1)}
        if decision.allowed:
            return decision, None
        code = decision.public_code
        body = {**decision.public(), "hint": HINTS.get(code, ""), "explain": explain}
        if decision.outcome is Outcome.ASK_PERSON:
            body["intent"] = decision.context.get("intent")
            return decision, web.json_response(body, status=403)
        if code is PublicCode.CHALLENGE_REQUIRED or code is PublicCode.CREDENTIAL_EXPIRED:
            return decision, challenge_response(spec, extra={k: v for k, v in body.items()
                                                             if k not in ("decision", "code")}
                                                | {"code": code.value})
        return decision, web.json_response(body, status=STATUS.get(code, 403))

    def allowed_body(decision, data: dict[str, Any]) -> dict[str, Any]:
        return {"decision": "allow", "data": data, "explain": {
            "agent": decision.agent, "operator": decision.operator,
            "operatorDomains": decision.operator_domains, "tier": decision.tier,
            "accountableRole": decision.accountable_role, "scopesGranted": decision.scopes_granted,
            "flags": decision.flags}}

    async def index(request: web.Request) -> web.Response:
        return web.json_response({
            "name": "Veridact Insurance (sandbox relying party)",
            "audience": config.audience,
            "trustList": config.trust_list_url,
            "routes": {
                "GET /claims/{id}/status": {"scope": "fs:claims:read-status", "risk": "low",
                                            "try": sorted(CLAIMS)},
                "POST /quotes": {"scope": "fs:quotes:create", "risk": "medium",
                                 "body": {"product": "car", "value": "250000.00"}},
                "POST /payments": {"scope": "fs:payments:initiate", "risk": "high",
                                   "body": {"amount": "350.00", "currency": "ZAR", "claim": "CLM-1001"}},
            },
            "howTo": "vbot call " + config.audience + "/claims/CLM-1001/status",
        })

    async def claim_status(request: web.Request) -> web.Response:
        spec = Request(scopes=frozenset({"fs:claims:read-status"}), risk=Risk.LOW)
        decision, denied = await guarded(request, spec)
        if denied:
            return denied
        claim_id = request.match_info["id"]
        claim = CLAIMS.get(claim_id)
        if claim is None:
            return web.json_response({"error": f"no claim {claim_id}"}, status=404)
        return web.json_response(allowed_body(decision, {"claim": claim_id, **claim}))

    async def quotes(request: web.Request) -> web.Response:
        spec = Request(scopes=frozenset({"fs:quotes:create"}), risk=Risk.MEDIUM)
        decision, denied = await guarded(request, spec)
        if denied:
            return denied
        data = await _json(request)
        try:
            value = Decimal(str(data.get("value", "200000.00")))
        except InvalidOperation:
            return web.json_response({"error": "value must be a decimal"}, status=400)
        premium = (value * Decimal("0.0042")).quantize(Decimal("0.01"))
        return web.json_response(allowed_body(decision, {
            "quote": f"Q-{int(time.time())}", "product": data.get("product", "car"),
            "monthlyPremium": str(premium), "currency": "ZAR"}), status=201)

    async def payments(request: web.Request) -> web.Response:
        data = await _json(request)
        try:
            amount = Decimal(str(data["amount"]))
            currency = str(data.get("currency", "ZAR"))
        except (KeyError, InvalidOperation):
            return web.json_response({"error": "amount (decimal string) is required"}, status=400)
        spec = Request(scopes=frozenset({"fs:payments:initiate"}), risk=Risk.HIGH)
        vp = Verifier.presentation_from_authorization(request.headers.get("Authorization"))
        if vp is None:
            return challenge_response(spec)
        # The ledger is keyed by agent, which only the verified presentation tells us. Peek at the
        # credential's subject to look up what was spent; verification below still checks everything.
        holder = _holder(vp)
        payment = Payment(amount, currency, ledger.spent(holder, currency) if holder else Decimal(0))
        decision, denied = await guarded(request, spec, payment_of=payment)
        if denied:
            return denied
        ledger.add(decision.agent, currency, amount)
        return web.json_response(allowed_body(decision, {
            "payment": f"P-{int(time.time() * 1000)}", "amount": str(amount), "currency": currency,
            "claim": data.get("claim"), "spentToday": str(ledger.spent(decision.agent, currency))}),
            status=201)

    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    app.add_routes([
        web.get("/", index),
        web.get("/claims/{id}/status", claim_status),
        web.post("/quotes", quotes),
        web.post("/payments", payments),
        web.get("/healthz", healthz),
    ])

    async def close(app: web.Application):
        fetcher_close = getattr(verifier.fetcher, "close", None)
        if fetcher_close:
            await fetcher_close()
    app.on_cleanup.append(close)
    return app


async def _json(request: web.Request) -> dict[str, Any]:
    if not request.can_read_body:
        return {}
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _holder(presentation: str) -> str | None:
    from veridact_verify import sdjwt
    try:
        holder = sdjwt.parse(presentation).jws.payload.get("sub")
    except sdjwt.SdJwtError:
        return None
    return holder if isinstance(holder, str) else None
