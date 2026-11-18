"""API Gateway (REST) Lambda authoriser for Veridact pattern B.

    no Authorization: Veridact header  ->  Deny + a fresh challenge
    valid presentation for this route  ->  Allow, with the agent's identity in the context
    anything else                      ->  Deny + the public code

API Gateway turns a Deny into its ACCESS_DENIED gateway response. The SAM template
sets that response to 401 and maps ``WWW-Authenticate`` and the body from the
authoriser's context, so the agent receives a proper ``Veridact`` challenge.

Environment:
  VERIDACT_CONFIG_JSON   relying-party config (audience, governance_keys, trust_list_url, ...)
                         or VERIDACT_CONFIG (a file path), or the VERIDACT_* variables
  VERIDACT_ROUTES        {"GET /claims/{id}/status": {"scopes": [...], "risk": "low"}, ...}
  VERIDACT_NONCE_TABLE   DynamoDB table for nonces (required with more than one instance,
                         which on Lambda means always)
  VERIDACT_REALM         realm in the challenge (default: the API id)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from veridact_sidecar import VerifierConfig, parse_request
from veridact_verify import Outcome, PublicCode, Request, Verifier

from .nonces import DynamoNonceStore

log = logging.getLogger("veridact.authoriser")
log.setLevel(logging.INFO)

CHALLENGE_CODES = {PublicCode.CHALLENGE_REQUIRED, PublicCode.CREDENTIAL_EXPIRED}


class Routes:
    """Which scopes and risk each route needs. Unlisted routes are denied (fail closed)."""

    def __init__(self, raw: dict[str, Any]):
        self.routes: dict[str, Request] = {}
        for key, spec in raw.items():
            method, _, path = key.strip().partition(" ")
            if key != "default" and (not method or not path.startswith("/")):
                raise ValueError(f"route keys look like 'GET /claims/{{id}}/status', got {key!r}")
            self.routes[key if key == "default" else f"{method.upper()} {path}"] = parse_request(spec)

    def match(self, method: str, resource: str) -> Request | None:
        return (self.routes.get(f"{method.upper()} {resource}")
                or self.routes.get(f"ANY {resource}")
                or self.routes.get("default"))


class Authoriser:
    """Built once per Lambda container, so caches stay warm across invocations."""

    def __init__(self, config: VerifierConfig, routes: Routes, *, nonces: Any = None,
                 realm: str | None = None, verifier: Verifier | None = None):
        self.routes = routes
        self.realm = realm
        self.verifier = verifier or config.build(nonces=nonces)
        self.loop = asyncio.new_event_loop()

    @classmethod
    def from_env(cls) -> "Authoriser":
        raw = os.environ.get("VERIDACT_CONFIG_JSON")
        config = VerifierConfig.from_dict(json.loads(raw)) if raw else VerifierConfig.from_env()
        routes = Routes(json.loads(os.environ.get("VERIDACT_ROUTES", "{}")))
        table = os.environ.get("VERIDACT_NONCE_TABLE")
        nonces = DynamoNonceStore(table) if table else None
        if nonces is None:
            log.warning("VERIDACT_NONCE_TABLE is not set: nonces are per instance, so challenges "
                        "will fail whenever API Gateway routes the retry to another instance")
        return cls(config, routes, nonces=nonces, realm=os.environ.get("VERIDACT_REALM"))

    def __call__(self, event: dict[str, Any]) -> dict[str, Any]:
        method_arn = event.get("methodArn", "")
        method = event.get("httpMethod", "")
        resource = event.get("resource", "")
        realm = self.realm or event.get("requestContext", {}).get("apiId") or "api"
        request = self.routes.match(method, resource)
        if request is None:
            log.info(json.dumps({"decision": "deny", "reason": "ROUTE_NOT_CONFIGURED",
                                 "route": f"{method} {resource}"}))
            return _deny(method_arn, "deny", PublicCode.AUTH_FAILED.value)

        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        vp = Verifier.presentation_from_authorization(headers.get("authorization"))
        if vp is None:
            _, challenge = self.verifier.challenge(request, realm=realm)
            return _deny(method_arn, "challenge", PublicCode.CHALLENGE_REQUIRED.value, challenge)

        decision = self.loop.run_until_complete(self.verifier.verify(vp, request))
        record = decision.log_record()
        record["route"] = f"{method} {resource}"
        log.info(json.dumps(record))

        if decision.allowed:
            return {
                "principalId": decision.agent,
                "policyDocument": _policy("Allow", method_arn),
                # Context values must be strings, numbers or booleans. The integration reads them
                # as $context.authorizer.<key>, or event.requestContext.authorizer in Lambda.
                "context": {
                    "veridactAgent": decision.agent or "",
                    "veridactOperator": decision.operator or "",
                    "veridactOperatorDomains": " ".join(decision.operator_domains),
                    "veridactTier": decision.tier or "",
                    "veridactScopes": " ".join(decision.scopes_granted),
                    "veridactAgentKeyId": decision.agent_key_id or "",
                    "veridactAccountableRole": decision.accountable_role or "",
                    "veridactAgentCredential": decision.agent_credential_id or "",
                    "veridactAgentCredentialExpires": decision.agent_credential_expires or 0,
                    "veridactFlags": " ".join(decision.flags),
                },
            }
        code = decision.public_code.value if decision.public_code else PublicCode.AUTH_FAILED.value
        challenge = None
        if decision.public_code in CHALLENGE_CODES or decision.outcome is Outcome.CHALLENGE:
            _, challenge = self.verifier.challenge(request, realm=realm)
        return _deny(method_arn, decision.outcome.value, code, challenge)


def _policy(effect: str, method_arn: str) -> dict[str, Any]:
    return {"Version": "2012-10-17",
            "Statement": [{"Action": "execute-api:Invoke", "Effect": effect, "Resource": method_arn}]}


def _deny(method_arn: str, decision: str, code: str, challenge: str | None = None) -> dict[str, Any]:
    return {
        "principalId": "veridact-unverified",
        "policyDocument": _policy("Deny", method_arn),
        "context": {"decision": decision, "code": code, "wwwAuthenticate": challenge or ""},
    }


_authoriser: Authoriser | None = None


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    global _authoriser
    if _authoriser is None:
        _authoriser = Authoriser.from_env()
    return _authoriser(event)
