"""The ACME-A issuer as an aiohttp application.

ACME API (spec: Issuance protocol)        Published for relying parties
  GET  /directory                           GET /issuers/{name}/did.jsonl   issuer DID log
  HEAD /acme/new-nonce                      GET /dids/{slug}/{id}/did.jsonl Veridact-hosted agent DIDs
  POST /acme/new-account                    GET /status/{kind}/{n}          status lists (vc+jwt)
  POST /acme/acct/{id}                      GET /trust-list.jwt             staging trust list
  POST /acme/new-order                      GET /governance-keys.json       staging governance JWKs
  POST /acme/order/{id}                     GET /log/entries                transparency log
  POST /acme/authz/{id}
  POST /acme/chall/{id}
  POST /acme/order/{id}/finalize
  POST /acme/cred/{id}
  POST /acme/revoke-cred
  GET  /acme/renewal-info/{id}
  POST /acme/did/{agent id}                 (extension: upload a Veridact-hosted agent DID log)
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import time
import uuid
from typing import Any, Callable

from aiohttp import web
from veridact_verify import RoutedFetcher, StaticFetcher, jose
from veridact_verify.did import DidError, WebvhResolver
from veridact_verify.fetch import ArtefactCache, Fetcher, HttpFetcher

from .acme import AcmeProblem, NonceStore, SignedRequest, jwk_thumbprint, verify_request
from .config import IssuerConfig
from .keys import IssuerIdentity, load_or_create_identity
from .publish import StatusLists, TransparencyLog, TrustListPublisher, iso
from .store import Store
from veridact_verify.did import ASSERTION_METHOD, AUTHENTICATION

from .validation import (
    Delegation,
    TxtResolver,
    Validator,
    check_dns_identifier,
    did_segments,
    hosted_did_path,
    is_operator_did_for,
)

log = logging.getLogger("veridact.issuer")

VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://veridact.net/ns/v1"]
ORDER_TTL = 3600
MAX_BODY = 64 * 1024
NO_STORE = {"Cache-Control": "no-store"}


class Issuer:
    """Issuance logic, independent of HTTP."""

    def __init__(self, config: IssuerConfig, *, identity: IssuerIdentity | None = None,
                 store: Store | None = None, fetcher: Fetcher | None = None,
                 txt: TxtResolver | None = None, clock: Callable[[], float] = time.time):
        self.config = config
        self.clock = clock
        self.identity = identity or load_or_create_identity(config, now=clock())
        self.store = store or Store(config.data_path / "issuer.sqlite3")
        if fetcher is None:
            fetcher = RoutedFetcher(config.routes) if config.routes else HttpFetcher()
        self.fetcher = fetcher
        self.validator = Validator(config, fetcher, txt=txt, clock=clock)
        self.nonces = NonceStore(clock=clock)
        self.status = StatusLists(config, self.identity, self.store)
        self.tlog = TransparencyLog(self.store)
        self.trust = TrustListPublisher(config, self.identity) if config.publish_trust_list else None

    def now(self) -> int:
        return int(self.clock())

    # -- URLs ----------------------------------------------------------------------

    def url(self, path: str) -> str:
        return self.config.base_url + path

    def account_url(self, account_id: str) -> str:
        return self.url(f"/acme/acct/{account_id}")

    def account_id_from_kid(self, kid: str) -> str | None:
        prefix = self.url("/acme/acct/")
        return kid[len(prefix):] if kid.startswith(prefix) else None

    def account_jwk(self, kid: str) -> dict[str, str] | None:
        account_id = self.account_id_from_kid(kid)
        account = self.store.account(account_id) if account_id else None
        if account is None or account["status"] != "valid":
            return None
        return json.loads(account["jwk"])

    # -- directory -------------------------------------------------------------------

    def directory(self) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "termsOfService": self.config.terms_of_service,
            "veridactTiers": list(self.config.tiers),
            "veridactEnvironment": self.config.environment,
            "veridactIssuer": self.identity.did,
            "veridactHostedDidPrefix": self.config.hosted_did_prefix,
            "veridactScopes": list(self.config.scopes),
        }
        if self.trust is not None:
            meta["trustList"] = self.config.trust_list_url
            meta["governanceKeys"] = self.url("/governance-keys.json")
        return {
            "newNonce": self.url("/acme/new-nonce"),
            "newAccount": self.url("/acme/new-account"),
            "newOrder": self.url("/acme/new-order"),
            "revokeCred": self.url("/acme/revoke-cred"),
            "renewalInfo": self.url("/acme/renewal-info"),
            "veridactDidHosting": self.url("/acme/did"),
            "meta": meta,
        }

    # -- accounts --------------------------------------------------------------------

    def new_account(self, req: SignedRequest) -> tuple[dict[str, Any], bool]:
        payload = req.payload or {}
        assert req.jwk is not None
        thumbprint = jwk_thumbprint(req.jwk)
        existing = self.store.account_by_thumbprint(thumbprint)
        if existing is not None:
            if existing["status"] != "valid":
                raise AcmeProblem("unauthorized", "account is deactivated", 403)
            return existing, False
        if payload.get("onlyReturnExisting"):
            raise AcmeProblem("accountDoesNotExist", "no account for this key")
        if payload.get("termsOfServiceAgreed") is not True:
            raise AcmeProblem("userActionRequired", "agree to the terms of service",
                              instance=self.config.terms_of_service)
        contact = payload.get("contact") or []
        if not isinstance(contact, list) or not all(
                isinstance(c, str) and c.startswith("mailto:") for c in contact):
            raise AcmeProblem("invalidContact", "contact must be a list of mailto: URLs")
        return self.store.create_account(req.jwk, thumbprint, contact, self.now()), True

    def account_object(self, account: dict[str, Any]) -> dict[str, Any]:
        return {"status": account["status"], "contact": json.loads(account["contact"] or "[]"),
                "orders": self.url(f"/acme/acct/{account['id']}/orders"),
                "veridactSlug": account["slug"]}

    def account_for(self, req: SignedRequest) -> dict[str, Any]:
        account_id = self.account_id_from_kid(req.kid or "")
        account = self.store.account(account_id) if account_id else None
        if account is None or account["status"] != "valid":
            raise AcmeProblem("unauthorized", "no valid account", 403)
        return account

    # -- orders ----------------------------------------------------------------------

    def new_order(self, account: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        now = self.now()
        if self.store.orders_since(account["id"], now - 3600) >= self.config.orders_per_hour:
            raise AcmeProblem("rateLimited", "too many orders this hour", 429)
        identifiers = payload.get("identifiers")
        if not isinstance(identifiers, list) or len(identifiers) != 1 or not isinstance(identifiers[0], dict):
            raise AcmeProblem("malformed", "an order names exactly one identifier")
        ident = identifiers[0]
        itype = ident.get("type")
        tier = payload.get("tier", self.config.tiers[0])
        if tier not in self.config.tiers:
            raise AcmeProblem("rejectedIdentifier", f"this issuer offers tiers {list(self.config.tiers)}")
        lifetime = payload.get("lifetime")
        if lifetime is not None and (not isinstance(lifetime, int) or isinstance(lifetime, bool)
                                     or lifetime < 300):
            raise AcmeProblem("malformed", "lifetime must be an integer number of seconds, at least 300")
        if itype == "dns":
            domain = check_dns_identifier(ident.get("value"))
            identifier = {"type": "dns", "value": domain}
            order = self.store.create_order(account["id"], "operator", identifier, now + ORDER_TTL,
                                            now, ["did-config-01", "dns-01"])
        elif itype == "agent-did":
            agent_did = ident.get("value")
            if not isinstance(agent_did, str):
                raise AcmeProblem("rejectedIdentifier", "agent-did value must be a DID")
            did_segments(agent_did)
            operators = self.store.operator_credentials(account["id"], now)
            if not operators:
                raise AcmeProblem("unauthorized",
                                  "this account holds no valid Operator Credential: order one first", 403)
            domains = sorted({d for op in operators for d in op["data"]["domains"]})
            self.validator.check_agent_location(agent_did, domains, account["slug"])
            identifier = {"type": "agent-did", "value": agent_did}
            order = self.store.create_order(account["id"], "agent", identifier, now + ORDER_TTL,
                                            now, ["delegation-01"])
        else:
            raise AcmeProblem("unsupportedIdentifier", "identifiers are dns (operators) or agent-did")
        self.store.update_order(order["id"], "pending", tier=tier, lifetime=lifetime)
        return self.store.order(order["id"])  # type: ignore[return-value]

    def owned(self, kind: str, obj: dict[str, Any] | None, account: dict[str, Any]) -> dict[str, Any]:
        if obj is None or obj["account_id"] != account["id"]:
            raise AcmeProblem("malformed", f"no such {kind}", 404)
        return obj

    def order_object(self, order: dict[str, Any]) -> dict[str, Any]:
        self._expire(order)
        body: dict[str, Any] = {
            "status": order["status"],
            "expires": iso(order["expires"]),
            "identifiers": [order["identifier"]],
            "authorizations": [self.url(f"/acme/authz/{a}") for a in order["data"]["authorizations"]],
            "finalize": self.url(f"/acme/order/{order['id']}/finalize"),
        }
        if order["data"].get("credential"):
            body["credential"] = self.url(f"/acme/cred/{order['data']['credential']}")
        if order["data"].get("error"):
            body["error"] = order["data"]["error"]
        return body

    def _expire(self, order: dict[str, Any]) -> None:
        if order["status"] in ("pending", "ready") and order["expires"] <= self.now():
            self.store.update_order(order["id"], "invalid", error={"type": "urn:ietf:params:acme:error:malformed",
                                                                    "detail": "order expired"})
            order["status"] = "invalid"

    def authz_object(self, authz: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": authz["status"],
            "expires": iso(authz["expires"]),
            "identifier": authz["identifier"],
            "challenges": [self.challenge_object(c) for c in self.store.challenges_for(authz["id"])],
        }

    def challenge_object(self, ch: dict[str, Any]) -> dict[str, Any]:
        body = {"type": ch["type"], "url": self.url(f"/acme/chall/{ch['id']}"),
                "status": ch["status"], "token": ch["token"]}
        if ch["data"].get("validated"):
            body["validated"] = iso(ch["data"]["validated"])
        if ch["data"].get("error"):
            body["error"] = ch["data"]["error"]
        return body

    # -- challenges --------------------------------------------------------------------

    async def respond_to_challenge(self, account: dict[str, Any], ch: dict[str, Any],
                                   payload: dict[str, Any]) -> dict[str, Any]:
        authz = self.store.authz(ch["authz_id"])
        order = self.store.order(authz["order_id"]) if authz else None
        if authz is None or order is None:
            raise AcmeProblem("malformed", "no such challenge", 404)
        self._expire(order)
        if ch["status"] != "pending" or authz["status"] != "pending" or order["status"] != "pending":
            return self.store.challenge(ch["id"])  # type: ignore[return-value]
        ident = authz["identifier"]
        try:
            extra: dict[str, Any] = {}
            if ch["type"] == "dns-01":
                await self.validator.dns01(ident["value"], ch["token"], json.loads(account["jwk"]))
            elif ch["type"] == "did-config-01":
                want = payload.get("did")
                extra["did"] = await self.validator.did_config01(
                    ident["value"], want if isinstance(want, str) else None)
            elif ch["type"] == "delegation-01":
                delegation = await self._delegation(account, order, payload.get("delegation"))
                extra["delegation"] = delegation.to_json()
            else:  # pragma: no cover
                raise AcmeProblem("malformed", "unknown challenge type")
        except AcmeProblem as problem:
            error = problem.body()
            self.store.update_challenge(ch["id"], "invalid", error=error)
            self.store.update_authz(authz["id"], "invalid")
            self.store.update_order(order["id"], "invalid", error=error)
            log.info("challenge failed", extra={"challenge": ch["type"], "detail": problem.detail})
            return self.store.challenge(ch["id"])  # type: ignore[return-value]
        self.store.update_challenge(ch["id"], "valid", validated=self.now())
        self.store.update_authz(authz["id"], "valid", **extra)
        self.store.update_order(order["id"], "ready")
        return self.store.challenge(ch["id"])  # type: ignore[return-value]

    async def _delegation(self, account: dict[str, Any], order: dict[str, Any], token: Any) -> Delegation:
        agent_did = order["identifier"]["value"]
        try:
            operator_did = jose.parse(token).payload.get("issuer") if isinstance(token, str) else None
        except jose.JoseError:
            operator_did = None
        operator = self._operator_credential(account, operator_did)
        self.validator.check_agent_location(agent_did, operator["data"]["domains"], account["slug"])
        return await self.validator.delegation01(token, agent_did, operator["subject"],
                                                 order["data"]["tier"])

    def _operator_credential(self, account: dict[str, Any], operator_did: Any) -> dict[str, Any]:
        for cred in self.store.operator_credentials(account["id"], self.now()):
            if cred["subject"] == operator_did:
                return cred
        raise AcmeProblem("unauthorized",
                          "the delegation's issuer has no valid Operator Credential on this account", 403)

    # -- finalize and issuance ----------------------------------------------------------

    async def finalize(self, account: dict[str, Any], order: dict[str, Any], req: SignedRequest) -> dict[str, Any]:
        self._expire(order)
        if order["status"] != "ready":
            raise AcmeProblem("orderNotReady", f"order is {order['status']}", 403)
        authz = self.store.authz(order["data"]["authorizations"][0])
        assert authz is not None
        payload = req.payload or {}
        finalize_url = self.url(f"/acme/order/{order['id']}/finalize")
        try:
            if order["kind"] == "operator":
                domain = order["identifier"]["value"]
                operator_did = authz["data"].get("did") or self._kb_issuer(payload.get("keyBinding"))
                if not isinstance(operator_did, str) or not is_operator_did_for(operator_did, domain):
                    raise AcmeProblem("badCSR", f"the operator DID must be did:webvh:{{SCID}}:{domain}")
                await self.validator.key_binding(
                    payload.get("keyBinding"), subject_did=operator_did, relationship=ASSERTION_METHOD,
                    finalize_url=finalize_url, request_nonce=req.nonce)
                cred_id = self._issue_operator(account, order, operator_did, domain)
            else:
                delegation = authz["data"]["delegation"]
                agent_did = order["identifier"]["value"]
                kid = await self.validator.key_binding(
                    payload.get("keyBinding"), subject_did=agent_did, relationship=AUTHENTICATION,
                    finalize_url=finalize_url, request_nonce=req.nonce)
                operator = self._operator_credential(account, delegation["operator"])
                cred_id = self._issue_agent(account, order, delegation, operator, kid)
        except AcmeProblem as problem:
            self.store.update_order(order["id"], "invalid", error=problem.body())
            raise
        self.store.update_order(order["id"], "valid", credential=cred_id)
        return self.store.order(order["id"])  # type: ignore[return-value]

    @staticmethod
    def _kb_issuer(token: Any) -> str | None:
        try:
            return jose.parse(token).payload.get("iss") if isinstance(token, str) else None
        except jose.JoseError:
            return None

    def _issue(self, account: dict[str, Any], kind: str, subject_did: str, credential_type: str,
               subject: dict[str, Any], lifetime: int, log_entry: dict[str, Any]) -> str:
        now = self.now()
        cred_uuid = str(uuid.uuid4())
        list_url, index = self.status.allocate("operators" if kind == "operator" else "agents")
        log_index = self.tlog.next_index()
        if kind == "operator":
            subject = {**subject, "transparencyLogEntry": self.tlog.entry_id_for(log_index)}
        payload = {
            "@context": VC_CONTEXT,
            "id": f"urn:uuid:{cred_uuid}",
            "type": ["VerifiableCredential", credential_type],
            "issuer": self.identity.did,
            "validFrom": iso(now),
            "validUntil": iso(now + lifetime),
            "iat": now,
            "exp": now + lifetime,
            "credentialSubject": subject,
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": str(index),
                "statusListCredential": list_url,
            },
        }
        jwt = self.identity.signer.sign({"typ": "vc+jwt"}, payload)
        # Logged before release (spec: Transparency log): the credential is only stored,
        # and so downloadable, once the log has it.
        receipt = self.tlog.append(jwt, {
            "issuer": self.identity.did, "subject": subject_did, "type": credential_type,
            "validFrom": payload["validFrom"], "validUntil": payload["validUntil"], **log_entry,
        }, now, expect_index=log_index)
        self.store.add_credential(cred_uuid, account["id"], kind, subject_did, jwt, list_url, index,
                                  now, now + lifetime, receipt["index"],
                                  {"receipt": receipt, **log_entry})
        log.info("issued", extra={"credential": cred_uuid, "kind": kind, "subject": subject_did})
        return cred_uuid

    def _issue_operator(self, account: dict[str, Any], order: dict[str, Any], operator_did: str,
                        domain: str) -> str:
        tier = order["data"]["tier"]
        lifetime = self.config.operator_credential_lifetime[tier]
        subject = {"id": operator_did, "domains": [domain], "tier": tier}
        return self._issue(account, "operator", operator_did, "VeridactOperatorCredential", subject,
                           lifetime, {"domains": [domain], "tier": tier})

    def _issue_agent(self, account: dict[str, Any], order: dict[str, Any], delegation: dict[str, Any],
                     operator: dict[str, Any], kid: str) -> str:
        now = self.now()
        tier = order["data"]["tier"]
        operator_tier = operator["data"]["tier"]
        tiers = ["domain", "organisation"]
        if tiers.index(tier) > tiers.index(operator_tier):
            raise AcmeProblem("unauthorized", "an agent's tier cannot rank above its operator's", 403)
        if delegation["validUntil"] <= now:
            raise AcmeProblem("unauthorized", "delegation has expired", 403)
        requested = order["data"].get("lifetime") or self.config.agent_credential_default_lifetime
        lifetime = min(requested, delegation["maxLifetime"], self.config.agent_credential_max_lifetime,
                       delegation["validUntil"] - now, operator["exp"] - now)
        if lifetime < 300:
            raise AcmeProblem("unauthorized",
                              "less than 5 minutes left on the delegation or the Operator Credential", 403)
        operator_cred_id = f"urn:uuid:{operator['id']}"
        subject: dict[str, Any] = {
            "id": delegation["agent"],
            "operator": delegation["operator"],
            "operatorCredential": operator_cred_id,
            "tier": tier,
            "scopes": delegation["scopes"],
            "accountableRole": delegation["accountableRole"],
            "cnf": {"kid": kid},
        }
        if delegation.get("limits"):
            subject["limits"] = delegation["limits"]
        return self._issue(account, "agent", delegation["agent"], "VeridactAgentCredential", subject,
                           lifetime, {"operator": delegation["operator"],
                                      "domains": operator["data"]["domains"], "tier": tier,
                                      "scopes": delegation["scopes"]})

    # -- revocation and renewal ----------------------------------------------------------

    def revoke(self, account: dict[str, Any], payload: dict[str, Any]) -> None:
        ref = payload.get("credential")
        if not isinstance(ref, str):
            raise AcmeProblem("malformed", "revoke-cred needs {\"credential\": <id or vc+jwt>}")
        cred = None
        if ref.count(".") == 2:
            cred = self.store.credential_by_jwt(ref)
        else:
            cred = self.store.credential(ref.removeprefix("urn:uuid:"))
        if cred is None or cred["account_id"] != account["id"]:
            raise AcmeProblem("unauthorized", "no such credential on this account", 403)
        if cred["revoked"]:
            raise AcmeProblem("alreadyRevoked", "credential is already revoked")
        reason = payload.get("reason", "unspecified")
        if not isinstance(reason, str) or len(reason) > 64:
            raise AcmeProblem("badRevocationReason", "reason must be a short string")
        self.status.set_bit(cred["status_list"], cred["status_index"])
        self.store.mark_revoked(cred["id"], reason)
        # Re-sign now, so the revocation is visible well inside the 5-minute requirement.
        self.status.signed(cred["status_list"], self.now())
        log.info("revoked", extra={"credential": cred["id"], "reason": reason})

    def renewal_info(self, cred_id: str) -> dict[str, Any]:
        cred = self.store.credential(cred_id.removeprefix("urn:uuid:"))
        if cred is None:
            raise AcmeProblem("malformed", "no such credential", 404)
        lifetime = cred["exp"] - cred["iat"]
        start = cred["iat"] + (2 * lifetime) // 3
        end = cred["iat"] + (5 * lifetime) // 6
        if cred["revoked"]:
            start, end = self.now() - 60, self.now()
        return {"suggestedWindow": {"start": iso(start), "end": iso(end)}}

    # -- Veridact-hosted DIDs ---------------------------------------------------------------

    async def host_did(self, account: dict[str, Any], agent_id: str, payload: dict[str, Any]) -> str:
        did_log = payload.get("log")
        if not isinstance(did_log, str) or len(did_log) > 256 * 1024:
            raise AcmeProblem("malformed", "upload needs {\"log\": <did.jsonl contents>}")
        did_log = did_log if did_log.endswith("\n") else did_log + "\n"
        path = hosted_did_path(self.config.hosted_did_prefix, account["slug"], agent_id)
        log_url = self.url(path + "/did.jsonl")
        try:
            first = json.loads(did_log.splitlines()[0])
            did = first["state"]["id"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AcmeProblem("malformed", "not a did:webvh log") from None
        self.validator.check_agent_location(did, [], account["slug"])
        if did_segments(did)[-1] != agent_id:
            raise AcmeProblem("malformed", "the DID's agent id does not match the upload path")
        resolver = WebvhResolver(StaticFetcher({log_url: did_log}), ArtefactCache(self.clock), ttl=0)
        try:
            await resolver.resolve(did)
        except DidError as err:
            raise AcmeProblem("malformed", f"DID log does not verify: {err}") from None
        existing = self.store.hosted_did(path)
        if existing is not None:
            if existing["account_id"] != account["id"] or existing["did"] != did:
                raise AcmeProblem("unauthorized", "that agent id is taken", 403)
            if not did_log.startswith(existing["log"]):
                raise AcmeProblem("malformed", "a DID log can only be extended, never rewritten")
        self.store.put_hosted_did(path, account["id"], did, did_log, self.now())
        return did


# =========================================================================================
# HTTP layer
# =========================================================================================

def _problem_response(problem: AcmeProblem, nonce: str | None) -> web.Response:
    headers = {**NO_STORE}
    if nonce:
        headers["Replay-Nonce"] = nonce
    return web.json_response(problem.body(), status=problem.status, headers=headers,
                             content_type="application/problem+json")


def create_app(issuer: Issuer, *, background: bool = True) -> web.Application:
    app = web.Application(client_max_size=MAX_BODY)
    app["issuer"] = issuer
    directory_link = f'<{issuer.url("/directory")}>;rel="index"'

    def acme_json(body: Any, status: int = 200, location: str | None = None) -> web.Response:
        headers = {"Replay-Nonce": issuer.nonces.issue(), "Link": directory_link, **NO_STORE}
        if location:
            headers["Location"] = location
        return web.json_response(body, status=status, headers=headers)

    @web.middleware
    async def problems(request: web.Request, handler):
        try:
            return await handler(request)
        except AcmeProblem as problem:
            return _problem_response(problem, issuer.nonces.issue())

    app.middlewares.append(problems)

    async def signed(request: web.Request, *, require_jwk: bool = False) -> SignedRequest:
        if request.content_type != "application/jose+json":
            raise AcmeProblem("malformed", "Content-Type must be application/jose+json", 415)
        body = await request.read()
        return verify_request(body, issuer.url(request.path), issuer.nonces, issuer.account_jwk,
                              require_jwk=require_jwk)

    # -- ACME ------------------------------------------------------------------------

    async def directory(request: web.Request) -> web.Response:
        return web.json_response(issuer.directory())

    async def new_nonce(request: web.Request) -> web.Response:
        status = 204 if request.method == "GET" else 200
        return web.Response(status=status, headers={"Replay-Nonce": issuer.nonces.issue(),
                                                    "Link": directory_link, **NO_STORE})

    async def new_account(request: web.Request) -> web.Response:
        req = await signed(request, require_jwk=True)
        account, created = issuer.new_account(req)
        return acme_json(issuer.account_object(account), 201 if created else 200,
                         issuer.account_url(account["id"]))

    async def account(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        if acct["id"] != request.match_info["id"]:
            raise AcmeProblem("unauthorized", "not your account", 403)
        if (req.payload or {}).get("status") == "deactivated":
            issuer.store.deactivate_account(acct["id"])
            acct = issuer.store.account(acct["id"])
        return acme_json(issuer.account_object(acct))

    async def new_order(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        order = issuer.new_order(acct, req.payload or {})
        return acme_json(issuer.order_object(order), 201, issuer.url(f"/acme/order/{order['id']}"))

    async def order(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        found = issuer.owned("order", issuer.store.order(request.match_info["id"]), acct)
        return acme_json(issuer.order_object(found))

    async def authz(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        found = issuer.owned("authorization", issuer.store.authz(request.match_info["id"]), acct)
        return acme_json(issuer.authz_object(found))

    async def challenge(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        ch = issuer.owned("challenge", issuer.store.challenge(request.match_info["id"]), acct)
        if req.payload is not None:
            ch = await issuer.respond_to_challenge(acct, ch, req.payload)
        authz_url = issuer.url(f"/acme/authz/{ch['authz_id']}")
        resp = acme_json(issuer.challenge_object(ch))
        resp.headers.add("Link", f'<{authz_url}>;rel="up"')
        return resp

    async def finalize(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        found = issuer.owned("order", issuer.store.order(request.match_info["id"]), acct)
        done = await issuer.finalize(acct, found, req)
        return acme_json(issuer.order_object(done), 200, issuer.url(f"/acme/order/{done['id']}"))

    async def credential(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        cred = issuer.owned("credential", issuer.store.credential(request.match_info["id"]), acct)
        receipt = base64.urlsafe_b64encode(
            json.dumps(cred["data"]["receipt"], separators=(",", ":")).encode()).rstrip(b"=").decode()
        return web.Response(text=cred["jwt"], content_type="application/vc+jwt", headers={
            "Replay-Nonce": issuer.nonces.issue(), "Link": directory_link,
            "Veridact-Log-Receipt": receipt, **NO_STORE})

    async def revoke(request: web.Request) -> web.Response:
        req = await signed(request)
        issuer.revoke(issuer.account_for(req), req.payload or {})
        return web.Response(status=200, headers={"Replay-Nonce": issuer.nonces.issue(), **NO_STORE})

    async def renewal_info(request: web.Request) -> web.Response:
        info = issuer.renewal_info(request.match_info["id"])
        return web.json_response(info, headers={"Retry-After": "3600"})

    async def upload_did(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        did = await issuer.host_did(acct, request.match_info["agent"], req.payload or {})
        return acme_json({"did": did}, 201)

    # -- publication --------------------------------------------------------------------

    async def issuer_did(request: web.Request) -> web.Response:
        if request.match_info["name"] != issuer.config.issuer_name:
            raise web.HTTPNotFound()
        return web.Response(text=issuer.identity.did_log, content_type="application/jsonl",
                            headers={"Cache-Control": "public, max-age=300"})

    async def hosted_did(request: web.Request) -> web.Response:
        path = hosted_did_path(issuer.config.hosted_did_prefix, request.match_info["slug"],
                               request.match_info["agent"])
        found = issuer.store.hosted_did(path)
        if found is None:
            raise web.HTTPNotFound()
        return web.Response(text=found["log"], content_type="application/jsonl",
                            headers={"Cache-Control": "public, max-age=60"})

    async def status_list(request: web.Request) -> web.Response:
        url = issuer.url(request.path)
        jwt = issuer.status.signed(url, issuer.now())
        if jwt is None:
            raise web.HTTPNotFound()
        return web.Response(text=jwt, content_type="application/vc+jwt",
                            headers={"Cache-Control": "public, max-age=60"})

    async def trust_list(request: web.Request) -> web.Response:
        if issuer.trust is None:
            raise web.HTTPNotFound()
        return web.Response(text=issuer.trust.signed(issuer.now()), content_type="application/jwt",
                            headers={"Cache-Control": "public, max-age=300"})

    async def governance_keys(request: web.Request) -> web.Response:
        if issuer.trust is None:
            raise web.HTTPNotFound()
        return web.json_response({"warning": "staging only: production keys are distributed out of band",
                                  "keys": issuer.identity.governance_jwks})

    async def log_entries(request: web.Request) -> web.Response:
        try:
            start = max(1, int(request.query.get("start", "1")))
            count = min(1000, max(1, int(request.query.get("count", "100"))))
        except ValueError:
            raise web.HTTPBadRequest(text="start and count must be integers") from None
        rows = issuer.store.tlog_range(start, count)
        return web.json_response({"log": TransparencyLog.LOG_ID, "entries": [
            {"index": r["idx"], "leafHash": r["leaf_hash"], "chainHash": r["chain_hash"],
             "entry": r["entry"]} for r in rows]})

    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "issuer": issuer.identity.did,
                                  "environment": issuer.config.environment})

    hosted_root = "/" + "/".join(issuer.config.hosted_did_prefix.split(":")[1:])
    app.add_routes([
        web.get("/directory", directory),
        web.head("/acme/new-nonce", new_nonce), web.get("/acme/new-nonce", new_nonce, allow_head=False),
        web.post("/acme/new-account", new_account),
        web.post("/acme/acct/{id}", account),
        web.post("/acme/new-order", new_order),
        web.post("/acme/order/{id}", order),
        web.post("/acme/order/{id}/finalize", finalize),
        web.post("/acme/authz/{id}", authz),
        web.post("/acme/chall/{id}", challenge),
        web.post("/acme/cred/{id}", credential),
        web.post("/acme/revoke-cred", revoke),
        web.get("/acme/renewal-info/{id}", renewal_info),
        web.post("/acme/did/{agent}", upload_did),
        web.get("/issuers/{name}/did.jsonl", issuer_did),
        web.get(hosted_root + "/{slug}/{agent}/did.jsonl", hosted_did),
        web.get("/status/{kind}/{n}", status_list),
        web.get("/trust-list.jwt", trust_list),
        web.get("/governance-keys.json", governance_keys),
        web.get("/log/entries", log_entries),
        web.get("/healthz", healthz),
    ])

    if background:
        async def refresher(app: web.Application):
            async def loop():
                while True:
                    await asyncio.sleep(60)
                    try:
                        issuer.status.refresh_all(issuer.now())
                    except Exception:  # keep re-signing whatever one failure was
                        log.exception("status list refresh failed")
            task = asyncio.create_task(loop())
            yield
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        app.cleanup_ctx.append(refresher)

    async def close(app: web.Application):
        close_fetcher = getattr(issuer.fetcher, "close", None)
        if close_fetcher:
            await close_fetcher()
    app.on_cleanup.append(close)
    return app
