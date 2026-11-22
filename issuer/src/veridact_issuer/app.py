"""The ACME-A issuer as an aiohttp application (specification v0.5).

ACME API (spec: Issuance protocol)        Published for relying parties
  GET  /directory                           GET /.well-known/jwt-vc-issuer/issuers/{name}   issuer keys
  HEAD /acme/new-nonce                      GET /agents/{slug}/{id}         Veridact-hosted agent CIMDs
  POST /acme/new-account                    GET /status/{kind}/{n}          Token Status Lists
  POST /acme/acct/{id}                      GET /assistants/{id}            known-assistant entries
  POST /acme/new-order                      GET /trust-list.jwt             staging trust list
  POST /acme/order/{id}                     GET /governance-keys.json       staging governance JWKs
  POST /acme/authz/{id}                     GET /log/entries                transparency log
  POST /acme/chall/{id}
  POST /acme/order/{id}/finalize
  POST /acme/cred/{id}                      (application/dc+sd-jwt)
  POST /acme/cred/{id}/attestation          (the Client Attestation form, when ordered)
  POST /acme/revoke-cred
  GET  /acme/renewal-info/{id}
  POST /acme/agent-metadata/{agent id}      (extension: upload a Veridact-hosted agent CIMD)
  POST /acme/key-event                      (extension: add, retire or compromise a key)
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
from veridact_verify import RoutedFetcher, jose, sdjwt
from veridact_verify import status as tsl
from veridact_verify.fetch import Fetcher, HttpFetcher
from veridact_verify.identifiers import (
    CLIENT_ATTESTATION_TYP,
    ISSUER_METADATA_WELL_KNOWN,
    VCT_AGENT,
    VCT_KNOWN_ASSISTANT,
    VCT_OPERATOR,
    IdentifierError,
    check_https_url,
    host_of,
    operator_url,
    parse_client_metadata,
    public_jwk,
)

from .acme import AcmeProblem, NonceStore, SignedRequest, jwk_thumbprint, verify_request
from .config import IssuerConfig
from .keys import IssuerIdentity, load_or_create_identity
from .publish import StatusLists, TransparencyLog, TrustListPublisher, iso
from .store import Store
from .validation import Delegation, TxtResolver, Validator, agent_id_of, check_dns_identifier

log = logging.getLogger("veridact.issuer")

ORDER_TTL = 3600
MAX_BODY = 64 * 1024
NO_STORE = {"Cache-Control": "no-store"}
FORMATS = ("dc+sd-jwt", "client-attestation")
KEY_ACTIONS = ("add", "retire", "compromise")
TIER_ORDER = ["domain", "organisation"]


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
        self.validator = Validator(config, fetcher, txt=txt, clock=clock, local=self.local_document)
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

    def hosted_path(self, slug: str, agent_id: str) -> str:
        return f"/agents/{slug}/{agent_id}"

    def local_document(self, url: str) -> bytes | None:
        """A Veridact-hosted CIMD, read from the store rather than over HTTP."""
        prefix = self.config.agent_hosting_url + "/"
        if not url.startswith(prefix):
            return None
        found = self.store.hosted_agent("/agents/" + url[len(prefix):])
        return found["doc"].encode() if found else b""

    # -- directory -------------------------------------------------------------------

    def directory(self) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "termsOfService": self.config.terms_of_service,
            "veridactSpecification": "0.5",
            "veridactTiers": list(self.config.tiers),
            "veridactEnvironment": self.config.environment,
            "veridactIssuer": self.identity.id,
            "veridactAgentHosting": self.config.agent_hosting_url,
            "veridactScopes": list(self.config.scopes),
            "veridactFormats": list(FORMATS),
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
            "veridactAgentMetadata": self.url("/acme/agent-metadata"),
            "veridactKeyEvent": self.url("/acme/key-event"),
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

    def operator_domains(self, account: dict[str, Any]) -> list[str]:
        return sorted({d for op in self.store.operator_credentials(account["id"], self.now())
                       for d in op["data"]["domains"]})

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
        formats = payload.get("formats", ["dc+sd-jwt"])
        if (not isinstance(formats, list) or "dc+sd-jwt" not in formats
                or not set(formats) <= set(FORMATS)):
            raise AcmeProblem("malformed", f"formats must include dc+sd-jwt; offered: {list(FORMATS)}")
        if itype == "dns":
            domain = check_dns_identifier(ident.get("value"))
            identifier = {"type": "dns", "value": domain}
            order = self.store.create_order(account["id"], "operator", identifier, now + ORDER_TTL,
                                            now, ["operator-keys-01", "dns-01"])
        elif itype == "agent":
            agent_url = ident.get("value")
            domains = self.operator_domains(account)
            if not domains:
                raise AcmeProblem("unauthorized",
                                  "this account holds no valid Operator Credential: order one first", 403)
            agent_id_of(agent_url, domains, account["slug"], self.config.agent_hosting_url)
            identifier = {"type": "agent", "value": agent_url}
            # One challenge: delegation-01. The agent key proof (client-metadata-01, the URL serves a
            # CIMD naming the key) runs inside it and again at finalize, against the key that signs.
            order = self.store.create_order(account["id"], "agent", identifier, now + ORDER_TTL,
                                            now, ["delegation-01"])
        else:
            raise AcmeProblem("unsupportedIdentifier",
                              "identifiers are dns (operators) or agent (an agent URL)")
        self.store.update_order(order["id"], "pending", tier=tier, lifetime=lifetime, formats=formats)
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
            if "client-attestation" in order["data"].get("formats", []):
                body["attestation"] = self.url(f"/acme/cred/{order['data']['credential']}/attestation")
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
            elif ch["type"] == "operator-keys-01":
                extra["operator_key"] = await self.validator.operator_keys01(ident["value"],
                                                                              payload.get("key"))
            elif ch["type"] == "delegation-01":
                await self.validator.client_keys(ident["value"])  # client-metadata-01
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
        agent_url = order["identifier"]["value"]
        try:
            iss = sdjwt.parse(token).jws.payload.get("iss") if isinstance(token, str) else None
        except sdjwt.SdJwtError:
            iss = None
        operator = self._operator_credential(account, iss)
        agent_id_of(agent_url, operator["data"]["domains"], account["slug"], self.config.agent_hosting_url)
        keys = await self.validator.operator_keys(host_of(operator["subject"]))
        return await self.validator.delegation01(token, agent_url, operator["subject"], order["data"]["tier"],
                                                 keys, self.key_is_logged)

    def _operator_credential(self, account: dict[str, Any], operator: Any) -> dict[str, Any]:
        for cred in self.store.operator_credentials(account["id"], self.now()):
            if cred["subject"] == operator:
                return cred
        raise AcmeProblem("unauthorized",
                          "the delegation's issuer has no valid Operator Credential on this account", 403)

    # -- key events ---------------------------------------------------------------------

    def key_is_logged(self, subject: str, jkt: str) -> bool:
        """True if the key has an add event and no later retire or compromise."""
        events = self.store.key_events(subject, jkt)
        return bool(events) and events[-1]["action"] == "add"

    def log_key_event(self, account: dict[str, Any], subject: str, jkt: str, action: str) -> str:
        """Append a key event to the transparency log, before it takes effect. Returns its entry id."""
        now = self.now()
        receipt = self.tlog.append(None, {"type": "key-event", "subject": subject, "jkt": jkt,
                                          "action": action, "time": iso(now)}, now)
        self.store.add_key_event(account["id"], subject, jkt, action, now, receipt["index"])
        log.info("key event", extra={"subject": subject, "jkt": jkt, "action": action})
        if action != "add":
            # No credential may outlive its key: revoke every one that names it.
            for cred in self.store.credentials_for_key(subject, jkt):
                self._revoke_row(cred, f"key {action}")
        return self.tlog.entry_id_for(receipt["index"])

    def ensure_key_logged(self, account: dict[str, Any], subject: str, jkt: str) -> str:
        events = self.store.key_events(subject, jkt)
        if events and events[-1]["action"] == "add":
            return self.tlog.entry_id_for(events[-1]["log_index"])
        if events:
            raise AcmeProblem("unauthorized", f"key {jkt} was {events[-1]['action']}d and cannot return", 403)
        return self.log_key_event(account, subject, jkt, "add")

    def key_event(self, account: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        subject, jkt, action = payload.get("subject"), payload.get("jkt"), payload.get("action")
        if action not in KEY_ACTIONS or not isinstance(jkt, str) or not jkt:
            raise AcmeProblem("malformed", "key-event needs subject, jkt and action (add, retire, compromise)")
        if not self._account_owns(account, subject):
            raise AcmeProblem("unauthorized", "that subject does not belong to this account", 403)
        if action == "add":
            entry = self.ensure_key_logged(account, subject, jkt)
        else:
            if not self.store.key_events(subject, jkt):
                raise AcmeProblem("malformed", "no such key for this subject")
            entry = self.log_key_event(account, subject, jkt, action)
        return {"subject": subject, "jkt": jkt, "action": action, "logEntry": entry}

    def _account_owns(self, account: dict[str, Any], subject: Any) -> bool:
        if not isinstance(subject, str):
            return False
        domains = self.operator_domains(account)
        if subject in [operator_url(d) for d in domains]:
            return True
        try:
            agent_id_of(subject, domains, account["slug"], self.config.agent_hosting_url)
            return True
        except AcmeProblem:
            return False

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
                operator = operator_url(domain)
                keys = await self.validator.operator_keys(domain)
                jkt = self.validator.key_binding(payload.get("keyBinding"), subject=operator, keys=keys,
                                                 finalize_url=finalize_url, request_nonce=req.nonce)
                named = authz["data"].get("operator_key")
                if named and named != jkt:
                    raise AcmeProblem("badCSR", "the key-binding key is not the key operator-keys-01 named")
                cred_id = self._issue_operator(account, order, operator, domain, keys[jkt])
            else:
                delegation = authz["data"]["delegation"]
                agent_url = order["identifier"]["value"]
                keys = await self.validator.client_keys(agent_url)
                jkt = self.validator.key_binding(payload.get("keyBinding"), subject=agent_url, keys=keys,
                                                 finalize_url=finalize_url, request_nonce=req.nonce)
                operator = self._operator_credential(account, delegation["operator"])
                cred_id = self._issue_agent(account, order, delegation, operator, keys[jkt])
        except AcmeProblem as problem:
            self.store.update_order(order["id"], "invalid", error=problem.body())
            raise
        self.store.update_order(order["id"], "valid", credential=cred_id)
        return self.store.order(order["id"])  # type: ignore[return-value]

    def _issue(self, account: dict[str, Any], kind: str, subject: str, vct: str,
               claims: dict[str, Any], disclosable: dict[str, Any], lifetime: int,
               log_entry: dict[str, Any], cnf_jkt: str | None) -> tuple[str, str, int, dict[str, Any]]:
        now = self.now()
        cred_uuid = str(uuid.uuid4())
        list_url, index = self.status.allocate(kind + "s")
        log_index = self.tlog.next_index()
        payload: dict[str, Any] = {
            "iss": self.identity.id,
            "vct": vct,
            "jti": f"urn:uuid:{cred_uuid}",
            "sub": subject,
            "iat": now, "nbf": now, "exp": now + lifetime,
            **claims,
            "status": tsl.ref_claim(index, list_url),
        }
        if kind == "operator":
            payload["log_entry"] = self.tlog.entry_id_for(log_index)
        token = sdjwt.issue({}, payload, disclosable, self.identity.signer.sign, decoys=2)
        # Logged before release (spec: Transparency log): the credential is only stored, and so
        # downloadable, once the log has it.
        receipt = self.tlog.append(token, {
            "issuer": self.identity.id, "subject": subject, "type": vct,
            "iat": now, "exp": now + lifetime, **log_entry,
        }, now, expect_index=log_index)
        self.store.add_credential(cred_uuid, account["id"], kind, subject, token, list_url, index,
                                  now, now + lifetime, receipt["index"], {"receipt": receipt, **log_entry},
                                  cnf_jkt=cnf_jkt)
        log.info("issued", extra={"credential": cred_uuid, "kind": kind, "subject": subject})
        return cred_uuid, list_url, index, payload

    def _issue_operator(self, account: dict[str, Any], order: dict[str, Any], operator: str,
                        domain: str, jwk: dict[str, Any]) -> str:
        tier = order["data"]["tier"]
        lifetime = self.config.operator_credential_lifetime[tier]
        jkt = jose.jwk_thumbprint(jwk)
        self.ensure_key_logged(account, operator, jkt)
        cred_id, *_ = self._issue(account, "operator", operator, VCT_OPERATOR,
                                  {"tier": tier, "domains": [domain], "cnf": {"jwk": public_jwk(jwk)}},
                                  {}, lifetime, {"domains": [domain], "tier": tier}, jkt)
        return cred_id

    def _issue_agent(self, account: dict[str, Any], order: dict[str, Any], delegation: dict[str, Any],
                     operator: dict[str, Any], jwk: dict[str, Any]) -> str:
        now = self.now()
        tier = order["data"]["tier"]
        operator_tier = operator["data"]["tier"]
        if TIER_ORDER.index(tier) > TIER_ORDER.index(operator_tier):
            raise AcmeProblem("unauthorized", "an agent's tier cannot rank above its operator's", 403)
        if delegation["valid_until"] <= now:
            raise AcmeProblem("unauthorized", "delegation has expired", 403)
        if not self.key_is_logged(delegation["operator"], delegation["operator_key"]):
            raise AcmeProblem("unauthorized", "the delegation's operator key is no longer logged as valid", 403)
        requested = order["data"].get("lifetime") or self.config.agent_credential_default_lifetime
        lifetime = min(requested, delegation["max_lifetime"], self.config.agent_credential_max_lifetime,
                       delegation["valid_until"] - now, operator["exp"] - now)
        if lifetime < 300:
            raise AcmeProblem("unauthorized",
                              "less than 5 minutes left on the delegation or the Operator Credential", 403)
        agent = delegation["agent"]
        jkt = jose.jwk_thumbprint(jwk)
        cnf_event = self.ensure_key_logged(account, agent, jkt)
        operator_claims = self._operator_payload(operator)
        claims: dict[str, Any] = {
            "operator": delegation["operator"],
            "operator_credential": f"urn:uuid:{operator['id']}",
            "operator_status": operator_claims["status"],
            "tier": tier,
            "scopes": delegation["scopes"],
            "accountable_role": delegation["accountable_role"],
            "cnf": {"jwk": public_jwk(jwk)},
            "cnf_event": cnf_event,
        }
        if delegation.get("limits"):
            claims["limits"] = delegation["limits"]
        # Operator facts a relying party may ask for (a consent screen), copied from the Operator
        # Credential and selectively disclosable. Domain-tier operators have none.
        disclosable = {f"operator_{k}": operator_claims[k]
                       for k in ("legal_name", "registration", "jurisdiction") if k in operator_claims}
        cred_id, list_url, index, payload = self._issue(
            account, "agent", agent, VCT_AGENT, claims, disclosable, lifetime,
            {"operator": delegation["operator"], "domains": operator["data"]["domains"], "tier": tier,
             "scopes": delegation["scopes"]}, jkt)
        if "client-attestation" in order["data"].get("formats", []):
            self._issue_attestation(cred_id, payload)
        return cred_id

    @staticmethod
    def _operator_payload(operator: dict[str, Any]) -> dict[str, Any]:
        return sdjwt.parse(operator["jwt"]).claims()

    def _issue_attestation(self, cred_id: str, agent_payload: dict[str, Any]) -> None:
        """The Client Attestation form (spec v0.5, 5.3): same sub, iat, exp, cnf and status as the
        Agent Credential, so revoking either revokes both, and logged with it."""
        p = agent_payload
        claims = {
            "iss": p["iss"], "sub": p["sub"], "iat": p["iat"], "exp": p["exp"],
            "cnf": p["cnf"], "status": p["status"],
            "veridact": {k: p[k] for k in ("operator", "tier", "scopes", "limits", "accountable_role",
                                            "operator_status") if k in p} | {"credential": p["jti"]},
        }
        token = self.identity.signer.sign({"typ": CLIENT_ATTESTATION_TYP}, claims)
        now = self.now()
        self.tlog.append(token, {"issuer": p["iss"], "subject": p["sub"], "type": CLIENT_ATTESTATION_TYP,
                                 "credential": p["jti"], "iat": p["iat"], "exp": p["exp"]}, now)
        self.store.update_credential_data(cred_id, attestation=token)

    # -- revocation and renewal ----------------------------------------------------------

    def _revoke_row(self, cred: dict[str, Any], reason: str) -> None:
        self.status.set_value(cred["status_list"], cred["status_index"], tsl.INVALID)
        self.store.mark_revoked(cred["id"], reason)
        # Re-sign now, so the revocation is visible well inside the 5-minute requirement.
        self.status.signed(cred["status_list"], self.now())
        log.info("revoked", extra={"credential": cred["id"], "reason": reason})

    def revoke(self, account: dict[str, Any], payload: dict[str, Any]) -> None:
        ref = payload.get("credential")
        if not isinstance(ref, str):
            raise AcmeProblem("malformed", "revoke-cred needs {\"credential\": <id or the SD-JWT>}")
        if "~" in ref:
            cred = self.store.credential_by_jwt(ref if ref.endswith("~") else ref + "~")
            if cred is None:
                try:
                    jti = sdjwt.parse(ref).jws.payload.get("jti", "")
                except sdjwt.SdJwtError:
                    jti = ""
                cred = self.store.credential(str(jti).removeprefix("urn:uuid:"))
        else:
            cred = self.store.credential(ref.removeprefix("urn:uuid:"))
        if cred is None or cred["account_id"] != account["id"]:
            raise AcmeProblem("unauthorized", "no such credential on this account", 403)
        if cred["revoked"]:
            raise AcmeProblem("alreadyRevoked", "credential is already revoked")
        reason = payload.get("reason", "unspecified")
        if not isinstance(reason, str) or len(reason) > 64:
            raise AcmeProblem("badRevocationReason", "reason must be a short string")
        self._revoke_row(cred, reason)

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

    # -- Veridact-hosted agents ---------------------------------------------------------------

    def host_agent(self, account: dict[str, Any], agent_id: str, payload: dict[str, Any]) -> str:
        """Store and serve an agent's CIMD at {agent_hosting_url}/{slug}/{agent_id}. Every key in it
        gets a logged add event; keys dropped since the last upload are retired (and their
        credentials revoked)."""
        doc = payload.get("metadata")
        if not isinstance(doc, dict):
            raise AcmeProblem("malformed", "upload needs {\"metadata\": <client metadata document>}")
        path = self.hosted_path(account["slug"], agent_id)
        client_id = self.url(path)
        agent_id_of(client_id, [], account["slug"], self.config.agent_hosting_url)
        body = json.dumps(doc, indent=2)
        if len(body) > 32 * 1024:
            raise AcmeProblem("malformed", "client metadata is too large")
        try:
            keys = parse_client_metadata(client_id, body.encode())
        except IdentifierError as err:
            raise AcmeProblem("malformed", f"client metadata: {err}") from None
        existing = self.store.hosted_agent(path)
        if existing is not None and existing["account_id"] != account["id"]:
            raise AcmeProblem("unauthorized", "that agent id is taken", 403)
        for jkt in keys:
            self.ensure_key_logged(account, client_id, jkt)
        if existing is not None:
            old = parse_client_metadata(client_id, existing["doc"].encode())
            for jkt in set(old) - set(keys):
                if self.key_is_logged(client_id, jkt):
                    self.log_key_event(account, client_id, jkt, "retire")
        self.store.put_hosted_agent(path, account["id"], client_id, body, self.now())
        return client_id

    # -- known-assistant entries --------------------------------------------------------------------

    def issue_known_assistant(self, entry_id: str, entry: dict[str, Any], *,
                              lifetime: int | None = None) -> str:
        """Issue (or reissue) a known-assistant entry (spec v0.5, section 6). Validation is
        documentary and done by a reviewer before this is called; Organisation tier only."""
        if "organisation" not in self.config.tiers:
            raise ValueError("known-assistant entries are Organisation tier: this issuer does not offer it")
        sub = entry.get("sub")
        if not isinstance(sub, str) or not sub:
            raise ValueError("an entry needs sub: a CIMD URL or a stable platform name")
        if sub.startswith("https://"):
            check_https_url(sub, what="sub")
        urls = entry.get("client_metadata_urls", [])
        if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
            raise ValueError("client_metadata_urls must be a list of URLs")
        operator = entry.get("operator")
        if not isinstance(operator, dict) or not isinstance(operator.get("name"), str):
            raise ValueError("operator needs at least a name")
        allowed = {"client_metadata_urls", "operator", "redirect_hosts", "token_endpoint_auth",
                   "published_egress", "max_level"}
        unknown = set(entry) - allowed - {"sub"}
        if unknown:
            raise ValueError(f"unknown entry claims: {sorted(unknown)}")
        now = self.now()
        lifetime = min(lifetime or self.config.known_assistant_lifetime, self.config.known_assistant_lifetime)
        existing = self.store.assistant(entry_id)
        if existing is not None:
            list_url, index = existing["status_list"], existing["status_index"]
        else:
            list_url, index = self.status.allocate("assistants")
        jti = f"urn:uuid:{uuid.uuid4()}"
        payload = {"iss": self.identity.id, "vct": VCT_KNOWN_ASSISTANT, "jti": jti, "sub": sub,
                   "iat": now, "nbf": now, "exp": now + lifetime,
                   **{k: v for k, v in entry.items() if k != "sub"},
                   "status": tsl.ref_claim(index, list_url)}
        token = sdjwt.issue({}, payload, {}, self.identity.signer.sign)
        self.tlog.append(token, {"issuer": self.identity.id, "subject": sub, "type": VCT_KNOWN_ASSISTANT,
                                 "operator": operator["name"], "iat": now, "exp": now + lifetime}, now)
        self.store.put_assistant(entry_id, sub, token, list_url, index, now, now + lifetime,
                                 {"entry": entry})
        return token

    def set_assistant_status(self, entry_id: str, value: int) -> None:
        """The kill switch: VALID, SUSPENDED or INVALID (withdrawn) for every relying party."""
        row = self.store.assistant(entry_id)
        if row is None:
            raise KeyError(entry_id)
        if value not in (tsl.VALID, tsl.INVALID, tsl.SUSPENDED):
            raise ValueError("status must be VALID, INVALID or SUSPENDED")
        if self.status.value(row["status_list"], row["status_index"]) == tsl.INVALID:
            raise ValueError("a withdrawn entry stays withdrawn: issue a new one")
        self.status.set_value(row["status_list"], row["status_index"], value)
        self.status.signed(row["status_list"], self.now())
        now = self.now()
        self.tlog.append(None, {"type": "assistant-status", "entry": entry_id, "subject": row["sub"],
                                "status": {0: "valid", 1: "withdrawn", 2: "suspended"}[value],
                                "time": iso(now)}, now)


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
        return web.Response(text=cred["jwt"], content_type="application/dc+sd-jwt", headers={
            "Replay-Nonce": issuer.nonces.issue(), "Link": directory_link,
            "Veridact-Log-Receipt": receipt, **NO_STORE})

    async def attestation(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        cred = issuer.owned("credential", issuer.store.credential(request.match_info["id"]), acct)
        token = cred["data"].get("attestation")
        if not token:
            raise AcmeProblem("malformed", "this credential was not ordered with the client-attestation format", 404)
        return web.Response(text=token, content_type="application/oauth-client-attestation+jwt", headers={
            "Replay-Nonce": issuer.nonces.issue(), "Link": directory_link, **NO_STORE})

    async def revoke(request: web.Request) -> web.Response:
        req = await signed(request)
        issuer.revoke(issuer.account_for(req), req.payload or {})
        return web.Response(status=200, headers={"Replay-Nonce": issuer.nonces.issue(), **NO_STORE})

    async def renewal_info(request: web.Request) -> web.Response:
        info = issuer.renewal_info(request.match_info["id"])
        return web.json_response(info, headers={"Retry-After": "3600"})

    async def upload_metadata(request: web.Request) -> web.Response:
        req = await signed(request)
        acct = issuer.account_for(req)
        client_id = issuer.host_agent(acct, request.match_info["agent"], req.payload or {})
        return acme_json({"client_id": client_id}, 201)

    async def key_event(request: web.Request) -> web.Response:
        req = await signed(request)
        return acme_json(issuer.key_event(issuer.account_for(req), req.payload or {}))

    # -- publication --------------------------------------------------------------------

    async def issuer_metadata(request: web.Request) -> web.Response:
        if request.match_info["name"] != issuer.config.issuer_name:
            raise web.HTTPNotFound()
        return web.json_response(issuer.identity.metadata(), headers={"Cache-Control": "public, max-age=300"})

    async def hosted_agent(request: web.Request) -> web.Response:
        found = issuer.store.hosted_agent(issuer.hosted_path(request.match_info["slug"],
                                                              request.match_info["agent"]))
        if found is None:
            raise web.HTTPNotFound()
        return web.Response(text=found["doc"], content_type="application/json",
                            headers={"Cache-Control": "public, max-age=60"})

    async def assistant(request: web.Request) -> web.Response:
        found = issuer.store.assistant(request.match_info["id"])
        if found is None:
            raise web.HTTPNotFound()
        return web.Response(text=found["credential"], content_type="application/dc+sd-jwt",
                            headers={"Cache-Control": "public, max-age=300"})

    async def assistants(request: web.Request) -> web.Response:
        return web.json_response({"entries": [
            {"id": row["id"], "sub": row["sub"], "url": issuer.url(f"/assistants/{row['id']}")}
            for row in issuer.store.assistants()]}, headers={"Cache-Control": "public, max-age=300"})

    async def status_list(request: web.Request) -> web.Response:
        url = issuer.url(request.path)
        jwt = issuer.status.signed(url, issuer.now())
        if jwt is None:
            raise web.HTTPNotFound()
        return web.Response(text=jwt, content_type="application/statuslist+jwt",
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
        return web.json_response({"status": "ok", "issuer": issuer.identity.id,
                                  "environment": issuer.config.environment})

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
        web.post("/acme/cred/{id}/attestation", attestation),
        web.post("/acme/revoke-cred", revoke),
        web.get("/acme/renewal-info/{id}", renewal_info),
        web.post("/acme/agent-metadata/{agent}", upload_metadata),
        web.post("/acme/key-event", key_event),
        web.get(ISSUER_METADATA_WELL_KNOWN + "/issuers/{name}", issuer_metadata),
        web.get("/agents/{slug}/{agent}", hosted_agent),
        web.get("/assistants", assistants),
        web.get("/assistants/{id}", assistant),
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
