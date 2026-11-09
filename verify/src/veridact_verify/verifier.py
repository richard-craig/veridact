"""The Veridact presentation verifier.

Runs the eight checks from the spec's "Verification at the relying party" section,
in order, and stops at the first failure. With a warm cache it makes no network
calls.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from . import jose
from .codes import Outcome, Reason
from .decision import Decision, Failure
from .did import (
    ASSERTION_METHOD,
    AUTHENTICATION,
    DidError,
    DidUnavailable,
    WebvhResolver,
    split_did_url,
)
from .fetch import ArtefactCache, Clock, Fetcher, FetchError, HttpFetcher
from .nonce import InMemoryNonceStore, NonceStore
from .policy import RelyingPartyPolicy, Request
from .status import StatusError, StatusList, StatusLists, parse_entries
from .trust import DEFAULT_TRUST_LIST_URL, TrustList, TrustRegistry

VP_TYP = "vp+jwt"
VC_TYP = "vc+jwt"
VC_DATA_PREFIX = "data:application/vc+jwt,"
AGENT_CREDENTIAL = "VeridactAgentCredential"
OPERATOR_CREDENTIAL = "VeridactOperatorCredential"
PRESENTATION_MAX_LIFETIME = 120


def _issuer_of(vc: dict[str, Any]) -> str | None:
    issuer = vc.get("issuer")
    if isinstance(issuer, dict):
        issuer = issuer.get("id")
    return issuer if isinstance(issuer, str) else None


def _types(obj: dict[str, Any]) -> list[str]:
    t = obj.get("type")
    return [t] if isinstance(t, str) else [x for x in (t or []) if isinstance(x, str)]


def _epoch(value: Any) -> int:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return int(dt.timestamp())


def _int_claim(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


class _Credential:
    def __init__(self, jws: jose.CompactJws, kind: str):
        self.jws = jws
        self.kind = kind
        self.vc = jws.payload
        self.issuer = _issuer_of(jws.payload)
        subject = jws.payload.get("credentialSubject")
        self.subject: dict[str, Any] = subject if isinstance(subject, dict) else {}

    @property
    def tier(self) -> str | None:
        tier = self.subject.get("tier")
        return tier if isinstance(tier, str) else None


class Verifier:
    """Verifies Veridact agent presentations for one relying party.

    ``governance_keys`` maps governance key ids to public JWKs and is the only
    trust anchor. Everything else is fetched, verified and cached.
    """

    def __init__(
        self,
        policy: RelyingPartyPolicy,
        *,
        governance_keys: dict[str, dict],
        fetcher: Fetcher | None = None,
        nonces: NonceStore | None = None,
        clock: Clock = time.time,
        trust_list_url: str = DEFAULT_TRUST_LIST_URL,
        did_ttl: float = 300.0,
        status_ttl: float = 300.0,
        trust_ttl: float = 3600.0,
    ):
        self.policy = policy
        self.clock = clock
        self.fetcher = fetcher or HttpFetcher()
        self.cache = ArtefactCache(clock)
        self.nonces = nonces or InMemoryNonceStore(ttl=PRESENTATION_MAX_LIFETIME, clock=clock)
        stale = policy.degraded_mode.stale_limit_seconds
        self.dids = WebvhResolver(self.fetcher, self.cache, ttl=did_ttl, max_stale=stale)
        self.trust = TrustRegistry(
            self.fetcher, self.cache, governance_keys, url=trust_list_url, ttl=trust_ttl
        )
        self.status = StatusLists(self.fetcher, self.cache, ttl=status_ttl, max_stale=stale)

    # -- challenges (pattern B) ------------------------------------------------

    def challenge(self, request: Request | None = None, *, realm: str | None = None) -> tuple[str, str]:
        """Issue a nonce; return it and a WWW-Authenticate header value."""
        request = request or Request()
        nonce = self.nonces.issue()
        parts = [f'realm="{realm or self.policy.audience}"', f'nonce="{nonce}"',
                 f'tier="{request.min_tier or self.policy.min_tier}"']
        if request.scopes:
            parts.append(f'scope="{" ".join(sorted(request.scopes))}"')
        return nonce, "Veridact " + ", ".join(parts)

    @staticmethod
    def presentation_from_authorization(header: str | None) -> str | None:
        """Extract the VP-JWT from 'Authorization: Veridact vp="<VP-JWT>"'."""
        if not header:
            return None
        scheme, _, rest = header.strip().partition(" ")
        if scheme.lower() != "veridact":
            return None
        rest = rest.strip()
        if rest.startswith('vp="') and rest.endswith('"') and rest.count('"') == 2:
            return rest[4:-1]
        return None

    # -- verification ------------------------------------------------------------

    def verify_sync(self, presentation: str, request: Request | None = None) -> Decision:
        return asyncio.run(self.verify(presentation, request))

    async def verify(self, presentation: str, request: Request | None = None) -> Decision:
        request = request or Request()
        decision = Decision(outcome=Outcome.DENY)
        check = 0
        try:
            check = 1
            vp_jws, holder, nonce = self._check_envelope(presentation)
            check = 2
            await self._check_presentation_signature(vp_jws, holder, nonce, decision)
            check = 3
            trust_list = await self._trust_list()
            agent_vc, operator_vc = await self._check_credentials(vp_jws, trust_list, decision)
            check = 4
            self._check_accreditation(agent_vc, trust_list)
            self._check_accreditation(operator_vc, trust_list)
            check = 5
            self._check_validity(agent_vc, trust_list)
            self._check_validity(operator_vc, trust_list)
            await self._check_status(agent_vc, operator_vc, trust_list, request, decision)
            check = 6
            self._check_holder_binding(agent_vc, holder, vp_jws)
            check = 7
            self._check_operator_binding(agent_vc, operator_vc, trust_list, decision)
            check = 8
            self._check_policy(agent_vc, trust_list, request, decision)
        except Failure as failure:
            return Decision.from_failure(failure, check, decision)
        except Exception as err:  # fail closed on anything unexpected
            return Decision.from_failure(
                Failure(Reason.INTERNAL_ERROR, f"{type(err).__name__}: {err}"), check, decision
            )
        decision.outcome = Outcome.ALLOW
        return decision

    # Check 1 ----------------------------------------------------------------------

    def _check_envelope(self, presentation: str) -> tuple[jose.CompactJws, str, str]:
        try:
            jws = jose.parse(presentation)
        except jose.JoseError as err:
            raise Failure(Reason.VP_MALFORMED, str(err)) from None
        if jws.typ != VP_TYP:
            raise Failure(Reason.VP_TYP, f"typ is {jws.typ!r}")
        vp = jws.payload
        if "VerifiablePresentation" not in _types(vp):
            raise Failure(Reason.VP_MALFORMED, "type must include VerifiablePresentation")
        holder = vp.get("holder")
        holder = holder.get("id") if isinstance(holder, dict) else holder
        if not isinstance(holder, str):
            raise Failure(Reason.VP_MALFORMED, "holder missing")
        aud = vp.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if self.policy.audience not in audiences:
            raise Failure(Reason.VP_AUDIENCE, f"aud {aud!r}")
        nonce = vp.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise Failure(Reason.NONCE_MISSING)
        if not self.nonces.is_live(nonce):
            raise Failure(Reason.NONCE_UNKNOWN, "nonce not issued here, expired or used")
        try:
            iat, exp = _int_claim(vp, "iat"), _int_claim(vp, "exp")
        except ValueError as err:
            raise Failure(Reason.VP_MALFORMED, str(err)) from None
        now, skew = self.clock(), self.policy.clock_skew_seconds
        if exp - iat > PRESENTATION_MAX_LIFETIME or exp <= iat:
            raise Failure(Reason.VP_LIFETIME, f"lifetime {exp - iat}s")
        if iat > now + skew:
            raise Failure(Reason.VP_NOT_YET_VALID)
        if now > exp + skew:
            raise Failure(Reason.VP_EXPIRED)
        return jws, holder, nonce

    # Check 2 ----------------------------------------------------------------------

    async def _check_presentation_signature(
        self, jws: jose.CompactJws, holder: str, nonce: str, decision: Decision
    ) -> None:
        kid = jws.kid
        try:
            kid_did, _ = split_did_url(kid or "")
        except DidError as err:
            raise Failure(Reason.VP_KID_INVALID, str(err)) from None
        if kid_did != holder:
            raise Failure(Reason.VP_KID_INVALID, "kid is not a key of the holder")
        try:
            resolved = await self.dids.resolve(holder)
        except DidUnavailable as err:
            raise Failure(Reason.DID_UNAVAILABLE, str(err)) from None
        except DidError as err:
            raise Failure(Reason.HOLDER_DID_UNRESOLVABLE, str(err)) from None
        try:
            key = resolved.key_for(kid, AUTHENTICATION)
        except DidError as err:
            raise Failure(Reason.VP_KID_INVALID, str(err)) from None
        try:
            jose.verify(jws, key)
        except jose.JoseError as err:
            raise Failure(Reason.VP_SIGNATURE, str(err)) from None
        # Consume only after the signature verifies, so nobody can burn a nonce
        # they did not earn; consume is atomic, so a parallel replay loses.
        if not self.nonces.consume(nonce):
            raise Failure(Reason.NONCE_REUSED)
        decision.agent = holder
        decision.agent_key_id = kid

    # Check 3 ----------------------------------------------------------------------

    async def _trust_list(self) -> TrustList:
        try:
            return await self.trust.current()
        except Exception as err:  # TrustListError, FetchError, undecodable body
            raise Failure(Reason.TRUST_LIST_UNAVAILABLE, str(err)) from None

    async def _check_credentials(
        self, vp_jws: jose.CompactJws, trust_list: TrustList, decision: Decision
    ) -> tuple[_Credential, _Credential]:
        entries = vp_jws.payload.get("verifiableCredential")
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list) or not entries:
            raise Failure(Reason.VC_MISSING, "no enveloped credentials")
        found: dict[str, _Credential] = {}
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or "EnvelopedVerifiableCredential" not in _types(entry)
                or not str(entry.get("id", "")).startswith(VC_DATA_PREFIX)
            ):
                raise Failure(Reason.VC_MALFORMED, "expected EnvelopedVerifiableCredential")
            try:
                vc_jws = jose.parse(entry["id"][len(VC_DATA_PREFIX):])
            except jose.JoseError as err:
                raise Failure(Reason.VC_MALFORMED, str(err)) from None
            if vc_jws.typ != VC_TYP:
                raise Failure(Reason.VC_TYP, f"typ is {vc_jws.typ!r}")
            types = _types(vc_jws.payload)
            if "VerifiableCredential" not in types:
                raise Failure(Reason.VC_MALFORMED, "type must include VerifiableCredential")
            kinds = [k for k in (AGENT_CREDENTIAL, OPERATOR_CREDENTIAL) if k in types]
            if len(kinds) != 1:
                raise Failure(Reason.VC_MALFORMED, f"unexpected credential types {types}")
            if kinds[0] in found:
                raise Failure(Reason.VC_MALFORMED, f"more than one {kinds[0]}")
            found[kinds[0]] = _Credential(vc_jws, kinds[0])
        for kind in (AGENT_CREDENTIAL, OPERATOR_CREDENTIAL):
            if kind not in found:
                raise Failure(Reason.VC_MISSING, f"{kind} missing")
        for cred in found.values():
            await self._check_credential_signature(cred, trust_list)
        decision.issuers = sorted({c.issuer for c in found.values() if c.issuer})
        return found[AGENT_CREDENTIAL], found[OPERATOR_CREDENTIAL]

    async def _check_credential_signature(self, cred: _Credential, trust_list: TrustList) -> None:
        if not cred.issuer:
            raise Failure(Reason.VC_MALFORMED, f"{cred.kind} has no issuer")
        # Resolve only issuers the trust list names, so a presentation cannot make
        # the verifier fetch arbitrary URLs. Reported as check 4 below.
        if trust_list.issuer(cred.issuer) is None:
            raise Failure(Reason.ISSUER_NOT_LISTED, cred.issuer, credential=cred.kind, check=4)
        try:
            kid_did, _ = split_did_url(cred.jws.kid or "")
        except DidError as err:
            raise Failure(Reason.VC_KID_INVALID, str(err)) from None
        if kid_did != cred.issuer:
            raise Failure(Reason.VC_KID_INVALID, "kid is not a key of the issuer")
        try:
            resolved = await self.dids.resolve(cred.issuer)
        except DidUnavailable as err:
            raise Failure(Reason.DID_UNAVAILABLE, str(err)) from None
        except DidError as err:
            raise Failure(Reason.ISSUER_DID_UNRESOLVABLE, str(err)) from None
        try:
            key = resolved.key_for(cred.jws.kid or "", ASSERTION_METHOD)
            jose.verify(cred.jws, key)
        except DidError as err:
            raise Failure(Reason.VC_KID_INVALID, str(err)) from None
        except jose.JoseError as err:
            raise Failure(Reason.VC_SIGNATURE, f"{cred.kind}: {err}") from None

    # Check 4 ----------------------------------------------------------------------

    def _check_accreditation(self, cred: _Credential, trust_list: TrustList) -> None:
        issuer = trust_list.issuer(cred.issuer or "")
        if issuer is None:
            raise Failure(Reason.ISSUER_NOT_LISTED, str(cred.issuer))
        if cred.kind not in issuer.credential_types:
            raise Failure(Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, f"not accredited for {cred.kind}")
        if cred.tier is None or cred.tier not in issuer.tiers:
            raise Failure(Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, f"tier {cred.tier!r}")
        key = issuer.key(cred.jws.kid or "")
        iat = cred.vc.get("iat")
        if key is None or not isinstance(iat, int) or not key.not_before <= iat <= key.not_after:
            raise Failure(Reason.ISSUER_KEY_NOT_LISTED, f"{cred.jws.kid} not valid at signing time")

    # Check 5 ----------------------------------------------------------------------

    def _check_validity(self, cred: _Credential, trust_list: TrustList) -> None:
        try:
            valid_from = _epoch(cred.vc.get("validFrom"))
            valid_until = _epoch(cred.vc.get("validUntil"))
            iat, exp = _int_claim(cred.vc, "iat"), _int_claim(cred.vc, "exp")
        except ValueError as err:
            raise Failure(Reason.VC_TIME_CLAIMS, f"{cred.kind}: {err}") from None
        if iat != valid_from or exp != valid_until or valid_until <= valid_from:
            raise Failure(Reason.VC_TIME_CLAIMS, f"{cred.kind}: iat/exp must equal validFrom/validUntil")
        policy = trust_list.policy
        if cred.kind == AGENT_CREDENTIAL:
            max_lifetime = policy.agent_credential_max_lifetime
        else:
            max_lifetime = policy.operator_credential_max_lifetime.get(cred.tier or "", 0)
        if valid_until - valid_from > max_lifetime:
            raise Failure(Reason.VC_LIFETIME, f"{cred.kind}: {valid_until - valid_from}s")
        now, skew = self.clock(), self.policy.clock_skew_seconds
        if now + skew < valid_from:
            raise Failure(Reason.VC_NOT_YET_VALID, cred.kind)
        if now > valid_until + skew:
            raise Failure(Reason.VC_EXPIRED, cred.kind)

    async def _check_status(
        self,
        agent_vc: _Credential,
        operator_vc: _Credential,
        trust_list: TrustList,
        request: Request,
        decision: Decision,
    ) -> None:
        worst_age = 0.0
        for cred in (agent_vc, operator_vc):
            try:
                entries = parse_entries(cred.vc)
            except StatusError as err:
                raise Failure(Reason.VC_MALFORMED, f"{cred.kind}: {err}") from None
            required = cred is agent_vc or self.policy.require_operator_status
            if not entries:
                if required:
                    raise Failure(Reason.STATUS_ENTRY_MISSING, cred.kind)
                continue

            async def verify_list(status_list: StatusList, cred: _Credential = cred) -> None:
                await self._verify_status_list(status_list, cred, trust_list)

            for entry in entries:
                try:
                    result = await self.status.check(entry, verify_list,
                                                     expected_issuer=cred.issuer or "")
                except Failure:
                    raise
                except (FetchError, StatusError, DidError, jose.JoseError) as err:
                    raise Failure(Reason.STATUS_UNAVAILABLE, f"{cred.kind}: {err}") from None
                if result.set:
                    reason = (
                        Reason.STATUS_REVOKED if entry.purpose == "revocation"
                        else Reason.STATUS_SUSPENDED
                    )
                    raise Failure(reason, cred.kind, statusList=entry.list_url)
                worst_age = max(worst_age, result.age)
        verdict = self.policy.degraded_mode.evaluate(worst_age, request.risk)
        if verdict == "block":
            raise Failure(Reason.STATUS_STALE, f"status list age {int(worst_age)}s",
                          risk=request.risk.value)
        if verdict == "flag":
            decision.flags.append("STATUS_STALE_REVIEW")
        decision.context["statusAge"] = int(worst_age)

    async def _verify_status_list(
        self, status_list: StatusList, cred: _Credential, trust_list: TrustList
    ) -> None:
        if status_list.issuer != cred.issuer:
            raise StatusError("status list issued by a different issuer")
        issuer = trust_list.issuer(status_list.issuer)
        if issuer is None:
            raise StatusError("status list issuer not in the trust list")
        resolved = await self.dids.resolve(status_list.issuer)
        key = resolved.key_for(status_list.jws.kid or "", ASSERTION_METHOD)
        jose.verify(status_list.jws, key)
        if issuer.key(status_list.jws.kid or "") is None:
            raise StatusError("status list signed by a key the trust list does not list")

    # Check 6 ----------------------------------------------------------------------

    def _check_holder_binding(self, agent_vc: _Credential, holder: str, vp_jws: jose.CompactJws) -> None:
        if agent_vc.subject.get("id") != holder:
            raise Failure(Reason.HOLDER_MISMATCH, "Agent Credential subject is not the holder")
        cnf = agent_vc.subject.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("kid") != vp_jws.kid:
            raise Failure(Reason.CNF_MISMATCH, "cnf key did not sign the presentation")

    # Check 7 ----------------------------------------------------------------------

    def _check_operator_binding(
        self, agent_vc: _Credential, operator_vc: _Credential, trust_list: TrustList,
        decision: Decision,
    ) -> None:
        operator = operator_vc.subject.get("id")
        if not isinstance(operator, str) or agent_vc.subject.get("operator") != operator:
            raise Failure(Reason.OPERATOR_MISMATCH, "operator DID differs")
        if agent_vc.subject.get("operatorCredential") != operator_vc.vc.get("id"):
            raise Failure(Reason.OPERATOR_MISMATCH, "operatorCredential id differs")
        rank = trust_list.policy.tier_rank
        if rank(operator_vc.tier or "") < rank(agent_vc.tier or ""):
            raise Failure(Reason.OPERATOR_TIER_BELOW_AGENT)
        decision.operator = operator
        domains = operator_vc.subject.get("domains")
        if isinstance(domains, list):
            decision.operator_domains = [d for d in domains if isinstance(d, str)]

    # Check 8 ----------------------------------------------------------------------

    def _check_policy(
        self, agent_vc: _Credential, trust_list: TrustList, request: Request, decision: Decision
    ) -> None:
        subject = agent_vc.subject
        operator = subject.get("operator")
        decision.tier = agent_vc.tier
        role = subject.get("accountableRole")
        decision.accountable_role = role if isinstance(role, str) else None
        decision.agent_credential_id = agent_vc.vc.get("id")
        decision.agent_credential_expires = agent_vc.vc.get("exp")

        rank = trust_list.policy.tier_rank
        min_tier = request.min_tier or self.policy.min_tier
        if rank(agent_vc.tier or "") < 0 or rank(agent_vc.tier or "") < rank(min_tier):
            raise Failure(Reason.TIER_TOO_LOW, f"{agent_vc.tier} below {min_tier}")
        allowed_ops = self.policy.allowed_operators
        if allowed_ops is not None and operator not in allowed_ops:
            raise Failure(Reason.OPERATOR_NOT_ALLOWED, str(operator))

        raw_scopes = subject.get("scopes")
        held = {s for s in raw_scopes if isinstance(s, str)} if isinstance(raw_scopes, list) else set()
        if trust_list.scopes:
            held &= trust_list.scopes
        decision.scopes_held = sorted(held)
        usable = held if self.policy.allowed_scopes is None else held & self.policy.allowed_scopes
        missing = set(request.scopes) - usable
        if missing:
            raise Failure(Reason.SCOPE_NOT_HELD, " ".join(sorted(missing)),
                          missingScopes=sorted(missing))

        if request.payment is not None:
            self._check_limits(subject, request, decision)
        decision.scopes_granted = sorted(request.scopes or usable)

    def _check_limits(self, subject: dict[str, Any], request: Request, decision: Decision) -> None:
        payment = request.payment
        assert payment is not None
        intent = {
            "action": "payment",
            "amount": str(payment.amount),
            "currency": payment.currency,
            "scopes": sorted(request.scopes),
        }
        limits = subject.get("limits")
        if not isinstance(limits, dict) or limits.get("currency") != payment.currency:
            # No limits for this currency means no authority to pay alone.
            raise Failure(Reason.LIMIT_PER_PAYMENT, "no delegated limit for this currency",
                          intent=intent)
        try:
            per_payment = Decimal(str(limits["perPayment"]))
            per_day = Decimal(str(limits["perDay"]))
        except (KeyError, InvalidOperation):
            raise Failure(Reason.LIMIT_PER_PAYMENT, "malformed limits", intent=intent) from None
        if payment.amount > per_payment:
            raise Failure(Reason.LIMIT_PER_PAYMENT, f"{payment.amount} > {per_payment}",
                          intent=intent)
        if payment.spent_today + payment.amount > per_day:
            raise Failure(Reason.LIMIT_PER_DAY,
                          f"{payment.spent_today} + {payment.amount} > {per_day}", intent=intent)
        decision.context["limits"] = {"currency": payment.currency,
                                      "perPayment": str(per_payment), "perDay": str(per_day)}
