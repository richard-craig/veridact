"""The Veridact presentation verifier (specification v0.5).

Runs the eight checks from the specification's "Verification at the relying party"
section, in order, and stops at the first failure. With a warm cache it makes no
network calls, and it never calls an issuer about a particular agent.

A presentation is an SD-JWT+KB: the Agent Credential (an SD-JWT VC), the disclosures
the agent chose to show, and a Key Binding JWT signed by the credential's ``cnf`` key
for this relying party and nonce.

Two more entry points serve authorisation servers:

* ``verify_client_attestation``: pattern C, a Veridact Client Attestation presented
  with ``attest_jwt_client_auth_dpop``, bound to the agent's DPoP key.
* ``verify_known_assistant``: a known-assistant entry for a mainstream assistant
  (Claude, ChatGPT, ...), matched to the OAuth client it describes.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from . import jose, sdjwt
from .codes import Outcome, Reason
from .decision import Decision, Failure
from .fetch import ArtefactCache, Clock, Fetcher, FetchError, HttpFetcher
from .identifiers import (
    CLIENT_ATTESTATION_TYP,
    VCT_AGENT,
    VCT_KNOWN_ASSISTANT,
    VCT_OPERATOR,
    IdentifierError,
    IssuerMetadataCache,
    MetadataUnavailable,
    host_of,
    public_jwk,
)
from .nonce import InMemoryNonceStore, NonceStore
from .policy import RelyingPartyPolicy, Request
from .status import INVALID, SUSPENDED, VALID, StatusError, StatusList, StatusLists, parse_ref
from .trust import DEFAULT_TRUST_LIST_URL, AccreditedIssuer, TrustList, TrustRegistry

PRESENTATION_MAX_AGE = 120
AUTH_SCHEME = "Veridact"
_AUTH_PARAM = 'sd-jwt="'


def _int_claim(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


@dataclass
class _Credential:
    """An issuer-signed credential and its claims after disclosures are applied."""

    jws: jose.CompactJws
    claims: dict[str, Any]
    disclosed: dict[str, Any]
    kind: str  # vct, or the attestation typ

    @property
    def issuer(self) -> str:
        return self.claims.get("iss") or ""

    @property
    def tier(self) -> str | None:
        tier = self.claims.get("tier")
        return tier if isinstance(tier, str) else None


class Verifier:
    """Verifies Veridact presentations for one relying party.

    ``governance_keys`` maps governance key ids to public JWKs and is the only trust
    anchor. Everything else is fetched, verified and cached.
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
        metadata_ttl: float = 300.0,
        status_ttl: float = 300.0,
        trust_ttl: float = 3600.0,
    ):
        self.policy = policy
        self.clock = clock
        self.fetcher = fetcher or HttpFetcher()
        self.cache = ArtefactCache(clock)
        self.nonces = nonces or InMemoryNonceStore(ttl=PRESENTATION_MAX_AGE, clock=clock)
        stale = policy.degraded_mode.stale_limit_seconds
        self.issuers = IssuerMetadataCache(self.fetcher, self.cache, ttl=metadata_ttl, max_stale=stale)
        self.trust = TrustRegistry(
            self.fetcher, self.cache, governance_keys, url=trust_list_url, ttl=trust_ttl
        )
        self.status = StatusLists(self.fetcher, self.cache, ttl=status_ttl, max_stale=stale)

    # -- challenges (pattern B) ------------------------------------------------------------

    def challenge(self, request: Request | None = None, *, realm: str | None = None) -> tuple[str, str]:
        """Issue a nonce; return it and a WWW-Authenticate header value."""
        request = request or Request()
        nonce = self.nonces.issue()
        parts = [f'realm="{realm or self.policy.audience}"', f'nonce="{nonce}"',
                 f'tier="{request.min_tier or self.policy.min_tier}"']
        if request.scopes:
            parts.append(f'scope="{" ".join(sorted(request.scopes))}"')
        disclose = self.policy.required_disclosures | request.disclose
        if disclose:
            parts.append(f'disclose="{" ".join(sorted(disclose))}"')
        return nonce, f"{AUTH_SCHEME} " + ", ".join(parts)

    @staticmethod
    def presentation_from_authorization(header: str | None) -> str | None:
        """Extract the SD-JWT+KB from 'Authorization: Veridact sd-jwt="<SD-JWT+KB>"'."""
        if not header:
            return None
        scheme, _, rest = header.strip().partition(" ")
        if scheme.lower() != AUTH_SCHEME.lower():
            return None
        rest = rest.strip()
        if rest.startswith(_AUTH_PARAM) and rest.endswith('"') and rest.count('"') == 2:
            return rest[len(_AUTH_PARAM):-1]
        return None

    # -- presentations ---------------------------------------------------------------------

    def verify_sync(self, presentation: str, request: Request | None = None) -> Decision:
        return asyncio.run(self.verify(presentation, request))

    async def verify(self, presentation: str, request: Request | None = None) -> Decision:
        request = request or Request()
        decision = Decision(outcome=Outcome.DENY)
        check = 0
        try:
            check = 1
            parsed, kb, nonce = self._check_envelope(presentation)
            check = 2
            trust_list = await self._trust_list()
            issuer = self._listed_issuer(parsed.jws.payload.get("iss"), trust_list)
            check = 3
            cred = await self._check_signature(parsed.jws, issuer, VCT_AGENT, decision,
                                               disclosures=parsed.disclosures)
            agent_jwk = self._check_key_binding(cred, kb)
            # Consume only after both signatures verify, so nobody can burn a nonce they did
            # not earn; consume is atomic, so a parallel replay loses.
            if not self.nonces.consume(nonce):
                raise Failure(Reason.NONCE_REUSED, check=1)
            check = 4
            self._check_accreditation(cred, issuer, require_tier=True)
            check = 5
            self._check_validity(cred, trust_list.policy.agent_credential_max_lifetime)
            await self._check_status(cred, cred.claims.get("operator_status"), trust_list, request,
                                     decision)
            check = 6
            self._check_key_logged(cred)
            check = 7
            self._check_disclosures(cred, request)
            check = 8
            self._describe_agent(cred, agent_jwk, decision)
            self._check_policy(cred.claims, trust_list, request, decision)
        except Failure as failure:
            return Decision.from_failure(failure, check, decision)
        except Exception as err:  # fail closed on anything unexpected
            return Decision.from_failure(
                Failure(Reason.INTERNAL_ERROR, f"{type(err).__name__}: {err}"), check, decision
            )
        decision.outcome = Outcome.ALLOW
        return decision

    # Check 1 ------------------------------------------------------------------------------

    def _check_envelope(self, presentation: str) -> tuple[sdjwt.SdJwt, jose.CompactJws, str]:
        try:
            parsed = sdjwt.parse(presentation)
        except sdjwt.SdJwtError as err:
            raise Failure(Reason.SDJWT_MALFORMED, str(err)) from None
        if parsed.kb_jwt is None:
            raise Failure(Reason.KB_MISSING, "a presentation ends with a KB-JWT")
        try:
            kb = jose.parse(parsed.kb_jwt)
        except jose.JoseError as err:
            raise Failure(Reason.KB_MALFORMED, str(err)) from None
        if kb.typ != sdjwt.KB_TYP:
            raise Failure(Reason.KB_TYP, f"typ is {kb.typ!r}")
        p = kb.payload
        aud = p.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if self.policy.audience not in audiences:
            raise Failure(Reason.KB_AUDIENCE, f"aud {aud!r}")
        nonce = p.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise Failure(Reason.NONCE_MISSING)
        if not self.nonces.is_live(nonce):
            raise Failure(Reason.NONCE_UNKNOWN, "nonce not issued here, expired or used")
        try:
            iat = _int_claim(p, "iat")
        except ValueError as err:
            raise Failure(Reason.KB_MALFORMED, str(err)) from None
        now, skew = self.clock(), self.policy.clock_skew_seconds
        if iat > now + skew:
            raise Failure(Reason.KB_NOT_YET_VALID)
        if now - iat > PRESENTATION_MAX_AGE + skew:
            raise Failure(Reason.KB_EXPIRED, f"KB-JWT is {int(now - iat)}s old")
        if p.get("sd_hash") != parsed.sd_hash:
            raise Failure(Reason.SD_HASH_MISMATCH, "sd_hash does not cover the presented SD-JWT")
        return parsed, kb, nonce

    # Check 2 ------------------------------------------------------------------------------

    async def _trust_list(self) -> TrustList:
        try:
            return await self.trust.current()
        except Exception as err:  # TrustListError, FetchError, undecodable body
            raise Failure(Reason.TRUST_LIST_UNAVAILABLE, str(err)) from None

    @staticmethod
    def _listed_issuer(iss: Any, trust_list: TrustList) -> AccreditedIssuer:
        # Fetch nothing for an issuer the trust list does not name, so a presentation cannot
        # make the verifier fetch arbitrary URLs. Reported as check 4.
        issuer = trust_list.issuer(iss) if isinstance(iss, str) else None
        if issuer is None:
            raise Failure(Reason.ISSUER_NOT_LISTED, str(iss), check=4)
        return issuer

    # Check 3 ------------------------------------------------------------------------------

    async def _check_signature(self, jws: jose.CompactJws, issuer: AccreditedIssuer, kind: str,
                               decision: Decision, *, disclosures=()) -> _Credential:
        expected_typ = CLIENT_ATTESTATION_TYP if kind == CLIENT_ATTESTATION_TYP else sdjwt.SD_JWT_TYP
        if jws.typ != expected_typ:
            raise Failure(Reason.VC_TYP, f"typ is {jws.typ!r}")
        if kind != CLIENT_ATTESTATION_TYP and jws.payload.get("vct") != kind:
            raise Failure(Reason.VCT_UNEXPECTED, f"vct is {jws.payload.get('vct')!r}")
        listed = issuer.key(jws.kid or "")
        if listed is None:
            raise Failure(Reason.ISSUER_KEY_NOT_LISTED, f"{jws.kid!r} is not pinned in the trust list",
                          check=4)
        try:
            metadata = await self.issuers.get(issuer.id)
        except MetadataUnavailable as err:
            raise Failure(Reason.ISSUER_METADATA_UNAVAILABLE, str(err)) from None
        except IdentifierError as err:
            raise Failure(Reason.ISSUER_METADATA_INVALID, str(err)) from None
        try:
            key = metadata.key(listed.kid)
        except IdentifierError as err:
            raise Failure(Reason.VC_KID_INVALID, str(err)) from None
        if jose.jwk_thumbprint(jose.key_to_jwk(key)) != listed.jkt:
            raise Failure(Reason.ISSUER_KEY_NOT_LISTED, "the metadata key differs from the pinned key",
                          check=4)
        try:
            jose.verify(jws, key)
        except jose.JoseError as err:
            raise Failure(Reason.VC_SIGNATURE, str(err)) from None
        try:
            claims = sdjwt.resolve(jws.payload, disclosures)
        except sdjwt.SdJwtError as err:
            raise Failure(Reason.DISCLOSURE_INVALID, str(err)) from None
        disclosed = {d.name: claims[d.name] for d in disclosures if d.name in claims}
        decision.issuers = [issuer.id]
        decision.credential_type = kind
        return _Credential(jws, claims, disclosed, kind)

    def _check_key_binding(self, cred: _Credential, kb: jose.CompactJws) -> dict[str, Any]:
        cnf = cred.claims.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        try:
            key = jose.key_from_jwk(public_jwk(jwk))  # type: ignore[arg-type]
        except (jose.JoseError, KeyError, TypeError):
            raise Failure(Reason.CNF_MISSING, "the credential has no usable cnf.jwk", check=6) from None
        try:
            jose.verify(kb, key)
        except jose.JoseError as err:
            raise Failure(Reason.KB_SIGNATURE, f"KB-JWT: {err}", check=6) from None
        return public_jwk(jwk)  # type: ignore[arg-type]

    # Check 4 ------------------------------------------------------------------------------

    @staticmethod
    def _check_accreditation(cred: _Credential, issuer: AccreditedIssuer, *, vct: str | None = None,
                             require_tier: bool, tier: str | None = None) -> None:
        vct = vct or cred.kind
        if vct not in issuer.vcts:
            raise Failure(Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, f"not accredited for {vct}")
        tier = tier if tier is not None else cred.tier
        if require_tier and (tier is None or tier not in issuer.tiers):
            raise Failure(Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, f"tier {tier!r}")
        key = issuer.key(cred.jws.kid or "")
        iat = cred.claims.get("iat")
        if key is None or not isinstance(iat, int) or not key.not_before <= iat <= key.not_after:
            raise Failure(Reason.ISSUER_KEY_NOT_LISTED, f"{cred.jws.kid} not valid at signing time")

    # Check 5 ------------------------------------------------------------------------------

    def _check_validity(self, cred: _Credential, max_lifetime: int) -> None:
        c = cred.claims
        try:
            iat, exp = _int_claim(c, "iat"), _int_claim(c, "exp")
            nbf = _int_claim(c, "nbf") if "nbf" in c else iat
        except ValueError as err:
            raise Failure(Reason.VC_TIME_CLAIMS, str(err)) from None
        if exp <= iat or nbf < iat or nbf >= exp:
            raise Failure(Reason.VC_TIME_CLAIMS, "need iat <= nbf < exp")
        if exp - iat > max_lifetime:
            raise Failure(Reason.VC_LIFETIME, f"{exp - iat}s")
        now, skew = self.clock(), self.policy.clock_skew_seconds
        if now + skew < nbf:
            raise Failure(Reason.VC_NOT_YET_VALID)
        if now > exp + skew:
            raise Failure(Reason.VC_EXPIRED)

    async def _check_status(self, cred: _Credential, operator_status: Any, trust_list: TrustList,
                            request: Request, decision: Decision, *, operator_required: bool = True) -> None:
        try:
            own = parse_ref(cred.claims.get("status"))
            operator = parse_ref(operator_status, field="operator_status")
        except StatusError as err:
            raise Failure(Reason.VC_MALFORMED, str(err)) from None
        if own is None:
            raise Failure(Reason.STATUS_ENTRY_MISSING, "status")
        if operator is None and operator_required and self.policy.require_operator_status:
            raise Failure(Reason.STATUS_ENTRY_MISSING, "operator_status")
        worst_age = 0.0
        for ref, whose in ((own, "credential"), (operator, "operator")):
            if ref is None:
                continue

            async def verify_list(status_list: StatusList, whose: str = whose) -> None:
                self._verify_status_list(status_list, cred, trust_list, whose)
                # The issuer key that signed the list is fetched like any other.
                issuer = trust_list.issuer(status_list.issuer)
                assert issuer is not None
                listed = issuer.key(status_list.jws.kid or "")
                if listed is None:
                    raise StatusError("status list key is not pinned in the trust list")
                metadata = await self.issuers.get(issuer.id)
                key = metadata.key(listed.kid)
                if jose.jwk_thumbprint(jose.key_to_jwk(key)) != listed.jkt:
                    raise StatusError("status list key differs from the pinned key")
                jose.verify(status_list.jws, key)

            try:
                result, _ = await self.status.check(ref, verify_list)
            except (FetchError, StatusError, IdentifierError, jose.JoseError) as err:
                raise Failure(Reason.STATUS_UNAVAILABLE, f"{whose}: {err}") from None
            if result.value == INVALID or result.value > SUSPENDED:
                reason = Reason.STATUS_REVOKED if whose == "credential" else Reason.OPERATOR_REVOKED
                raise Failure(reason, whose, statusList=ref.uri)
            if result.value == SUSPENDED:
                reason = Reason.STATUS_SUSPENDED if whose == "credential" else Reason.OPERATOR_SUSPENDED
                raise Failure(reason, whose, statusList=ref.uri)
            assert result.value == VALID
            worst_age = max(worst_age, result.age)
        verdict = self.policy.degraded_mode.evaluate(worst_age, request.risk)
        if verdict == "block":
            raise Failure(Reason.STATUS_STALE, f"status list age {int(worst_age)}s",
                          risk=request.risk.value)
        if verdict == "flag":
            decision.flags.append("STATUS_STALE_REVIEW")
        decision.context["statusAge"] = int(worst_age)

    @staticmethod
    def _verify_status_list(status_list: StatusList, cred: _Credential, trust_list: TrustList,
                            whose: str) -> None:
        issuer = trust_list.issuer(status_list.issuer)
        if issuer is None:
            raise StatusError("status list issuer not in the trust list")
        if whose == "credential" and status_list.issuer != cred.issuer:
            raise StatusError("status list issued by a different issuer")
        if whose == "operator" and VCT_OPERATOR not in issuer.vcts:
            raise StatusError("operator status list from an issuer not accredited for operators")
        key_epoch = issuer.key(status_list.jws.kid or "")
        if key_epoch is None or not key_epoch.not_before <= status_list.issued_at <= key_epoch.not_after:
            raise StatusError("status list signed by a key the trust list does not list for its iat")

    # Check 6 ------------------------------------------------------------------------------

    @staticmethod
    def _check_key_logged(cred: _Credential) -> None:
        # The issuer signs the cnf key into a credential only after the key's add event is in
        # the transparency log, records that entry here, and revokes every credential naming a
        # key once a retire or compromise event is logged (specification v0.5, Key events).
        event = cred.claims.get("cnf_event")
        if not isinstance(event, str) or not event:
            raise Failure(Reason.KEY_NOT_LOGGED, "no logged add event for the cnf key")

    # Check 7 ------------------------------------------------------------------------------

    def _check_disclosures(self, cred: _Credential, request: Request) -> None:
        required = self.policy.required_disclosures | request.disclose
        missing = sorted(required - set(cred.disclosed))
        if missing:
            raise Failure(Reason.CLAIMS_NOT_DISCLOSED, " ".join(missing), missingClaims=missing)

    # Check 8 ------------------------------------------------------------------------------

    @staticmethod
    def _describe_agent(cred: _Credential, agent_jwk: dict[str, Any], decision: Decision) -> None:
        c = cred.claims
        decision.agent = c.get("sub") if isinstance(c.get("sub"), str) else None
        operator = c.get("operator")
        decision.operator = operator if isinstance(operator, str) else None
        decision.operator_domains = [host_of(operator)] if isinstance(operator, str) else []
        decision.tier = cred.tier
        role = c.get("accountable_role")
        decision.accountable_role = role if isinstance(role, str) else None
        decision.agent_jwk = agent_jwk
        decision.agent_key_id = jose.jwk_thumbprint(agent_jwk)
        decision.agent_credential_id = c.get("jti") if isinstance(c.get("jti"), str) else None
        decision.agent_credential_expires = c.get("exp")
        decision.disclosed = dict(cred.disclosed)

    def _check_policy(self, claims: dict[str, Any], trust_list: TrustList, request: Request,
                      decision: Decision) -> None:
        tier = claims.get("tier") if isinstance(claims.get("tier"), str) else ""
        rank = trust_list.policy.tier_rank
        min_tier = request.min_tier or self.policy.min_tier
        if rank(tier) < 0 or rank(tier) < rank(min_tier):
            raise Failure(Reason.TIER_TOO_LOW, f"{tier} below {min_tier}")
        allowed_ops = self.policy.allowed_operators
        operator = claims.get("operator")
        if allowed_ops is not None and operator not in allowed_ops:
            raise Failure(Reason.OPERATOR_NOT_ALLOWED, str(operator))

        raw_scopes = claims.get("scopes")
        held = {s for s in raw_scopes if isinstance(s, str)} if isinstance(raw_scopes, list) else set()
        if trust_list.scopes:
            held &= trust_list.scopes
        decision.scopes_held = sorted(held)
        usable = held if self.policy.allowed_scopes is None else held & self.policy.allowed_scopes
        missing = set(request.scopes) - usable
        if missing:
            raise Failure(Reason.SCOPE_NOT_HELD, " ".join(sorted(missing)),
                          missingScopes=sorted(missing))
        limits = claims.get("limits")
        decision.limits = limits if isinstance(limits, dict) else None
        if request.payment is not None:
            self._check_limits(limits, request, decision)
        decision.scopes_granted = sorted(request.scopes or usable)

    def _check_limits(self, limits: Any, request: Request, decision: Decision) -> None:
        payment = request.payment
        assert payment is not None
        intent = {
            "action": "payment",
            "amount": str(payment.amount),
            "currency": payment.currency,
            "scopes": sorted(request.scopes),
        }
        if not isinstance(limits, dict) or limits.get("currency") != payment.currency:
            # No limits for this currency means no authority to pay alone.
            raise Failure(Reason.LIMIT_PER_PAYMENT, "no delegated limit for this currency",
                          intent=intent)
        try:
            per_payment = Decimal(str(limits["per_payment"]))
            per_day = Decimal(str(limits["per_day"]))
        except (KeyError, InvalidOperation):
            raise Failure(Reason.LIMIT_PER_PAYMENT, "malformed limits", intent=intent) from None
        if payment.amount > per_payment:
            raise Failure(Reason.LIMIT_PER_PAYMENT, f"{payment.amount} > {per_payment}",
                          intent=intent)
        if payment.spent_today + payment.amount > per_day:
            raise Failure(Reason.LIMIT_PER_DAY,
                          f"{payment.spent_today} + {payment.amount} > {per_day}", intent=intent)
        decision.context["limits"] = {"currency": payment.currency,
                                      "per_payment": str(per_payment), "per_day": str(per_day)}

    # -- pattern C: client attestations ---------------------------------------------------------

    async def verify_client_attestation(self, attestation: str, *, client_id: str, dpop_jkt: str,
                                        request: Request | None = None) -> Decision:
        """Admit an OAuth client by its Veridact Client Attestation (``attest_jwt_client_auth_dpop``).

        The authorisation server verifies the DPoP proof itself (signature, ``htm``, ``htu``,
        ``iat``, ``jti`` and its own nonce) and passes the proof key's thumbprint here. The
        attestation must name this client and be bound to that key.
        """
        request = request or Request()
        decision = Decision(outcome=Outcome.DENY)
        check = 0
        try:
            check = 1
            try:
                jws = jose.parse(attestation)
            except jose.JoseError as err:
                raise Failure(Reason.VC_MALFORMED, str(err)) from None
            check = 2
            trust_list = await self._trust_list()
            issuer = self._listed_issuer(jws.payload.get("iss"), trust_list)
            check = 3
            cred = await self._check_signature(jws, issuer, CLIENT_ATTESTATION_TYP, decision)
            veridact = cred.claims.get("veridact")
            if not isinstance(veridact, dict):
                raise Failure(Reason.VC_MALFORMED, "attestation has no veridact claim")
            check = 4
            self._check_accreditation(cred, issuer, vct=VCT_AGENT, require_tier=True,
                                      tier=veridact.get("tier"))
            check = 5
            self._check_validity(cred, trust_list.policy.agent_credential_max_lifetime)
            await self._check_status(cred, veridact.get("operator_status"), trust_list, request,
                                     decision)
            check = 6
            if cred.claims.get("sub") != client_id:
                raise Failure(Reason.CLIENT_MISMATCH, "attestation sub is not this client_id")
            cnf = cred.claims.get("cnf")
            jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
            try:
                agent_jwk = public_jwk(jwk)  # type: ignore[arg-type]
                jkt = jose.jwk_thumbprint(agent_jwk)
            except (KeyError, TypeError, jose.JoseError):
                raise Failure(Reason.CNF_MISSING, "attestation has no usable cnf.jwk") from None
            if jkt != dpop_jkt:
                raise Failure(Reason.DPOP_KEY_MISMATCH, "the DPoP key is not the attested key")
            check = 8
            claims = {"sub": client_id, **veridact}
            view = _Credential(jws, claims, {}, CLIENT_ATTESTATION_TYP)
            self._describe_agent(view, agent_jwk, decision)
            decision.agent_credential_id = veridact.get("credential") or cred.claims.get("jti")
            decision.agent_credential_expires = cred.claims.get("exp")
            self._check_policy(claims, trust_list, request, decision)
        except Failure as failure:
            return Decision.from_failure(failure, check, decision)
        except Exception as err:
            return Decision.from_failure(
                Failure(Reason.INTERNAL_ERROR, f"{type(err).__name__}: {err}"), check, decision)
        decision.outcome = Outcome.ALLOW
        return decision

    # -- known-assistant entries ------------------------------------------------------------------

    async def verify_known_assistant(self, entry: str, *, client_id: str) -> Decision:
        """Check a known-assistant entry and that it describes ``client_id``.

        ``entry`` is the SD-JWT VC as Veridact publishes it (all disclosures attached, no
        KB-JWT: the platform holds no Veridact key). Run it at client registration and on
        every token request; a suspended entry stops the assistant on its next check.
        The decision carries the verified operator (``disclosed["operator"]``), the
        recommended ceiling (``context["maxLevel"]``) and the entry's other facts.
        """
        decision = Decision(outcome=Outcome.DENY)
        check = 0
        try:
            check = 1
            try:
                parsed = sdjwt.parse(entry)
            except sdjwt.SdJwtError as err:
                raise Failure(Reason.SDJWT_MALFORMED, str(err)) from None
            check = 2
            trust_list = await self._trust_list()
            issuer = self._listed_issuer(parsed.jws.payload.get("iss"), trust_list)
            check = 3
            cred = await self._check_signature(parsed.jws, issuer, VCT_KNOWN_ASSISTANT, decision,
                                               disclosures=parsed.disclosures)
            check = 4
            # Organisation tier only (specification v0.5, Known-assistant entries).
            self._check_accreditation(cred, issuer, require_tier=True, tier="organisation")
            check = 5
            self._check_validity(cred, trust_list.policy.known_assistant_max_lifetime)
            await self._check_status(cred, None, trust_list, Request(), decision,
                                     operator_required=False)
            check = 6
            c = cred.claims
            urls = c.get("client_metadata_urls")
            names = [c.get("sub")] + (urls if isinstance(urls, list) else [])
            if client_id not in [n for n in names if isinstance(n, str)]:
                raise Failure(Reason.ASSISTANT_NOT_LISTED, f"{client_id} is not in this entry")
            check = 8
            operator = c.get("operator") if isinstance(c.get("operator"), dict) else {}
            decision.agent = client_id
            decision.operator = operator.get("name") if isinstance(operator.get("name"), str) else None
            decision.agent_credential_id = c.get("jti")
            decision.agent_credential_expires = c.get("exp")
            decision.tier = "organisation"
            decision.disclosed = dict(cred.disclosed)
            decision.context.update({
                "platform": c.get("sub"),
                "operator": operator,
                "maxLevel": c.get("max_level"),
                "redirectHosts": c.get("redirect_hosts"),
                "tokenEndpointAuth": c.get("token_endpoint_auth"),
                "publishedEgress": c.get("published_egress"),
            })
        except Failure as failure:
            return Decision.from_failure(failure, check, decision)
        except Exception as err:
            return Decision.from_failure(
                Failure(Reason.INTERNAL_ERROR, f"{type(err).__name__}: {err}"), check, decision)
        decision.outcome = Outcome.ALLOW
        return decision
