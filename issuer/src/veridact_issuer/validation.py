"""Challenge validation and key-binding proofs (spec: Issuance protocol).

dns-01          control of the operator's domain (a TXT record, as in RFC 8555)
did-config-01   the operator DID and the domain belong together (DIF Well Known
                DID Configuration, JWT form)
delegation-01   the operator authorised this agent (a Delegation Credential signed
                by an operator DID that holds a valid Operator Credential)

Every DID is resolved and its did:webvh log verified with the same code relying
parties use (veridact-verify), so the issuer cannot accept a DID that verifiers
would reject.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Protocol
from urllib.parse import quote

from veridact_verify import jose
from veridact_verify.did import ASSERTION_METHOD, DidError, WebvhResolver, split_did_url
from veridact_verify.fetch import ArtefactCache, Fetcher, FetchError

from .acme import AcmeProblem, dns01_txt_value
from .config import IssuerConfig

KB_TYP = "veridact-kb+jwt"
KB_MAX_AGE = 300
DELEGATION_TYPE = "VeridactDelegationCredential"
DID_CONFIGURATION_PATH = "/.well-known/did-configuration.json"
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_AMOUNT = re.compile(r"^\d{1,12}(\.\d{1,2})?$")


class TxtResolver(Protocol):
    async def txt(self, name: str) -> list[str]: ...


class DnsPythonResolver:
    """TXT lookups through dnspython. Production adds multi-vantage checks (Month 2)."""

    async def txt(self, name: str) -> list[str]:
        try:
            import dns.asyncresolver
            import dns.exception
        except ImportError as err:  # pragma: no cover - optional dependency
            raise AcmeProblem("serverInternal", "dns-01 needs dnspython: pip install 'veridact-issuer[dns]'",
                              500) from err
        try:
            answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=10)
        except dns.exception.DNSException as err:
            raise AcmeProblem("dns", f"TXT lookup for {name} failed: {type(err).__name__}") from None
        return [b"".join(r.strings).decode("ascii", "replace") for r in answer]


class StaticTxtResolver:
    """For tests and the local sandbox: records set by hand."""

    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}

    async def txt(self, name: str) -> list[str]:
        return list(self.records.get(name.lower().rstrip("."), []))


def check_dns_identifier(value: Any) -> str:
    if not isinstance(value, str):
        raise AcmeProblem("rejectedIdentifier", "dns identifier must be a string")
    name = value.lower().rstrip(".")
    labels = name.split(".")
    if (len(name) > 253 or len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels)
            or labels[-1].isdigit()):
        raise AcmeProblem("rejectedIdentifier", f"{value!r} is not a domain name")
    return name


def did_segments(did: str) -> list[str]:
    """The host and path segments of did:webvh:{SCID}:{host}:{path...}."""
    parts = did.split(":")
    if len(parts) < 4 or parts[0] != "did" or parts[1] != "webvh" or not parts[2]:
        raise AcmeProblem("rejectedIdentifier", f"{did!r} is not a did:webvh DID")
    return parts[3:]


def is_operator_did_for(did: str, domain: str) -> bool:
    """Operator DIDs live at the root of the operator's domain: did:webvh:{SCID}:{domain}."""
    return did_segments(did) == [domain]


def _int(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


@dataclass
class Delegation:
    jwt: str
    id: str
    operator: str
    agent: str
    scopes: list[str]
    accountable_role: str
    max_lifetime: int
    valid_until: int
    environment: str
    limits: dict[str, str] | None = None
    audiences: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"jwt": self.jwt, "id": self.id, "operator": self.operator, "agent": self.agent,
                "scopes": self.scopes, "accountableRole": self.accountable_role,
                "maxLifetime": self.max_lifetime, "validUntil": self.valid_until,
                "environment": self.environment, "limits": self.limits, "audiences": self.audiences}


class Validator:
    def __init__(self, config: IssuerConfig, fetcher: Fetcher, *,
                 txt: TxtResolver | None = None, clock: Callable[[], float] = time.time):
        self.config = config
        self.fetcher = fetcher
        self.txt = txt or DnsPythonResolver()
        self.clock = clock
        # No caching at issuance: always read the operator's current DID log.
        self.resolver = WebvhResolver(fetcher, ArtefactCache(clock), ttl=0, max_stale=0)

    async def _key(self, kid: str, relationship: str):
        try:
            did, _ = split_did_url(kid)
            resolved = await self.resolver.resolve(did)
            return resolved.key_for(kid, relationship)
        except DidError as err:
            raise AcmeProblem("unauthorized", f"cannot use {kid}: {err}", 403) from None

    # -- dns-01 ------------------------------------------------------------------------

    async def dns01(self, domain: str, token: str, account_jwk: dict[str, str]) -> None:
        expected = dns01_txt_value(token, account_jwk)
        records = await self.txt.txt(f"_acme-challenge.{domain}")
        if expected not in records:
            raise AcmeProblem("incorrectResponse",
                              f"no TXT record _acme-challenge.{domain} with the expected value")

    # -- did-config-01 -------------------------------------------------------------------

    async def did_config01(self, domain: str, want_did: str | None) -> str:
        """Return the operator DID the domain links to."""
        url = f"https://{domain}{DID_CONFIGURATION_PATH}"
        try:
            body = await self.fetcher.fetch(url)
            config = json.loads(body)
        except FetchError as err:
            raise AcmeProblem("connection", f"cannot fetch {url}: {err}") from None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise AcmeProblem("incorrectResponse", f"{url} is not JSON") from None
        linked = config.get("linked_dids") if isinstance(config, dict) else None
        if not isinstance(linked, list) or not linked:
            raise AcmeProblem("incorrectResponse", f"{url} has no linked_dids")
        errors = []
        for item in linked:
            try:
                did = await self._domain_linkage(item, domain)
            except (AcmeProblem, jose.JoseError, ValueError) as err:
                errors.append(str(err))
                continue
            if want_did is None or did == want_did:
                return did
            errors.append(f"{did} is not the DID the client named")
        raise AcmeProblem("incorrectResponse",
                          "no valid Domain Linkage Credential for an operator DID at this domain: "
                          + "; ".join(errors[:3]))

    async def _domain_linkage(self, token: Any, domain: str) -> str:
        if not isinstance(token, str):
            raise ValueError("linked_dids entries must be JWTs")
        jws = jose.parse(token)
        if not jws.kid:
            raise ValueError("Domain Linkage Credential has no kid")
        did, _ = split_did_url(jws.kid)
        if not is_operator_did_for(did, domain):
            raise ValueError(f"{did} is not an operator DID for {domain} (did:webvh:{{SCID}}:{domain})")
        jose.verify(jws, await self._key(jws.kid, ASSERTION_METHOD))
        p = jws.payload
        vc = p.get("vc")
        if not isinstance(vc, dict):
            raise ValueError("Domain Linkage Credential needs a vc claim")
        subject = vc.get("credentialSubject") or {}
        types = vc.get("type") or []
        if p.get("iss") != did or p.get("sub") != did or subject.get("id") != did:
            raise ValueError("iss, sub and credentialSubject.id must all be the operator DID")
        if "DomainLinkageCredential" not in types:
            raise ValueError("type must include DomainLinkageCredential")
        if subject.get("origin", "").rstrip("/") != f"https://{domain}":
            raise ValueError(f"origin must be https://{domain}")
        now = self.clock()
        if "exp" in p and _int(p, "exp") <= now:
            raise ValueError("Domain Linkage Credential has expired")
        if "nbf" in p and _int(p, "nbf") > now + 60:
            raise ValueError("Domain Linkage Credential is not yet valid")
        return did

    # -- delegation-01 ---------------------------------------------------------------------

    async def delegation01(self, token: Any, agent_did: str, operator_did: str,
                           tier: str) -> Delegation:
        if not isinstance(token, str):
            raise AcmeProblem("malformed", "delegation-01 needs {\"delegation\": <vc+jwt>}")
        try:
            jws = jose.parse(token)
        except jose.JoseError as err:
            raise AcmeProblem("malformed", f"delegation: {err}") from None
        if jws.typ != "vc+jwt" or not jws.kid:
            raise AcmeProblem("malformed", "delegation must be a vc+jwt with a kid")
        p = jws.payload
        if p.get("issuer") != operator_did or split_did_url(jws.kid)[0] != operator_did:
            raise AcmeProblem("unauthorized", "delegation is not signed by the operator DID", 403)
        try:
            jose.verify(jws, await self._key(jws.kid, ASSERTION_METHOD))
        except jose.JoseError as err:
            raise AcmeProblem("unauthorized", f"delegation signature: {err}", 403) from None
        if DELEGATION_TYPE not in (p.get("type") or []):
            raise AcmeProblem("malformed", f"delegation type must include {DELEGATION_TYPE}")
        subject = p.get("credentialSubject")
        if not isinstance(subject, dict) or subject.get("id") != agent_did:
            raise AcmeProblem("unauthorized", "delegation is for a different agent", 403)
        now = int(self.clock())
        try:
            iat, exp = _int(p, "iat"), _int(p, "exp")
        except ValueError as err:
            raise AcmeProblem("malformed", f"delegation: {err}") from None
        if exp <= now:
            raise AcmeProblem("unauthorized", "delegation has expired", 403)
        if iat > now + 60:
            raise AcmeProblem("unauthorized", "delegation is not yet valid", 403)
        if exp - iat > self.config.delegation_max_lifetime:
            raise AcmeProblem("unauthorized", "delegation lifetime is over 90 days", 403)
        environment = subject.get("environment")
        if environment != self.config.environment:
            raise AcmeProblem("unauthorized",
                              f"delegation is for environment {environment!r}, this issuer is "
                              f"{self.config.environment!r}", 403)
        scopes = subject.get("scopes")
        if not isinstance(scopes, list) or not scopes or not all(isinstance(s, str) for s in scopes):
            raise AcmeProblem("malformed", "delegation needs a non-empty scopes list")
        allowed = self.config.scopes_for_tier(tier)
        outside = sorted(set(scopes) - allowed)
        if outside:
            raise AcmeProblem("unauthorized", f"scopes not allowed at {tier} tier: {outside}", 403)
        role = subject.get("accountableRole")
        if not isinstance(role, str) or not role.strip() or len(role) > 120:
            raise AcmeProblem("malformed", "delegation needs an accountableRole (a role title)")
        max_lifetime = subject.get("maxLifetime", self.config.agent_credential_default_lifetime)
        if not isinstance(max_lifetime, int) or isinstance(max_lifetime, bool) or max_lifetime < 300:
            raise AcmeProblem("malformed", "maxLifetime must be an integer number of seconds, at least 300")
        limits = self._limits(subject.get("limits"))
        audiences = subject.get("audiences") or []
        if not isinstance(audiences, list) or not all(isinstance(a, str) for a in audiences):
            raise AcmeProblem("malformed", "audiences must be a list of strings")
        return Delegation(
            jwt=token, id=str(p.get("id") or ""), operator=operator_did, agent=agent_did,
            scopes=sorted(set(scopes)), accountable_role=role.strip(),
            max_lifetime=min(max_lifetime, self.config.agent_credential_max_lifetime),
            valid_until=exp, environment=environment, limits=limits, audiences=audiences)

    def _limits(self, raw: Any) -> dict[str, str] | None:
        if raw is None:
            return None
        if not isinstance(raw, dict) or set(raw) - {"currency", "perPayment", "perDay"}:
            raise AcmeProblem("malformed", "limits has currency, perPayment and perDay")
        currency, per_payment, per_day = raw.get("currency"), raw.get("perPayment"), raw.get("perDay")
        if not isinstance(currency, str) or not _CURRENCY.match(currency):
            raise AcmeProblem("malformed", "limits.currency must be an ISO 4217 code")
        for name, value in (("perPayment", per_payment), ("perDay", per_day)):
            if not isinstance(value, str) or not _AMOUNT.match(value):
                raise AcmeProblem("malformed", f"limits.{name} must be a decimal string such as \"500.00\"")
        try:
            pp, pd = Decimal(per_payment), Decimal(per_day)  # type: ignore[arg-type]
        except InvalidOperation:
            raise AcmeProblem("malformed", "limits amounts must be decimals") from None
        if pp > pd:
            raise AcmeProblem("malformed", "perPayment cannot exceed perDay")
        if (currency == self.config.two_person_currency
                and pp > Decimal(self.config.two_person_threshold)):
            # Approver Credentials (and so the two-person rule) arrive after Month 1.
            raise AcmeProblem(
                "unauthorized",
                f"single payments above {currency} {self.config.two_person_threshold} need two "
                "approvers; this issuer does not accept approver chains yet", 403)
        return {"currency": currency, "perPayment": per_payment, "perDay": per_day}

    # -- key binding (finalize) ---------------------------------------------------------

    async def key_binding(self, token: Any, *, subject_did: str, relationship: str,
                          finalize_url: str, request_nonce: str) -> str:
        """Verify the key-binding JWT that replaces the CSR. Returns its kid."""
        if not isinstance(token, str):
            raise AcmeProblem("malformed", "finalize needs {\"keyBinding\": <JWT>}")
        try:
            jws = jose.parse(token)
        except jose.JoseError as err:
            raise AcmeProblem("badCSR", f"key binding: {err}") from None
        if jws.typ != KB_TYP or not jws.kid:
            raise AcmeProblem("badCSR", f"key binding must have typ {KB_TYP} and a kid")
        try:
            kid_did, _ = split_did_url(jws.kid)
        except DidError as err:
            raise AcmeProblem("badCSR", str(err)) from None
        p = jws.payload
        if kid_did != subject_did or p.get("iss") != subject_did:
            raise AcmeProblem("badCSR", "key binding must be signed by the subject DID")
        if p.get("aud") != finalize_url:
            raise AcmeProblem("badCSR", "key binding aud must be this order's finalize URL")
        if p.get("nonce") != request_nonce:
            raise AcmeProblem("badCSR", "key binding nonce must be this request's ACME nonce")
        try:
            iat = _int(p, "iat")
        except ValueError as err:
            raise AcmeProblem("badCSR", str(err)) from None
        if abs(self.clock() - iat) > KB_MAX_AGE:
            raise AcmeProblem("badCSR", "key binding iat is not fresh")
        try:
            jose.verify(jws, await self._key(jws.kid, relationship))
        except jose.JoseError as err:
            raise AcmeProblem("badCSR", f"key binding signature: {err}") from None
        return jws.kid

    # -- where agent DIDs may live ---------------------------------------------------------

    def check_agent_location(self, agent_did: str, operator_domains: list[str], slug: str) -> None:
        segments = did_segments(agent_did)
        hosted = self.config.hosted_did_prefix.split(":")
        on_domain = (len(segments) == 3 and segments[0] in operator_domains
                     and segments[1] == "agents")
        on_veridact = segments[:-2] == hosted and len(segments) == len(hosted) + 2 \
            and segments[-2] == slug
        if not (on_domain or on_veridact):
            raise AcmeProblem(
                "rejectedIdentifier",
                "an agent DID must be did:webvh:{SCID}:{operator domain}:agents:{id} or "
                f"did:webvh:{{SCID}}:{self.config.hosted_did_prefix}:{slug}:{{id}}")
        if not _LABEL.match(segments[-1]):
            raise AcmeProblem("rejectedIdentifier", "agent id must be lowercase letters, digits or -")


def hosted_did_path(prefix: str, slug: str, agent_id: str) -> str:
    """URL path for a Veridact-hosted DID log, from the did:webvh prefix."""
    path = prefix.split(":")[1:]
    return "/" + "/".join(quote(p) for p in (*path, slug, agent_id))
