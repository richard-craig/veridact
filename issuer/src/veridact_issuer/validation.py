"""Challenge validation and key-binding proofs (specification v0.5: Issuance protocol).

dns-01              control of the operator's domain (a TXT record, as in RFC 8555)
operator-keys-01    https://{domain}/.well-known/veridact-operator.json names the operator
                    and lists the key it will sign delegations with
client-metadata-01  the agent URL serves a Client ID Metadata Document whose client_id is
                    the URL and whose jwks hold the agent's key
delegation-01       the operator authorised this agent: a Delegation Credential (SD-JWT VC)
                    signed by a logged operator key

Every document is read fresh (no cache) at issuance, with the same parsers relying parties
use (veridact-verify), so the issuer cannot accept something verifiers would reject.
Production adds checks from several network vantage points.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from veridact_verify import jose, sdjwt
from veridact_verify.fetch import Fetcher, FetchError
from veridact_verify.identifiers import (
    VCT_DELEGATION,
    IdentifierError,
    operator_metadata_url,
    operator_url,
    parse_client_metadata,
    parse_operator_metadata,
)

from .acme import AcmeProblem, dns01_txt_value
from .config import IssuerConfig

KB_TYP = "veridact-kb+jwt"
KB_MAX_AGE = 300
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


def agent_id_of(agent_url: str, operator_domains: list[str], slug: str, hosting_url: str) -> str:
    """Where an agent may live: https://{operator domain}/agents/{id}, or
    {hosting_url}/{operator slug}/{id} when Veridact hosts its metadata. Returns the id."""
    if not isinstance(agent_url, str):
        raise AcmeProblem("rejectedIdentifier", "agent value must be the agent's https URL")
    parts = urlsplit(agent_url)
    host = parts.netloc
    segments = parts.path.split("/")[1:]
    hosted = urlsplit(hosting_url)
    hosted_prefix = hosted.path.split("/")[1:]
    on_domain = (parts.scheme == "https" and host in operator_domains and len(segments) == 2
                 and segments[0] == "agents")
    on_veridact = (parts.scheme == "https" and host == hosted.netloc
                   and segments[:-2] == hosted_prefix and len(segments) == len(hosted_prefix) + 2
                   and segments[-2] == slug)
    if parts.query or parts.fragment or not (on_domain or on_veridact):
        raise AcmeProblem(
            "rejectedIdentifier",
            "an agent URL must be https://{operator domain}/agents/{id} or "
            f"{hosting_url}/{slug}/{{id}}")
    if not _LABEL.match(segments[-1]):
        raise AcmeProblem("rejectedIdentifier", "agent id must be lowercase letters, digits or -")
    return segments[-1]


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
    operator_key: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"jwt": self.jwt, "id": self.id, "operator": self.operator, "agent": self.agent,
                "scopes": self.scopes, "accountable_role": self.accountable_role,
                "max_lifetime": self.max_lifetime, "valid_until": self.valid_until,
                "environment": self.environment, "limits": self.limits, "audiences": self.audiences,
                "operator_key": self.operator_key}


class Validator:
    def __init__(self, config: IssuerConfig, fetcher: Fetcher, *,
                 txt: TxtResolver | None = None, clock: Callable[[], float] = time.time,
                 local: Callable[[str], bytes | None] | None = None):
        self.config = config
        self.fetcher = fetcher
        self.txt = txt or DnsPythonResolver()
        self.clock = clock
        # Documents the issuer serves itself (Veridact-hosted CIMDs) are read from its store.
        self.local = local or (lambda url: None)

    async def _fetch(self, url: str) -> bytes:
        local = self.local(url)
        if local is not None:
            return local
        try:
            return await self.fetcher.fetch(url)
        except FetchError as err:
            raise AcmeProblem("connection", f"cannot fetch {url}: {err}") from None

    # -- dns-01 ------------------------------------------------------------------------

    async def dns01(self, domain: str, token: str, account_jwk: dict[str, str]) -> None:
        expected = dns01_txt_value(token, account_jwk)
        records = await self.txt.txt(f"_acme-challenge.{domain}")
        if expected not in records:
            raise AcmeProblem("incorrectResponse",
                              f"no TXT record _acme-challenge.{domain} with the expected value")

    # -- operator-keys-01 ----------------------------------------------------------------

    async def operator_keys(self, domain: str) -> dict[str, dict[str, Any]]:
        """The operator's published delegation keys, thumbprint -> JWK."""
        operator = operator_url(domain)
        body = await self._fetch(operator_metadata_url(operator))
        try:
            return parse_operator_metadata(operator, body)
        except IdentifierError as err:
            raise AcmeProblem("incorrectResponse", f"veridact-operator.json: {err}") from None

    async def operator_keys01(self, domain: str, want: Any) -> str:
        """Check the operator document; return the thumbprint of the key the operator named."""
        keys = await self.operator_keys(domain)
        if want is None and len(keys) == 1:
            return next(iter(keys))
        if not isinstance(want, str) or want not in keys:
            raise AcmeProblem("incorrectResponse",
                              "name the delegation key ({\"key\": <JWK thumbprint>}) the document lists")
        return want

    # -- client-metadata-01 ----------------------------------------------------------------

    async def client_keys(self, agent_url: str) -> dict[str, dict[str, Any]]:
        body = await self._fetch(agent_url)
        try:
            return parse_client_metadata(agent_url, body)
        except IdentifierError as err:
            raise AcmeProblem("incorrectResponse", f"client metadata: {err}") from None

    # -- delegation-01 ---------------------------------------------------------------------

    async def delegation01(self, token: Any, agent_url: str, operator: str, tier: str,
                           operator_keys: dict[str, dict[str, Any]],
                           key_is_logged: Callable[[str, str], bool]) -> Delegation:
        if not isinstance(token, str):
            raise AcmeProblem("malformed", "delegation-01 needs {\"delegation\": <SD-JWT VC>}")
        try:
            parsed = sdjwt.parse(token)
            claims = parsed.claims()
        except sdjwt.SdJwtError as err:
            raise AcmeProblem("malformed", f"delegation: {err}") from None
        jws = parsed.jws
        if jws.typ != sdjwt.SD_JWT_TYP or claims.get("vct") != VCT_DELEGATION:
            raise AcmeProblem("malformed", f"delegation must be a dc+sd-jwt with vct {VCT_DELEGATION}")
        if claims.get("iss") != operator:
            raise AcmeProblem("unauthorized", "delegation is not issued by the operator", 403)
        jwk = operator_keys.get(jws.kid or "")
        if jwk is None:
            raise AcmeProblem("unauthorized",
                              "delegation kid is not a key in the operator's veridact-operator.json", 403)
        if not key_is_logged(operator, jws.kid or ""):
            raise AcmeProblem("unauthorized", "the operator key has no logged add event", 403)
        try:
            jose.verify(jws, jose.key_from_jwk({k: jwk[k] for k in ("kty", "crv", "x", "y")}))
        except jose.JoseError as err:
            raise AcmeProblem("unauthorized", f"delegation signature: {err}", 403) from None
        if claims.get("sub") != agent_url:
            raise AcmeProblem("unauthorized", "delegation is for a different agent", 403)
        now = int(self.clock())
        try:
            iat, exp = _int(claims, "iat"), _int(claims, "exp")
        except ValueError as err:
            raise AcmeProblem("malformed", f"delegation: {err}") from None
        if exp <= now:
            raise AcmeProblem("unauthorized", "delegation has expired", 403)
        if iat > now + 60:
            raise AcmeProblem("unauthorized", "delegation is not yet valid", 403)
        if exp - iat > self.config.delegation_max_lifetime:
            raise AcmeProblem("unauthorized", "delegation lifetime is over 90 days", 403)
        environment = claims.get("environment")
        if environment != self.config.environment:
            raise AcmeProblem("unauthorized",
                              f"delegation is for environment {environment!r}, this issuer is "
                              f"{self.config.environment!r}", 403)
        scopes = claims.get("scopes")
        if not isinstance(scopes, list) or not scopes or not all(isinstance(x, str) for x in scopes):
            raise AcmeProblem("malformed", "delegation needs a non-empty scopes list")
        allowed = self.config.scopes_for_tier(tier)
        outside = sorted(set(scopes) - allowed)
        if outside:
            raise AcmeProblem("unauthorized", f"scopes not allowed at {tier} tier: {outside}", 403)
        role = claims.get("accountable_role")
        if not isinstance(role, str) or not role.strip() or len(role) > 120:
            raise AcmeProblem("malformed", "delegation needs an accountable_role (a role title)")
        max_lifetime = claims.get("max_lifetime", self.config.agent_credential_default_lifetime)
        if not isinstance(max_lifetime, int) or isinstance(max_lifetime, bool) or max_lifetime < 300:
            raise AcmeProblem("malformed", "max_lifetime must be an integer number of seconds, at least 300")
        limits = self._limits(claims.get("limits"))
        audiences = claims.get("audiences") or []
        if not isinstance(audiences, list) or not all(isinstance(x, str) for x in audiences):
            raise AcmeProblem("malformed", "audiences must be a list of strings")
        return Delegation(
            jwt=token, id=str(claims.get("jti") or ""), operator=operator, agent=agent_url,
            scopes=sorted(set(scopes)), accountable_role=role.strip(),
            max_lifetime=min(max_lifetime, self.config.agent_credential_max_lifetime),
            valid_until=exp, environment=environment, limits=limits, audiences=audiences,
            operator_key=jws.kid or "")

    def _limits(self, raw: Any) -> dict[str, str] | None:
        if raw is None:
            return None
        if not isinstance(raw, dict) or set(raw) - {"currency", "per_payment", "per_day"}:
            raise AcmeProblem("malformed", "limits has currency, per_payment and per_day")
        currency, per_payment, per_day = raw.get("currency"), raw.get("per_payment"), raw.get("per_day")
        if not isinstance(currency, str) or not _CURRENCY.match(currency):
            raise AcmeProblem("malformed", "limits.currency must be an ISO 4217 code")
        for name, value in (("per_payment", per_payment), ("per_day", per_day)):
            if not isinstance(value, str) or not _AMOUNT.match(value):
                raise AcmeProblem("malformed", f"limits.{name} must be a decimal string such as \"500.00\"")
        try:
            pp, pd = Decimal(per_payment), Decimal(per_day)  # type: ignore[arg-type]
        except InvalidOperation:
            raise AcmeProblem("malformed", "limits amounts must be decimals") from None
        if pp > pd:
            raise AcmeProblem("malformed", "per_payment cannot exceed per_day")
        if (currency == self.config.two_person_currency
                and pp > Decimal(self.config.two_person_threshold)):
            # Approver Credentials (and so the two-person rule) arrive after Month 1.
            raise AcmeProblem(
                "unauthorized",
                f"single payments above {currency} {self.config.two_person_threshold} need two "
                "approvers; this issuer does not accept approver chains yet", 403)
        return {"currency": currency, "per_payment": per_payment, "per_day": per_day}

    # -- key binding (finalize) ---------------------------------------------------------

    def key_binding(self, token: Any, *, subject: str, keys: dict[str, dict[str, Any]],
                    finalize_url: str, request_nonce: str) -> str:
        """Verify the key-binding JWT that replaces the CSR. Its kid is the JWK thumbprint of a
        key in ``keys`` (the subject's published keys). Returns that thumbprint."""
        if not isinstance(token, str):
            raise AcmeProblem("malformed", "finalize needs {\"keyBinding\": <JWT>}")
        try:
            jws = jose.parse(token)
        except jose.JoseError as err:
            raise AcmeProblem("badCSR", f"key binding: {err}") from None
        if jws.typ != KB_TYP or not jws.kid:
            raise AcmeProblem("badCSR", f"key binding must have typ {KB_TYP} and a kid (the JWK thumbprint)")
        jwk = keys.get(jws.kid)
        if jwk is None:
            raise AcmeProblem("badCSR", "the key-binding kid is not a key the subject publishes")
        p = jws.payload
        if p.get("iss") != subject:
            raise AcmeProblem("badCSR", "key binding iss must be the subject")
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
            jose.verify(jws, jose.key_from_jwk({k: jwk[k] for k in ("kty", "crv", "x", "y")}))
        except jose.JoseError as err:
            raise AcmeProblem("badCSR", f"key binding signature: {err}") from None
        return jws.kid
