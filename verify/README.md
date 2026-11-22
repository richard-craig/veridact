# veridact-verify

The reference verifier for [Veridact](../docs/specification.md) agent presentations. A relying party (a bank's
authorisation server, an API gateway authoriser or any service) uses it to decide whether to serve an AI agent.
Verification reads only public, signed, cacheable files. With a warm cache it makes no network calls, and no
issuer learns which agent was checked.

Status: alpha, tracking specification v0.2.

## What it checks

The eight checks in the specification's "Verification at the relying party" section, in order. It stops at the
first failure.

| # | Check | Typical public codes |
|---|-------|----------------------|
| 1 | An SD-JWT+KB: the KB-JWT is `kb+jwt`, its `aud` is this relying party, its nonce was issued here and is live, its `iat` is within 120 s, and `sd_hash` covers the SD-JWT as presented | `CHALLENGE_REQUIRED`, `AUTH_FAILED` |
| 2 | The trust list names the credential's `iss`, before anything is fetched | `ISSUER_UNTRUSTED`, `VERIFICATION_UNAVAILABLE` |
| 3 | `typ: dc+sd-jwt` and the agent `vct`; the issuer's signature with a key pinned in the trust list *and* served in its JWT VC Issuer Metadata; every disclosure; the KB-JWT signature with `cnf.jwk`; then the nonce is consumed | `AUTH_FAILED` |
| 4 | The trust list accredits the issuer for the `vct` and tier, and lists the signing key for its `iat` | `ISSUER_UNTRUSTED` |
| 5 | `iat` ≤ `nbf` < `exp`, lifetime caps; Token Status List entries for `status` and `operator_status`; degraded-mode policy | `CREDENTIAL_EXPIRED`, `AUTH_FAILED`, `VERIFICATION_UNAVAILABLE` |
| 6 | Key binding: the KB-JWT is signed by `cnf.jwk`, and `cnf_event` names the key's logged add event | `AUTH_FAILED` |
| 7 | Disclosure: every claim the policy or route requires (`required_disclosures`, `Request.disclose`) is disclosed | `AUTH_FAILED` |
| 8 | Relying-party policy: minimum tier, allowed operators, scopes, payment limits | `TIER_TOO_LOW`, `OPERATOR_NOT_ALLOWED`, `SCOPE_NOT_HELD`, `LIMIT_PER_PAYMENT`, `LIMIT_PER_DAY` |

SD-JWT parsing and disclosure checks ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) and Token Status Lists
are implemented in this package (`sdjwt.py`, `status.py`), small and ES256-only: every other `alg` is refused before
parsing goes further.

Two more entry points serve authorisation servers:

- `verify_client_attestation(attestation, client_id=…, dpop_jkt=…)`: pattern C, a Veridact Client Attestation
  presented with `attest_jwt_client_auth_dpop`. Check the DPoP proof yourself, then pass its key thumbprint.
- `verify_known_assistant(entry, client_id=…)`: a known-assistant entry (Claude, ChatGPT, …) matched to the OAuth
  client it describes; the decision carries the verified operator and `context["maxLevel"]`. A suspended entry is
  the kill switch.

## Use

```python
from veridact_verify import Payment, RelyingPartyPolicy, Request, Risk, Verifier

verifier = Verifier(
    RelyingPartyPolicy(audience="https://api.bank.example", min_tier="organisation"),
    governance_keys={"gov-2026a": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}},
)

route = Request(scopes=frozenset({"fs:claims:read-status"}), risk=Risk.LOW)

# Pattern B (gateway): no presentation yet, so issue a challenge.
nonce, www_authenticate = verifier.challenge(route, realm="claims-api")
# -> 401, WWW-Authenticate: Veridact realm="claims-api", nonce="…", tier="organisation", scope="…"

# The agent retries with: Authorization: Veridact sd-jwt="<SD-JWT+KB>"
presentation = Verifier.presentation_from_authorization(headers["Authorization"])
decision = await verifier.verify(presentation, route)

if decision.allowed:
    ...                                  # decision.scopes_granted, decision.operator, decision.tier
response_body = decision.public()        # {"decision": "deny", "code": "AUTH_FAILED"}: safe for the caller
audit_log.info(decision.log_record())    # full explanation, for your logs only
```

For pattern A (token exchange), verify the `subject_token` the same way. If the decision is `allow`, issue a
DPoP-bound access token with `decision.scopes_granted` intersected with customer consent, bound to
`decision.agent_key_id` (the RFC 7638 thumbprint of the credential's `cnf.jwk`; compare it with the DPoP proof's
key). `decision.disclosed` holds the selectively disclosed claims the agent showed, for example
`operator_legal_name` for a consent screen.

Payments: pass `Request(payment=Payment(amount, "ZAR", spent_today))`. The verifier is stateless about money:
`spent_today` comes from your own ledger. A payment over the delegated limits returns `ask_person`, with the
exact action in `decision.context["intent"]`.

## Deployment notes

- **Trust anchor.** `governance_keys` is the only thing you configure by hand. Pin it like a root CA.
- **Nonces.** `InMemoryNonceStore` suits one process. Behind a load balancer, implement `NonceStore` on a shared
  store with an atomic consume (a Redis `GETDEL`, or a DynamoDB conditional delete).
- **Outbound fetching.** The verifier fetches only issuer metadata and status lists, and only for issuers the
  trust list names, so a presentation cannot make it fetch arbitrary URLs. Nothing is fetched from the agent's or
  operator's domain. It fetches over HTTPS only, without redirects, under a size cap. Run it with an egress
  allowlist or behind a member mirror (`FallbackFetcher([MirrorFetcher(mirror_url, HttpFetcher()), HttpFetcher()])`).
- **Caching.** Issuer metadata and status lists are cached for 5 minutes and the trust list for 1 hour. On refresh
  failure, the last good copy is used within the degraded-mode policy. A status list's age is measured from its
  `iat` (default: flag medium-risk actions after 5 minutes, block high-risk; block everything after 4 hours). A file that fails verification is never cached, so a
  tampered mirror cannot displace a good copy.
- **Clock.** Inject `clock=` for tests. Production uses `time.time` with a 30-second skew allowance.

## Develop

```sh
cd verify
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

`veridact_verify.testing.MockNetwork` builds a complete mock network for tests: governance key, issuer, operator,
agent, issuer metadata, Token Status Lists, a client attestation, a known-assistant entry and the trust list. The language-neutral
[conformance vectors](../conformance) run as part of the suite.

## Not yet

- Transparency log inclusion proofs (spec: "Relying parties may require one at Organisation tier")
- Sub-agent grants (`veridact_grants`) and Verification Records
- Trust Registry Query Protocol lookups, as an alternative to the downloaded list
