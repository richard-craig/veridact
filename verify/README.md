# veridact-verify

The reference verifier for [Veridact](../docs/specification.md) agent presentations. A relying party (a bank's
authorisation server, an API gateway authoriser or any service) uses it to decide whether to serve an AI agent.
Verification reads only public, signed, cacheable files. With a warm cache it makes no network calls, and no
issuer learns which agent was checked.

Status: alpha, tracking specification v0.1 plus the [v0.2 proposals](../docs/proposals/0.2-verifier-gaps.md).

## What it checks

The eight checks in the specification's "Verification at the relying party" section, in order. It stops at the
first failure.

| # | Check | Typical public codes |
|---|-------|----------------------|
| 1 | Compact JWS, `typ: vp+jwt`, `aud` is this relying party, nonce issued here and live, lifetime ≤ 120 s | `CHALLENGE_REQUIRED`, `AUTH_FAILED` |
| 2 | Resolve the agent's did:webvh log, verify its hash chain and proofs, verify the presentation with an `authentication` key; consume the nonce | `AUTH_FAILED` |
| 3 | Unwrap the enveloped Agent and Operator Credentials; verify each with an `assertionMethod` key of its issuer | `AUTH_FAILED` |
| 4 | Trust list accredits each issuer for the credential type and tier, and lists the signing key for its signing time | `ISSUER_UNTRUSTED` |
| 5 | Validity windows and lifetime caps; revocation status of both credentials; degraded-mode policy | `CREDENTIAL_EXPIRED`, `AUTH_FAILED`, `VERIFICATION_UNAVAILABLE` |
| 6 | The Agent Credential's subject is the holder, and its `cnf` key signed the presentation | `AUTH_FAILED` |
| 7 | The Agent Credential names the Operator Credential's subject and id | `AUTH_FAILED` |
| 8 | Relying-party policy: minimum tier, allowed operators, scopes, payment limits | `TIER_TOO_LOW`, `OPERATOR_NOT_ALLOWED`, `SCOPE_NOT_HELD`, `LIMIT_PER_PAYMENT`, `LIMIT_PER_DAY` |

did:webvh log verification (SCID, hash chain, eddsa-jcs-2022 proofs, pre-rotation, witness rules) is delegated
to the [did-webvh](https://pypi.org/project/did-webvh/) reference library. All Veridact signatures are ES256.
Every other `alg` is refused before parsing goes further.

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

# The agent retries with: Authorization: Veridact vp="<VP-JWT>"
vp = Verifier.presentation_from_authorization(headers["Authorization"])
decision = await verifier.verify(vp, route)

if decision.allowed:
    ...                                  # decision.scopes_granted, decision.operator, decision.tier
response_body = decision.public()        # {"decision": "deny", "code": "AUTH_FAILED"}: safe for the caller
audit_log.info(decision.log_record())    # full explanation, for your logs only
```

For pattern A (token exchange), verify the `subject_token` the same way. If the decision is `allow`, issue a
DPoP-bound access token with `decision.scopes_granted` intersected with customer consent, bound to
`decision.agent_key_id`.

Payments: pass `Request(payment=Payment(amount, "ZAR", spent_today))`. The verifier is stateless about money:
`spent_today` comes from your own ledger. A payment over the delegated limits returns `ask_person`, with the
exact action in `decision.context["intent"]`.

## Deployment notes

- **Trust anchor.** `governance_keys` is the only thing you configure by hand. Pin it like a root CA.
- **Nonces.** `InMemoryNonceStore` suits one process. Behind a load balancer, implement `NonceStore` on a shared
  store with an atomic consume (a Redis `GETDEL`, or a DynamoDB conditional delete).
- **Outbound fetching.** The agent's DID is chosen by the caller, so the verifier fetches from the agent's
  operator's domain. It fetches over HTTPS only, without redirects, under a size cap. Run it with an egress
  allowlist or behind a member mirror (`FallbackFetcher([MirrorFetcher(mirror_url, HttpFetcher()), HttpFetcher()])`).
  Issuer DIDs are resolved only if the trust list names them.
- **Caching.** DID documents and status lists are cached for 5 minutes and the trust list for 1 hour. On refresh
  failure, the last good copy is used within the degraded-mode policy (default: flag medium-risk actions after 5
  minutes, block high-risk; block everything after 4 hours). A file that fails verification is never cached, so a
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
agent, did:webvh logs, status lists and trust list. The language-neutral
[conformance vectors](../conformance) run as part of the suite.

## Not yet

- HTTP sidecar with a `/verify` endpoint, and reference integrations (Lambda authoriser, token-exchange handler)
- Transparency log inclusion proofs (spec: "Relying parties may require one at Organisation tier")
- Witness requirements for issuer DIDs taken from the trust list
- Trust Registry Query Protocol lookups, as an alternative to the downloaded list
