# veridact-lambda-authoriser

An API Gateway (REST) Lambda authoriser for Veridact pattern B. It challenges agents that arrive without a
presentation, verifies the ones that come back, and passes the agent's identity to your backend.

```
agent ── GET /claims/CLM-1/status ─────────────▶ API Gateway ──▶ authoriser: no presentation
      ◀─ 401  WWW-Authenticate: Veridact realm=…, nonce=…, scope=…        (Deny + challenge)
agent ── GET … Authorization: Veridact sd-jwt="…" ─▶ API Gateway ──▶ authoriser: verify, consume nonce
                                                              ──▶ backend, with $context.authorizer.veridact*
```

## How the challenge gets out

A Lambda authoriser cannot write response headers itself. It returns Deny with the challenge in its context, and
the template's `ACCESS_DENIED` gateway response turns that into a **401** carrying
`WWW-Authenticate: $context.authorizer.wwwAuthenticate` and a body of `{"decision", "code"}`. Two consequences:

- Every authoriser denial is a 401, including `SCOPE_NOT_HELD` and `TIER_TOO_LOW`. The `code` in the body says
  which, and only challenge-type denials carry a non-empty `WWW-Authenticate`.
- Result caching must stay **off** (`AuthorizerResultTtlInSeconds: 0`): every presentation carries a fresh nonce.
  With caching off, the authoriser needs no identity source, so it also runs when `Authorization` is missing,
  which is exactly when it has to issue the challenge.

HTTP APIs (API Gateway v2) cannot map authoriser context into a denial response, so pattern B there needs the
challenge served by your backend or the sidecar. This authoriser targets REST APIs.

## Nonces

Lambda runs many copies of the authoriser, and the retry rarely lands on the one that issued the nonce. Nonces live
in DynamoDB (`VERIDACT_NONCE_TABLE`): issued with a conditional put, consumed with a conditional delete, so of two
parallel replays exactly one succeeds. TTL cleans up the rest.

## Configure

| Variable | |
|---|---|
| `VERIDACT_CONFIG_JSON` | `{"audience": "https://api.bank.example", "governance_keys": {...}, "trust_list_url": "...", "min_tier": "organisation"}`, same fields as the [sidecar](../../sidecar) |
| `VERIDACT_ROUTES` | `{"GET /claims/{id}/status": {"scopes": ["fs:claims:read-status"], "risk": "low"}}`. Keys are the method and the **resource template**. Unlisted routes are denied |
| `VERIDACT_NONCE_TABLE` | DynamoDB table, partition key `nonce` (S), TTL attribute `expires` |
| `VERIDACT_REALM` | Realm in the challenge (default: the API id) |

On Allow, the backend reads `veridactAgent`, `veridactOperator`, `veridactOperatorDomains`, `veridactTier`,
`veridactScopes` (granted, space-separated), `veridactAgentKeyId`, `veridactAccountableRole`,
`veridactAgentCredential` and `veridactAgentCredentialExpires` from `$context.authorizer` (or
`event.requestContext.authorizer` in a Lambda proxy integration). The authoriser logs each decision's full
explanation to CloudWatch; callers see only the public code.

**Payments.** Authorisers never see the request body, so they cannot check an amount against delegation limits.
Protect payment routes with the scope here, and check limits in the backend with the
[library](../../verify) or the [sidecar](../../sidecar) (`payment` in `/v1/verify`).

## Deploy

```sh
cd integrations/aws-lambda
./build.sh                      # build/ for python3.13 x86_64
sam deploy --guided             # Audience, GovernanceKeys, TrustListUrl, MinTier, Routes
```

The template creates the nonce table, the authoriser, a REST API with one demo route
(`GET /claims/{id}/status` echoing the agent's identity) and the gateway responses. Point `vbot call` at the
`Endpoint` output, with the `Audience` you deployed (the agent signs for the URL's origin, so use a custom domain
whose origin equals `Audience`, or set `Audience` to the execute-api origin).

## Test

```sh
pip install -e ../../verify -e ../../sidecar -e '.[test]'
pytest
```

The tests use moto for DynamoDB and the verifier's mock network. The template passes `cfn-lint`; it has not yet
been deployed to a real account.
