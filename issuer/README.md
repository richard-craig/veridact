# veridact-issuer

A staging ACME-A issuer for Veridact: it validates operators, issues Operator and Agent Credentials as SD-JWT VCs,
logs every credential and key event before it takes effect, and publishes its issuer metadata, Token Status Lists,
hosted agent metadata, known-assistant entries and (in staging only) a trust list.

Status: alpha, **staging only**. Domain tier by default. Tracks [specification v0.5](../docs/specification.md).

## Run it

```sh
pip install -e ./verify -e './issuer[dns]'
veridact-issuer init  --base-url https://staging.veridact.net --data-dir ./issuer-data
veridact-issuer serve --base-url https://staging.veridact.net --data-dir ./issuer-data --port 8080
```

`base_url` is the canonical https origin. It is signed into the issuer identifier, every status list URL and every ACME
URL, so put TLS termination (a load balancer or CDN) in front with that name. For local work without TLS, see
[`deploy/`](../deploy): `--route host=url` makes the issuer fetch an operator's `https://host/...` from a local
address while keeping the canonical URL.

Configuration can also come from a JSON file (`--config`); every field is in
[`config.py`](src/veridact_issuer/config.py).

## What it serves

| Path | |
|---|---|
| `GET /directory` | ACME directory, with `veridactTiers`, `veridactEnvironment`, `veridactIssuer`, `veridactAgentHosting`, `veridactFormats`, `trustList` |
| `HEAD /acme/new-nonce`, `POST /acme/new-account`, `/acme/new-order`, `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/chall/{id}`, `/acme/order/{id}/finalize`, `/acme/cred/{id}`, `/acme/revoke-cred` | ACME-A (RFC 8555, ES256 only); credentials download as `application/dc+sd-jwt` |
| `POST /acme/cred/{id}/attestation` | The Client Attestation form (pattern C), when the order's `formats` include `client-attestation` |
| `GET /acme/renewal-info/{id}` | ARI suggested renewal window (two thirds to five sixths through the lifetime) |
| `POST /acme/agent-metadata/{agent id}` | Upload a Veridact-hosted agent's Client ID Metadata Document; new keys get add events, dropped keys are retired |
| `POST /acme/key-event` | Add, retire or report a compromised operator or agent key; retire and compromise revoke every credential naming it |
| `GET /.well-known/jwt-vc-issuer/issuers/{name}` | JWT VC Issuer Metadata: the issuer's keys (the trust list pins the same keys by thumbprint) |
| `GET /agents/{slug}/{agent}` | Veridact-hosted agent Client ID Metadata Documents |
| `GET /assistants`, `GET /assistants/{id}` | Known-assistant entries (SD-JWT VC) |
| `GET /status/{agents\|operators\|assistants}/{n}` | Token Status Lists: 2-bit entries, 131,072 per list, re-signed at least every 4 minutes, `exp` 4 hours |
| `GET /trust-list.jwt`, `GET /governance-keys.json` | **Staging only**: a trust list naming this issuer, signed by a staging governance key |
| `GET /log/entries?start=&count=` | The transparency log (credentials and key events), for operators watching their domains |

## What it checks

- **dns-01**: TXT at `_acme-challenge.{domain}` (single vantage point today).
- **operator-keys-01**: `https://{domain}/.well-known/veridact-operator.json` names `https://{domain}` and lists the
  key the client names; finalize must be signed by that key, which becomes the Operator Credential's `cnf`.
- **delegation-01**: a Delegation Credential (SD-JWT VC) signed by a logged key of an operator that holds a valid,
  unrevoked Operator Credential *on the same account*; scopes inside the tier's policy; at most 90 days; matching
  environment; per-payment limits above R1,000 refused until approver chains exist. It also fetches the agent URL
  and checks it is a Client ID Metadata Document whose `client_id` is that URL.
- **finalize**: a key-binding JWT whose `kid` is the thumbprint of a key the subject publishes (the operator's
  document, or the agent's CIMD), bound to the order's finalize URL and the request's ACME nonce.
- **Agent location**: on the operator's domain (`https://{domain}/agents/{id}`) or under the account's own slug on
  the issuer's agent hosting.

## Known-assistant entries

```sh
veridact-issuer assistant issue claude --entry claude.json --config issuer.json   # Organisation tier only
veridact-issuer assistant suspend claude --config issuer.json                     # the kill switch
veridact-issuer assistant restore claude --config issuer.json
veridact-issuer assistant withdraw claude --config issuer.json                    # for good
```

`claude.json` holds the entry's claims (`sub`, `client_metadata_urls`, `operator`, `redirect_hosts`,
`token_endpoint_auth`, `published_egress`, `max_level`). Validation is documentary and done by a reviewer first.

## Before production (Month 2)

| Today (staging) | Production |
|---|---|
| Software signing key on disk | AWS KMS / CloudHSM, non-exportable, dual control (`Signer` is the seam) |
| The issuer signs its own trust list | The governance authority signs it, with keys held apart from every issuer |
| SQLite, one process, in-memory ACME nonces | Postgres or DynamoDB, several instances, shared nonce store |
| Hash-chained log, no proofs | Tile-based Merkle log, inclusion proofs in receipts, witness-cosigned tree heads, two logs |
| dns-01 from one vantage point | Three vantage points that must agree |
| Domain tier only | Organisation tier: CIPC or vLEI review, 12-month re-validation |
| Per-account order limit only | Per-account and per-domain rate limits |
