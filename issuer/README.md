# veridact-issuer

A staging ACME-A issuer for Veridact: it validates operators, issues Operator and Agent Credentials, logs every
credential before release, and publishes the issuer DID, status lists and (in staging only) a trust list.

Status: alpha, **staging only**. Domain tier. Tracks [specification v0.2](../docs/specification.md); the
wire-format choices the spec leaves open are in [v0.3 proposals](../docs/proposals/0.3-issuer-gaps.md).

## Run it

```sh
pip install -e ./verify -e './issuer[dns]'
veridact-issuer init  --base-url https://staging.veridact.net --data-dir ./issuer-data
veridact-issuer serve --base-url https://staging.veridact.net --data-dir ./issuer-data --port 8080
```

`base_url` is the canonical https origin. It is signed into the issuer DID, every status list URL and every ACME
URL, so put TLS termination (a load balancer or CDN) in front with that name. For local work without TLS, see
[`deploy/`](../deploy): `--route host=url` makes the issuer fetch an operator's `https://host/...` from a local
address while keeping the canonical URL.

Configuration can also come from a JSON file (`--config`); every field is in
[`config.py`](src/veridact_issuer/config.py).

## What it serves

| Path | |
|---|---|
| `GET /directory` | ACME directory, with `veridactTiers`, `veridactEnvironment`, `veridactIssuer`, `trustList` |
| `HEAD /acme/new-nonce`, `POST /acme/new-account`, `/acme/new-order`, `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/chall/{id}`, `/acme/order/{id}/finalize`, `/acme/cred/{id}`, `/acme/revoke-cred` | ACME-A (RFC 8555, ES256 only) |
| `GET /acme/renewal-info/{id}` | ARI suggested renewal window (two thirds to five sixths through the lifetime) |
| `POST /acme/did/{agent id}` | Upload a Veridact-hosted agent DID log (verified, append-only) |
| `GET /issuers/{name}/did.jsonl` | The issuer's did:webvh log (with pre-rotation) |
| `GET /dids/{slug}/{agent}/did.jsonl` | Veridact-hosted agent DIDs |
| `GET /status/{agents\|operators}/{n}` | Bitstring Status Lists: 131,072 entries, re-signed at least every 4 minutes, `exp` 4 hours |
| `GET /trust-list.jwt`, `GET /governance-keys.json` | **Staging only**: a trust list naming this issuer, signed by a staging governance key |
| `GET /log/entries?start=&count=` | The transparency log, for operators watching their domains |

## What it checks

- **dns-01**: TXT at `_acme-challenge.{domain}` (single vantage point today).
- **did-config-01**: a DIF Domain Linkage JWT at `https://{domain}/.well-known/did-configuration.json`, signed by
  `did:webvh:{SCID}:{domain}`, whose log is resolved and verified with `veridact-verify`.
- **delegation-01**: a Delegation Credential signed by an operator DID that holds a valid, unrevoked Operator
  Credential *on the same account*; scopes inside the tier's policy; at most 90 days; matching environment;
  per-payment limits above R1,000 refused until approver chains exist.
- **finalize**: a key-binding JWT from the subject DID, bound to the order's finalize URL and the request's ACME
  nonce. Agent keys must be `authentication` keys; operator keys `assertionMethod` keys.
- **Agent DID location**: on the operator's domain (`{domain}:agents:{id}`) or under the account's own slug on
  the issuer's DID hosting.

## Before production (Month 2)

| Today (staging) | Production |
|---|---|
| Software signing key on disk | AWS KMS / CloudHSM, non-exportable, dual control (`Signer` is the seam) |
| The issuer signs its own trust list | The governance authority signs it, with keys held apart from every issuer |
| SQLite, one process, in-memory ACME nonces | Postgres or DynamoDB, several instances, shared nonce store |
| Hash-chained log, no proofs | Tile-based Merkle log, inclusion proofs in receipts, witness-cosigned tree heads, two logs |
| dns-01 from one vantage point | Three vantage points that must agree |
| No issuer DID witnesses | Two member-run witnesses on issuer DID updates |
| Domain tier only | Organisation tier: CIPC or vLEI review, 12-month re-validation |
| Per-account order limit only | Per-account and per-domain rate limits |
