# veridact-sidecar

The [reference verifier](../verify) as a small HTTP service, for relying parties whose gateway or authorisation
server is not written in Python. Run it next to the component that makes the decision, on localhost or a private
network.

## Run it

```sh
pip install -e ./verify -e ./sidecar
VERIDACT_SIDECAR_TOKEN=change-me veridact-sidecar --config rp.json --port 8090
```

`rp.json`:

```json
{
  "audience": "https://api.bank.example",
  "governance_keys": { "veridact-governance-1": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "trust_list_url": "https://trust.veridact.net/trust-list.jwt",
  "min_tier": "organisation",
  "allowed_operators": null,
  "mirror_url": null
}
```

`governance_keys` is the trust anchor: pin it like a root CA. Or configure through the environment:
`VERIDACT_AUDIENCE`, `VERIDACT_GOVERNANCE_KEYS` (JSON), `VERIDACT_TRUST_LIST_URL`, `VERIDACT_MIN_TIER`,
`VERIDACT_MIRROR_URL`. With `VERIDACT_SIDECAR_TOKEN` set, callers must send `Authorization: Bearer <token>`.

## API

**Pattern B (gateway).** No `Authorization: Veridact` header yet? Ask for a challenge and return it as a 401:

```http
POST /v1/challenge
{"scopes": ["fs:claims:read-status"], "risk": "low", "realm": "claims-api"}

200 {"nonce": "9f2c…", "wwwAuthenticate": "Veridact realm=\"claims-api\", nonce=\"9f2c…\", tier=\"domain\", scope=\"fs:claims:read-status\""}
```

Then verify the retry:

```http
POST /v1/verify
{"authorization": "Veridact vp=\"eyJ…\"", "scopes": ["fs:claims:read-status"], "risk": "low"}

200 {"decision": "allow", "public": {"decision": "allow"}, "allowed": true,
     "agent": "did:webvh:…", "operator": "did:webvh:…", "operatorDomains": ["operator.example"],
     "tier": "domain", "scopesGranted": ["fs:claims:read-status"], "agentKeyId": "did:webvh:…#key-1",
     "accountableRole": "Head of Digital Claims", "flags": [], "log": {…}}
```

Return only `public` to the caller. `log` is the full explanation (which check, which reason) and belongs in your
logs. For payments, add `"payment": {"amount": "350.00", "currency": "ZAR", "spentToday": "0.00"}`; over the
delegated limits the decision is `ask_person` with an `intent`.

**Pattern A (token exchange).** Verify the `subject_token` the same way (`"presentation": "<VP-JWT>"`). On
`allow`, issue a DPoP-bound access token with `scopesGranted` (intersected with customer consent), bound to
`agentKeyId`.

## Deployment notes

- **One instance per nonce store.** Nonces are in memory, so a challenge issued by one instance cannot be
  verified by another. Behind a load balancer, use sticky sessions or a shared `NonceStore` (planned).
- **Egress.** The verifier fetches the agent's DID log from the operator's domain. Allow outbound HTTPS, or set
  `mirror_url` to a member mirror.
