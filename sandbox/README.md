# veridact-sandbox: Veridact Insurance

A pretend insurer API for trying agents against. It challenges like a real relying party, and then, unlike a real
one, explains every decision: which check ran, why it failed and what to do next.

| Route | Scope | Risk |
|---|---|---|
| `GET /claims/{id}/status` (CLM-1001 to CLM-1003) | `fs:claims:read-status` | low |
| `POST /quotes` `{"product": "car", "value": "250000.00"}` | `fs:quotes:create` | medium |
| `POST /payments` `{"amount": "350.00", "currency": "ZAR"}` | `fs:payments:initiate` | high, delegation limits apply |

```sh
vbot call https://sandbox.veridact.net/claims/CLM-1001/status
```

```json
{ "decision": "deny", "code": "SCOPE_NOT_HELD",
  "hint": "Delegate the scope: `vbot delegate --scope ...`, then `vbot issue`.",
  "explain": { "reason": "SCOPE_NOT_HELD", "check": 8, "scopesHeld": ["fs:claims:read-status"], … } }
```

**Do not copy `explain` into a real API.** Telling a caller which cryptographic check failed helps an attacker; a
production relying party returns only `{"decision", "code"}` (see [the sidecar](../sidecar)).

## Run it

```sh
veridact-sandbox --audience https://sandbox.veridact.net \
  --trust-list https://staging.veridact.net/trust-list.jwt \
  --governance-keys-url https://staging.veridact.net/governance-keys.json
```

`--governance-keys-url` is a staging convenience. A production relying party pins its governance keys from an
out-of-band source. `--status-ttl 0` shows revocations at once; the default is the spec's 5 minutes.
