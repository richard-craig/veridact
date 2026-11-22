# veridact-keycloak-bridge

Veridact pattern A for banks that run Keycloak. An agent trades a Veridact presentation for an ordinary Keycloak
access token, bound to its Veridact key with DPoP. Downstream APIs keep validating the JWTs they already
accept.

```
agent ─POST /token──────────────────────────────▶ bridge ─ 400 use_veridact_nonce, Veridact-Nonce: n
agent ─POST /token  subject_token=<VP for n>
                    DPoP: <proof for Keycloak's token endpoint, signed with the agent key>
        bridge: all eight Veridact checks · DPoP key = the agent's Veridact key · agent user provisioned
        bridge ─jwt-bearer grant (60-second assertion) + the agent's DPoP proof──▶ Keycloak
agent ◀─ {"access_token": …, "token_type": "DPoP", "scope": "fs:claims:read-status"}   (from Keycloak)
```

No Keycloak extension or custom build: the bridge uses the **JWT Authorization Grant** (RFC 7523), supported in
Keycloak from 26.6, and Keycloak's built-in DPoP. Keycloak issues every access token under the bank's own client,
scope and session policies. The bridge only signs short-lived assertions that one identity provider in one
realm trusts.

## Why a bridge

Keycloak cannot verify a Veridact presentation itself: it is an SD-JWT+KB bound to the agent's own key, the
credentials need status-list and trust-list checks, and the nonce is single-use. A Java token-exchange provider
could do it inside Keycloak, but it would build on Keycloak's internal token-exchange classes, which change
between releases. The bridge runs the reference verifier, then hands Keycloak something it already understands.

## What the bridge enforces

- **Every Veridact check** (the [verifier](../../verify)), with nonces it issues itself: a first request without
  `subject_token` returns `400 use_veridact_nonce` and a `Veridact-Nonce` header, as DPoP does for its nonces.
- **The DPoP key is the agent's Veridact key**, the one the Agent Credential's `cnf` names. Keycloak then binds the
  access token to it (`cnf.jkt`). Required by default (`require_dpop`).
- **Scopes**: the assertion carries only the scopes the agent holds (intersected with what it asked for), and
  Keycloak adds only those that exist as client scopes on the bridge's client.
- **One Keycloak user per agent**, created and linked on its first verified presentation:
  username `agent-<hash of the agent URL>`, federated identity = the agent URL, attributes `veridactOperator`,
  `veridactOperatorDomains`, `veridactTier`, `veridactAccountableRole`. Keycloak's grant requires the user to
  exist; disable the user to block the agent at the bank regardless of its credentials.

**Pattern C.** `grant_type=client_credentials` with `client_id` (the agent URL), the Client Attestation in an
`OAuth-Client-Attestation` header and a DPoP proof (`attest_jwt_client_auth_dpop`): the bridge checks the
attestation names this client and is bound to the DPoP key, then continues as for pattern A. Assertions carry
`act` (`sub`: the agent URL, `sub_profile`: `ai_agent`).

Public Veridact codes map to OAuth errors: `SCOPE_NOT_HELD` → `invalid_scope`, `VERIFICATION_UNAVAILABLE` → `503
temporarily_unavailable`, everything else → `invalid_grant` with the code as `error_description`.

## Set up

```sh
pip install -e ./verify -e ./sidecar -e ./integrations/keycloak

# 1. Configure the realm: identity provider, clients, client scopes, provisioning rights.
python -m veridact_bridge.setup_realm --keycloak https://sso.bank.example --realm bank \
  --admin-user admin --admin-password … \
  --bridge-issuer https://auth.bank.example --jwks-url https://auth.bank.example/.well-known/jwks.json
#    prints the "keycloak" block for bridge.json, with the generated client secrets

# 2. Run the bridge (behind TLS at https://auth.bank.example).
veridact-keycloak-bridge --config bridge.json --port 8095
```

`bridge.json`:

```json
{
  "base_url": "https://auth.bank.example",
  "verifier": {
    "governance_keys": { "veridact-governance-1": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
    "trust_list_url": "https://trust.veridact.net/trust-list.jwt",
    "min_tier": "organisation"
  },
  "keycloak": {
    "url": "https://sso.bank.example", "realm": "bank",
    "client_id": "veridact-bridge", "client_secret": "…",
    "admin_client_id": "veridact-admin", "admin_client_secret": "…"
  }
}
```

If Keycloak's public hostname differs from the URL the bridge uses to reach it, set `keycloak_issuer` (the
assertion `aud`) and `keycloak.public_token_endpoint` (the URL agents sign their DPoP proofs for).

## The agent side

```sh
vbot token https://auth.bank.example --scope fs:claims:read-status
```

The bridge publishes what agents need at `/.well-known/veridact-bridge`: the token endpoint, the audience to sign
presentations for, and `dpop_htu`. Its signing key is at `/.well-known/jwks.json`.

## Tested

- Against a stand-in Keycloak that follows the 26.6 source (`e2e/test_keycloak_bridge.py`): DPoP binding to the
  agent key, a stranger's DPoP key refused, scope and revocation refusals, nonce replay, Keycloak refusing an
  assertion signed by any other key, the `vbot token` command.
- Against a real Keycloak 26.6 container in CI (`e2e/test_keycloak_real.py`, the `keycloak` job): realm setup
  with `setup_realm`, then a DPoP-bound token for a real agent.

## Not yet

- Nonces are in memory, so run one bridge instance (or sticky sessions) until a shared store lands.
- Agent attributes are written when the user is created, not refreshed.
- Payment limits are not part of token exchange: check them at the API with the verifier or the sidecar.
