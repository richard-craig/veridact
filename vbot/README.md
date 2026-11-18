# vbot

The Veridact agent client: it gets your AI agents short-lived credentials over ACME-A and keeps them renewed,
the way certbot does for TLS certificates.

Status: alpha, tracking [specification v0.2](../docs/specification.md) and the
[v0.3 issuer proposals](../docs/proposals/0.3-issuer-gaps.md). Domain tier, software keys.

## Ten minutes, start to finish

```sh
pip install -e ./verify -e ./vbot

# 1. An ACME-A account and your operator DID
vbot init --issuer https://staging.veridact.net/directory --domain example.com

# 2. Publish the two files vbot wrote under ~/.vbot/publish/ at https://example.com/:
#      /.well-known/did.jsonl                  your operator DID log
#      /.well-known/did-configuration.json     links that DID to your domain
vbot operator                     # did-config-01; or --challenge dns-01 for a TXT record

# 3. An agent, its authority, its credential
vbot agent new                    # key + DID, hosted by the issuer (--on-domain to host it yourself)
vbot delegate --scope fs:claims:read-status --role "Head of Digital Claims" \
              --per-payment 500.00 --per-day 2000.00
vbot issue                        # an Agent Credential, valid for 8 hours

# 4. Use it
vbot call https://sandbox.veridact.net/claims/CLM-1001/status
vbot run                          # renews two thirds through each lifetime
```

`vbot call` handles pattern B for you: the API answers `401` with a `Veridact` challenge, vbot signs a
presentation for that nonce and retries with `Authorization: Veridact vp="…"`.

## Commands

| Command | Does |
|---|---|
| `init --issuer URL --domain D` | Registers an ACME-A account, creates the operator DID and the files to publish |
| `operator [--challenge dns-01]` | Proves the domain and obtains the Operator Credential (90 days at Domain tier) |
| `agent new [--on-domain] [--id]` | Creates an agent key and DID. Ids are random by default, because DIDs are public |
| `delegate --scope … --role …` | The operator signs a Delegation Credential: scopes, limits, accountable role, up to 90 days |
| `issue [--agent] [--lifetime 8h]` | Orders the Agent Credential (delegation-01, key-binding proof, download) |
| `run [--once]` | Keeps every agent renewed |
| `call URL [-X POST --json …]` | Calls a Veridact-protected API |
| `present --aud --nonce` | Prints a presentation, for wiring into other clients |
| `revoke AGENT\|operator` | Revokes a credential; it shows in the status list within minutes |
| `status` | Operator, agents, scopes and expiry |

State lives in `~/.vbot` (`--home` or `VBOT_HOME`): `state.json`, `keys/` (mode 0600) and `publish/`.

## As a library

```python
from vbot import Vbot, call

bot = Vbot.load("~/.vbot")
result = await call(bot, "https://api.bank.example/claims/CLM-1001/status", agent_id="a1b2c3")

# Or build the header yourself, for any HTTP client:
header = bot.authorization("a1b2c3", aud="https://api.bank.example", nonce=nonce_from_challenge)
```

## Not yet

- Keys in a TPM, cloud KMS or HSM (required from Organisation tier). `KeyStore` is the seam.
- Approver Credentials and the two-person rule: today the operator DID signs delegations itself, and the staging
  issuer refuses per-payment limits above R1,000 until approver chains exist.
- Dual issuance (two issuers at once, for failover).
- DID key rotation commands (the update keys and pre-rotation commitments are already stored).
