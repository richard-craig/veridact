# vbot

The Veridact agent client: it gets your AI agents short-lived credentials over ACME-A and keeps them renewed,
the way certbot does for TLS certificates.

Status: alpha, tracking [specification v0.5](../docs/specification.md) (SD-JWT VC, HTTPS identifiers). Domain tier,
software keys.

## Ten minutes, start to finish

```sh
pip install -e ./verify -e ./vbot

# 1. An ACME-A account and your operator's delegation key
vbot init --issuer https://staging.veridact.net/directory --domain example.com

# 2. Publish the file vbot wrote under ~/.vbot/publish/ at https://example.com/:
#      /.well-known/veridact-operator.json     your operator id and delegation key
vbot operator                     # operator-keys-01; or --challenge dns-01 for a TXT record

# 3. An agent, its authority, its credential
vbot agent new                    # key + client metadata, hosted by the issuer (--on-domain to host it yourself)
vbot delegate --scope fs:claims:read-status --role "Head of Digital Claims" \
              --per-payment 500.00 --per-day 2000.00
vbot issue                        # an Agent Credential (SD-JWT VC), valid for 8 hours

# 4. Use it
vbot call https://sandbox.veridact.net/claims/CLM-1001/status
vbot run                          # renews two thirds through each lifetime
```

`vbot call` handles pattern B for you: the API answers `401` with a `Veridact` challenge, vbot signs a
presentation (an SD-JWT+KB) for that nonce and retries with `Authorization: Veridact sd-jwt="…"`. If the
challenge names claims in `disclose`, vbot discloses those and nothing else.

## Commands

| Command | Does |
|---|---|
| `init --issuer URL --domain D` | Registers an ACME-A account, creates the operator's delegation key and `veridact-operator.json` to publish |
| `operator [--challenge dns-01]` | Proves the domain and obtains the Operator Credential (90 days at Domain tier) |
| `agent new [--on-domain] [--id]` | Creates an agent key and its Client ID Metadata Document (the agent URL is its `client_id`). Ids are random by default, because the documents are public |
| `delegate --scope … --role …` | The operator signs a Delegation Credential (an SD-JWT VC): scopes, limits, accountable role, up to 90 days |
| `issue [--agent] [--lifetime 8h] [--attestation]` | Orders the Agent Credential (delegation-01, key-binding proof, download), and with `--attestation` its Client Attestation form for pattern C |
| `run [--once]` | Keeps every agent renewed |
| `call URL [-X POST --json …]` | Calls a Veridact-protected API |
| `present --aud --nonce [--disclose CLAIM]` | Prints a presentation (SD-JWT+KB), for wiring into other clients |
| `revoke AGENT\|operator` | Revokes a credential; it shows in the status list within minutes |
| `retire-key AGENT\|operator [--compromised]` | Logs a retire or compromise key event; the issuer revokes every credential naming the key |
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
- Approver Credentials and the two-person rule: today the operator's delegation key signs delegations itself, and the staging
  issuer refuses per-payment limits above R1,000 until approver chains exist.
- Dual issuance (two issuers at once, for failover).
- A key rotation command that publishes the new key before retiring the old one (`retire-key` covers the second half).
