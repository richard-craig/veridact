# veridact-attester

A reference **known-assistant attester** for Veridact v0.5 ([proposal §6 and §7](../docs/proposals/0.5-sd-jwt-vc.md)).

Mainstream assistants such as Claude, ChatGPT, Gemini and Copilot connect to a bank as one OAuth client per
platform. They do not hold Veridact keys or run ACME-A. So Veridact checks the platform's operator itself and issues
a credential *about* the platform: a **known-assistant entry**. Relying parties check it locally, and one status
change stops that assistant at every relying party on its next check. The platform takes no part.

| Published for relying parties | |
|---|---|
| `GET /.well-known/jwt-vc-issuer` | JWT VC Issuer Metadata: the issuer's keys |
| `GET /known-assistants` | The entries, summarised |
| `GET /known-assistants/{id}` | The entry, an SD-JWT VC (`typ` `dc+sd-jwt`, `vct` `https://veridact.net/vct/known-assistant/v1`) |
| `GET /status/known-assistants/1` | The Token Status List (`typ` `statuslist+jwt`, 2 bits: valid, withdrawn, suspended) |

| Admin (needs `VERIDACT_ADMIN_SECRET`; also restrict it by network) | |
|---|---|
| `GET /admin` | A small page to suspend, restore or withdraw an entry |
| `POST /admin/known-assistants/{id}/status` | `{"status": "suspended", "reason": "…"}` with `Authorization: Bearer <secret>` |

A withdrawn entry cannot be restored: issue a new one. A suspended entry can be.

## Run

```bash
pip install ./verify ./attester
VERIDACT_ISSUER=http://localhost:8100 VERIDACT_ADMIN_SECRET=change-me veridact-attester serve
```

| Setting | Default | |
|---|---|---|
| `VERIDACT_ISSUER` | `http://localhost:8100` | The public URL: the `iss` of every artefact |
| `VERIDACT_DATA` | `./attester-data` | Issuer key and the state file |
| `VERIDACT_ADMIN_SECRET` | (none: admin off) | Bearer secret for status changes |
| `VERIDACT_STATUS_TTL` | `300` | The status list's `ttl`; a demo can set it lower so a suspension shows quickly |

## What this is not

A demonstration and pilot attester, not the production service. Its keys are software keys on disk, its state is a
JSON file, and its two entries (Claude, operated by Anthropic PBC; ChatGPT, operated by OpenAI OpCo, LLC) are seeded for the Veridact Valet demo, not a statement
made by or with Anthropic. A production attester keeps its keys in an HSM, is named in the governance-signed trust
list, validates operators by documentary review with a published procedure, tells a platform before withdrawing its
entry where possible, and logs every issuance and status change to the transparency log.
