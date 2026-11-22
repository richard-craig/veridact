# Veridact

**Short-lived, verifiable credentials for AI agents, issued the way Let's Encrypt issues certificates.**

When an AI agent calls a bank's or an insurer's API, the API needs answers to two questions before it serves the
request: *which organisation operates this agent and answers for it?* and *what has that organisation allowed it
to do?* Passwords and API keys can't answer either question.

Veridact answers both with open standards:

- **An identity for every agent:** an HTTPS URL that is also its OAuth `client_id` (a Client ID Metadata Document),
  with a key the agent holds and never exports.
- **Credentials that expire in hours:** SD-JWT Verifiable Credentials, the IETF OAuth format, with selective
  disclosure and Token Status Lists, issued and renewed automatically through **ACME-A**, a profile of ACME
  (RFC 8555), the protocol behind Let's Encrypt.
- **Known assistants:** credentials *about* mainstream assistants such as Claude and ChatGPT, so a bank can identify
  them, show their verified operator, and switch them off everywhere with one status entry.
- **A human at every point that matters:** authority flows from appointed approvers down to the agent, and nobody
  can delegate more than they hold.
- **Verification without calling home:** relying parties check credentials against signed, cacheable public files,
  so verification works through an issuer outage and no issuer learns where agents are used.
- **No secret issuance:** every credential goes into a public, append-only transparency log before it is released.

TLS is the right comparison: the protocol and the clients are open, and certificate authorities compete to run
issuance. Veridact works the same way.

## What's here

- [**Specification**](docs/specification.md) (v0.5): trust model, identifiers and keys, credential profiles,
  delegation and sub-agents, known-assistant entries, the ACME-A protocol, Agent Certificates, the verification checks and reason codes,
  the transparency log, archival verification, the trust registry, security, privacy and resilience.
- [**veridact-verify**](verify): the reference verifier library (Python, alpha). It runs all eight verification
  checks with reason codes, caching and degraded mode, and makes no call home.
- [**veridact-issuer**](issuer): a staging ACME-A issuer (alpha, Domain tier). It validates operators with dns-01 or
  operator-keys-01 and agents with delegation-01, logs every credential and key event before it takes effect, and
  publishes issuer metadata, Token Status Lists, hosted agent metadata, known-assistant entries and a staging trust
  list.
- [**vbot**](vbot): the agent client. `vbot init`, `vbot operator`, `vbot agent new`, `vbot delegate`, `vbot issue`,
  then `vbot call` any Veridact-protected API and `vbot run` to stay renewed.
- [**veridact-sidecar**](sidecar): the verifier over HTTP (`/v1/challenge`, `/v1/verify`, `/v1/client-attestation`,
  `/v1/known-assistant`) for gateways and authorisation servers in any language.
- [**Lambda authoriser**](integrations/aws-lambda): pattern B on AWS API Gateway, with DynamoDB nonces and a SAM
  template.
- [**Keycloak bridge**](integrations/keycloak): patterns A and C for Keycloak 26.6+. An agent trades a presentation
  or its Client Attestation for a DPoP-bound Keycloak access token through the JWT Authorization Grant, with no
  Keycloak extension.
- [**veridact-sandbox**](sandbox): Veridact Insurance, a pretend insurer API that challenges agents and explains every
  decision.
- [**Conformance vectors**](conformance): language-neutral test cases for anyone implementing a verifier.
- [**Proposals**](docs/proposals): [v0.2](docs/proposals/0.2-verifier-gaps.md) (gaps found building the verifier,
  accepted), [v0.3](docs/proposals/0.3-issuer-gaps.md) (gaps found building the issuer, vbot and the
  integrations, accepted) and [v0.4](docs/proposals/0.4-iiw42-proposals.md) (sub-agents, actor claims, Agent
  Certificates and archival verification, from IIW 42, accepted) and
  [v0.5](docs/proposals/0.5-sd-jwt-vc.md) (SD-JWT VC, OAuth-native identifiers and known assistants, accepted and
  implemented).

## Try it

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ./verify -e './issuer[dns]' -e ./vbot -e ./sidecar -e ./sandbox
deploy/local-demo.sh
```

That starts an issuer, an operator's website and the sandbox on your machine, then walks vbot from a new account
to an allowed call, a denied scope and a revocation. [`deploy/`](deploy) also has a Docker Compose stack.

## Related project

[**Veridact Valet**](https://github.com/richard-craig/veridact-valet) lets bank customers give AI agents scoped,
revocable access to their accounts. Veridact answers *which agent is this, and is it still trusted?*; Valet
answers *what did the customer allow?* Both run beside a bank's own systems: the Veridact verifier (this repo's
sidecar) next to the bank's authorisation server, and the Valet decision service next to its MCP server and APIs.

## Status

Specification v0.5, a draft for review. It moved credentials from W3C VC with did:webvh to SD-JWT VC with HTTPS
identifiers ([proposal](docs/proposals/0.5-sd-jwt-vc.md)), and the reference code implements it: SD-JWT+KB
presentations, Token Status Lists, key events, client attestations (pattern C) and known-assistant entries.
Sub-agent grants, Agent Certificates and Verification Records are specified but not built yet. The issuer, vbot, sidecar and
sandbox are alpha and run as a staging network; nothing here is accredited for production use yet. Feedback is welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and report
security problems in the design through [SECURITY.md](SECURITY.md).

## Governance and support

Veridact is run as an open project: [GOVERNANCE.md](GOVERNANCE.md) sets out how decisions are made and how
contributors become maintainers, with the aim of maintainers from at least three organisations and no single
organisation holding a majority ([MAINTAINERS.md](MAINTAINERS.md)). Commercial support, integration help and
assurance are available from IAME (IAM Experts); nobody needs a contract to use the code or the specification.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). The project's names are covered separately in [TRADEMARKS.md](TRADEMARKS.md).
