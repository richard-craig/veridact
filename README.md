# Veridact

**Short-lived, verifiable credentials for AI agents, issued the way Let's Encrypt issues certificates.**

When an AI agent calls a bank's or an insurer's API, the API needs answers to two questions before it serves the
request: *which organisation operates this agent and answers for it?* and *what has that organisation allowed it
to do?* Passwords and API keys can't answer either question.

Veridact answers both with open standards:

- **An identity for every agent:** a `did:webvh` identifier with a key the agent holds and never exports.
- **Credentials that expire in hours:** W3C Verifiable Credentials (VC Data Model 2.0, secured as JWT), issued and
  renewed automatically through **ACME-A**, a profile of ACME (RFC 8555), the protocol behind Let's Encrypt.
- **A human at every point that matters:** authority flows from appointed approvers down to the agent, and nobody
  can delegate more than they hold.
- **Verification without calling home:** relying parties check credentials against signed, cacheable public files,
  so verification works through an issuer outage and no issuer learns where agents are used.
- **No secret issuance:** every credential goes into a public, append-only transparency log before it is released.

TLS is the right comparison: the protocol and the clients are open, and certificate authorities compete to run
issuance. Veridact works the same way.

## What's here

- [**Specification**](docs/specification.md) (v0.4): trust model, identifiers and keys, credential profiles,
  delegation and sub-agents, the ACME-A protocol, Agent Certificates, the verification checks and reason codes,
  the transparency log, archival verification, the trust registry, security, privacy and resilience.
- [**veridact-verify**](verify): the reference verifier library (Python, alpha). It runs all eight verification
  checks with reason codes, caching and degraded mode, and makes no call home.
- [**veridact-issuer**](issuer): a staging ACME-A issuer (alpha, Domain tier). It validates operators with dns-01 or
  did-config-01 and agents with delegation-01, logs every credential before release, and publishes the issuer DID,
  status lists and a staging trust list.
- [**vbot**](vbot): the agent client. `vbot init`, `vbot operator`, `vbot agent new`, `vbot delegate`, `vbot issue`,
  then `vbot call` any Veridact-protected API and `vbot run` to stay renewed.
- [**veridact-sidecar**](sidecar): the verifier over HTTP (`/v1/challenge`, `/v1/verify`) for gateways and
  authorisation servers in any language.
- [**Lambda authoriser**](integrations/aws-lambda): pattern B on AWS API Gateway, with DynamoDB nonces and a SAM
  template.
- [**Keycloak bridge**](integrations/keycloak): pattern A for Keycloak 26.6+. An agent trades a presentation for a
  DPoP-bound Keycloak access token through the JWT Authorization Grant, with no Keycloak extension.
- [**veridact-sandbox**](sandbox): Veridact Insurance, a pretend insurer API that challenges agents and explains every
  decision.
- [**Conformance vectors**](conformance): language-neutral test cases for anyone implementing a verifier.
- [**Proposals**](docs/proposals): [v0.2](docs/proposals/0.2-verifier-gaps.md) (gaps found building the verifier,
  accepted), [v0.3](docs/proposals/0.3-issuer-gaps.md) (gaps found building the issuer, vbot and the
  integrations, accepted) and [v0.4](docs/proposals/0.4-iiw42-proposals.md) (sub-agents, actor claims, Agent
  Certificates and archival verification, from IIW 42, accepted).

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
revocable access to their accounts. Valet's agent registry can use Veridact credentials to know which agent is
calling.

## Status

Specification v0.4, a draft for review. The reference code implements v0.3: sub-agent grants, actor claims,
Agent Certificates and Verification Records are specified but not built yet. The issuer, vbot, sidecar and
sandbox are alpha and run as a staging network; nothing here is accredited for production use yet. Feedback is welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and report
security problems in the design through [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
