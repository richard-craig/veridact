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

- [**Specification**](docs/specification.md): trust model, identifiers and keys, credential profiles, delegation,
  the ACME-A protocol, the verification checks and reason codes, the transparency log, the trust registry,
  security, privacy and resilience.
- [**veridact-verify**](verify): the reference verifier library (Python, alpha). It runs all eight verification
  checks with reason codes, caching and degraded mode, and makes no call home.
- [**Conformance vectors**](conformance): language-neutral test cases for anyone implementing a verifier.
- [**v0.2 proposals**](docs/proposals/0.2-verifier-gaps.md): gaps found while building the verifier, and the
  choices it makes.

An agent client (`vbot`) and an HTTP sidecar for the verifier are planned.

## Related project

[**Veridact Valet**](https://github.com/richard-craig/veridact-valet) lets bank customers give AI agents scoped,
revocable access to their accounts. Valet's agent registry can use Veridact credentials to know which agent is
calling.

## Status

Version 0.1, a draft for review. Feedback is welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and report
security problems in the design through [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
