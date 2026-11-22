# Governance

Veridact is an open specification with reference implementations. A specification for verifying AI agents
across banks and insurers is only trusted if no single person or company controls it, its founder included. This
document says how decisions are made, how people earn a say, and how the project outlives any one contributor.

There are two layers, and they are kept apart:

- **This project:** the specification, the proposals, and the reference code (verifier, issuer, agent client,
  sidecar, integrations and conformance vectors). It is governed here.
- **Running an issuer:** accrediting issuers, setting tier policy and publishing the trust list. These belong to
  the governance authority the specification describes (a member consortium), not to this repository.

## Principles

1. **Open by default.** Design discussions, decisions and their reasons happen in public issues, proposals and
   pull requests. Security reports are the exception (see [SECURITY.md](SECURITY.md)).
2. **Proposal first, then specification, then code.** A change to anything an implementer relies on starts as a
   proposal in [`docs/proposals/`](docs/proposals). When it is accepted, it is written into
   [`docs/specification.md`](docs/specification.md). The reference code and conformance vectors then follow the
   specification, never the other way round.
3. **Built on published standards.** Veridact profiles existing IETF, OpenID and W3C work. It defines new
   formats only where none exist, and says where it does.
4. **No call home.** Relying parties verify from cached public files. Nothing in the reference code reports to
   the project or to any company.

## Roles

| Role | Who | What they can do |
|---|---|---|
| **Contributor** | Anyone who opens an issue, a proposal or a pull request | Propose changes, review, take part in discussion |
| **Maintainer** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Review and merge pull requests, triage issues, accept proposals, cut releases |
| **Lead maintainer** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Breaks ties, and acts for the project until the steering group exists |

### Becoming a maintainer

A contributor becomes a maintainer after sustained, good-quality contributions over at least three months: code,
review, specification, conformance or security work. An existing maintainer nominates them in a public issue.
They are added if no maintainer objects within 14 days, or by a majority of maintainers if someone does.

Maintainers who are inactive for 12 months move to emeritus status. They can return by asking.

### Spread of maintainers

The project aims to have maintainers from **at least three different organisations**, including at least one
relying party (a bank or insurer) and at least one organisation that does not operate an issuer. **No single
organisation may hold a majority** of maintainer seats. Until that is reached, the lead maintainer actively seeks
maintainers from relying parties, agent operators and independent contributors.

## How decisions are made

- **Everyday changes** (fixes, tests, docs, refactors): one maintainer approval, with CI passing.
- **Specification changes:** a proposal, open for review for at least 14 days, accepted by two maintainers,
  preferably from different organisations. Its status line records the decision and the date.
- **Security-relevant code** (verification checks, signing, status, key handling): two maintainer approvals, and
  the conformance vectors updated in the same pull request.
- **Lazy consensus:** if no maintainer objects within the review period, the change can proceed. An objection
  must give a reason and, where possible, an alternative.
- **Disagreement:** discuss in the issue first. If maintainers can't agree, they vote and a simple majority
  decides. The lead maintainer breaks ties until the steering group exists.
- **Standards bodies:** where a format Veridact profiles changes at the IETF or OpenID Foundation, the project
  follows the standard and records the change in a proposal.

## Steering group

Once there are at least three maintainers from at least two organisations, they form a steering group. It takes
over the lead maintainer's tie-breaking role, approves changes to this document, and decides on joining a neutral
foundation. No organisation may hold more than one third of steering-group seats.

## Commercial support

The code and specification are free under Apache 2.0, and nobody needs a contract to use them. Commercial support,
integration help and assurance are available from **IAME (IAM Experts)**. IAME has no extra say in the project
because of it: its people take part as contributors and maintainers under the same rules as everyone else.

## Changing this document

Changes need two thirds of maintainers to agree, with the pull request open for at least 14 days.

## Name and trademark

The code is licensed under Apache 2.0 and belongs to everyone. The name "Veridact" is held separately so that
people can rely on what carries it. See [TRADEMARKS.md](TRADEMARKS.md).

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
