# Contributing

Veridact is a draft specification, and the most useful contributions are reviews of it.

- **Find the flaws.** A way to obtain a credential you shouldn't have, to widen a delegation, or to verify
  something that shouldn't verify. Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- **Check the standards use.** Places where the profile misuses or diverges from SD-JWT VC, the Token Status
  List, attestation-based client authentication, Client ID Metadata Documents or ACME (v0.5, see the
  [proposal](docs/proposals/0.5-sd-jwt-vc.md)). Up to v0.4 the profile used did:webvh, VC-JOSE-COSE and Bitstring
  Status List.
- **Implementer feedback.** Anything that would be hard to build in a bank's API gateway, authorisation server or
  agent framework.

Open an issue that names the section of [`docs/specification.md`](docs/specification.md) you are commenting on.

Changes to the specification start as a proposal in [`docs/proposals/`](docs/proposals); see
[GOVERNANCE.md](GOVERNANCE.md) for how proposals are accepted.

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) instead of a
contributor licence agreement. Add a `Signed-off-by` line to each commit (`git commit -s`) to confirm you wrote
the change, or have the right to submit it, under this project's licence. A check on every pull request confirms
it. If you forget, `git commit --amend -s` fixes the latest commit and `git rebase --signoff main` fixes them all.

If you contribute as part of your job, check that your employer allows it.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0, the licence of this
project. The project's names are covered separately in [TRADEMARKS.md](TRADEMARKS.md).
