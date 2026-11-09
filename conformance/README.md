# Conformance vectors

Language-neutral test cases for anyone implementing a Veridact verifier. They are JSON, they need no network, and
each case states the decision an implementation must reach.

[`vectors/verifier-v0.1.json`](vectors/verifier-v0.1.json) covers specification v0.1 plus the
[v0.2 proposals](../docs/proposals/0.2-verifier-gaps.md).

## Format

```text
now            fixed verification time (Unix seconds)
nonce          a nonce the relying party has issued and not yet seen used
trustListUrl   where the trust list is published
bundles[]
  governanceKeys   pinned governance JWKs, kid -> JWK
  artefacts        every published file, URL -> body (did:webvh logs, status lists, trust list)
  cases[]
    policy               { audience, minTier }
    request              { scopes?, payment?: { amount, currency, spentToday? } }
    artefactOverrides    URL -> body, layered over the bundle's artefacts for this case only
    presentation         the VP-JWT the agent sends
    expected             { decision, code, reason }
```

For each case, serve `artefacts` plus `artefactOverrides` from memory, set the clock to `now`, register `nonce`
as live, verify `presentation`, and compare. `decision` and `code` are normative. `reason` is the reference
library's internal code: it shows what was meant to fail, and other implementations need not match it.

## Regenerating

The keys are random, so regenerating replaces every signature. Regenerate only when a case changes:

```sh
pip install -e verify
python conformance/generate.py
```
