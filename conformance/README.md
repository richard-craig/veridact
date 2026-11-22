# Conformance vectors

Language-neutral test cases for anyone implementing a Veridact verifier. They are JSON, they need no network, and
each case states the decision an implementation must reach.

[`vectors/verifier-v0.5.json`](vectors/verifier-v0.5.json) covers specification v0.5: SD-JWT+KB presentations,
selective disclosure, Token Status Lists, client attestations (pattern C) and known-assistant entries. The v0.2
vectors were retired with the move to v0.5, which is a clean cut.

## Format

```text
now            fixed verification time (Unix seconds)
nonce          a nonce the relying party has issued and not yet seen used
trustListUrl   where the trust list is published
bundles[]
  governanceKeys   pinned governance JWKs, kid -> JWK
  artefacts        every published file, URL -> body (issuer metadata, status lists, trust list)
  cases[]
    kind                 presentation | client-attestation | known-assistant
    policy               { audience, minTier, requiredDisclosures? }
    request              { scopes?, risk? (low | medium | high, default medium), disclose?,
                           payment?: { amount, currency, spentToday? } }
    artefactOverrides    URL -> body, layered over the bundle's artefacts for this case only
    presentation         kind presentation: the SD-JWT+KB the agent sends
    attestation, clientId, dpopJkt
                         kind client-attestation: the Client Attestation, the OAuth client_id, and the
                         thumbprint of the key that made the (already checked) DPoP proof
    entry, clientId      kind known-assistant: the entry as published, and the client it must describe
    expected             { decision, code, reason }
```

For each case, serve `artefacts` plus `artefactOverrides` from memory, set the clock to `now`, register `nonce`
as live, run the verification `kind` names, and compare. `decision` and `code` are normative. `reason` is the reference
library's internal code: it shows what was meant to fail, and other implementations need not match it.

## Regenerating

The keys are random, so regenerating replaces every signature. Regenerate only when a case changes:

```sh
pip install -e verify
python conformance/generate.py
```
