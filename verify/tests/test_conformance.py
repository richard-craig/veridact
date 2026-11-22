"""Run the committed, language-neutral conformance vectors."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from veridact_verify import (
    InMemoryNonceStore,
    Payment,
    RelyingPartyPolicy,
    Request,
    Risk,
    StaticFetcher,
    Verifier,
)

VECTORS = Path(__file__).resolve().parents[2] / "conformance" / "vectors" / "verifier-v0.5.json"
DOC = json.loads(VECTORS.read_text())


def _cases():
    for bundle in DOC["bundles"]:
        for case in bundle["cases"]:
            yield pytest.param(bundle, case, id=f'{bundle["name"]}/{case["name"]}')


def _request(raw: dict) -> Request:
    payment = raw.get("payment")
    return Request(
        scopes=frozenset(raw.get("scopes", [])),
        risk=Risk(raw.get("risk", "medium")),
        payment=Payment(Decimal(payment["amount"]), payment["currency"],
                        Decimal(payment.get("spentToday", "0"))) if payment else None,
        disclose=frozenset(raw.get("disclose", [])),
    )


@pytest.mark.parametrize("bundle,case", list(_cases()))
async def test_vector(bundle, case):
    files = {**bundle["artefacts"], **case.get("artefactOverrides", {})}
    now = DOC["now"]
    nonces = InMemoryNonceStore(clock=lambda: now)
    nonces.add(DOC["nonce"])
    policy = case["policy"]
    verifier = Verifier(
        RelyingPartyPolicy(audience=policy["audience"], min_tier=policy["minTier"],
                           required_disclosures=frozenset(policy.get("requiredDisclosures", []))),
        governance_keys=bundle["governanceKeys"],
        fetcher=StaticFetcher(files),
        nonces=nonces,
        clock=lambda: now,
        trust_list_url=DOC["trustListUrl"],
    )
    request = _request(case["request"])
    if case["kind"] == "presentation":
        decision = await verifier.verify(case["presentation"], request)
    elif case["kind"] == "client-attestation":
        decision = await verifier.verify_client_attestation(
            case["attestation"], client_id=case["clientId"], dpop_jkt=case["dpopJkt"], request=request)
    else:
        decision = await verifier.verify_known_assistant(case["entry"], client_id=case["clientId"])
    expected = case["expected"]
    assert decision.outcome.value == expected["decision"], decision.log_record()
    assert (decision.public_code.value if decision.public_code else None) == expected["code"]
    assert (decision.reason.value if decision.reason else None) == expected["reason"]
