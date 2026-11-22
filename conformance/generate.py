"""Generate the Veridact verifier conformance vectors (specification v0.5).

    python conformance/generate.py            # writes conformance/vectors/verifier-v0.5.json

The vectors are frozen: keys and signatures are random, so regenerating replaces
every value. Commit the output; implementations test against the committed file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify import jose, sdjwt, status
from veridact_verify.testing.mock_network import AUDIENCE, CLAUDE_CIMD, NOW, TRUST_LIST_URL, MockNetwork

OUT = Path(__file__).parent / "vectors" / "verifier-v0.5.json"
NONCE = "9f2c41d0a7e3b5f8a1c2d3e4f5a6b7c8"
LIMITS = {"currency": "ZAR", "per_payment": "500.00", "per_day": "2000.00"}
DENY, ALLOW, ASK, CHALLENGE = "deny", "allow", "ask_person", "challenge"


def presentation_cases(net: MockNetwork):
    """Yield (name, description, build, request, expected, policy extras)."""
    a = net.agent_credential

    def vp(**kw):
        return lambda: net.presentation(NONCE, **kw)

    def cred(**kw):
        return vp(credential=a(**kw))

    yield ("allow-basic", "Valid SD-JWT+KB at Organisation tier, every disclosure shown",
           vp(), {"scopes": ["fs:claims:read-status"]}, (ALLOW, None, None), {})
    yield ("allow-no-disclosures", "The agent withholds every selectively disclosable claim",
           vp(disclose=[]), {}, (ALLOW, None, None), {})
    yield ("allow-required-disclosure-shown", "The route needs operator_legal_name and gets it",
           vp(disclose=["operator_legal_name"]), {"disclose": ["operator_legal_name"]}, (ALLOW, None, None), {})
    yield ("deny-required-disclosure-withheld", "The route needs operator_legal_name; it is withheld",
           vp(disclose=["operator_jurisdiction"]), {"disclose": ["operator_legal_name"]},
           (DENY, "AUTH_FAILED", "CLAIMS_NOT_DISCLOSED"), {})
    yield ("deny-policy-disclosure-withheld", "The relying party's policy needs operator_registration",
           vp(disclose=[]), {}, (DENY, "AUTH_FAILED", "CLAIMS_NOT_DISCLOSED"),
           {"requiredDisclosures": ["operator_registration"]})
    yield ("deny-no-key-binding", "An SD-JWT with no KB-JWT",
           lambda: a(), {}, (DENY, "AUTH_FAILED", "KB_MISSING"), {})
    yield ("deny-kb-typ", "KB-JWT typ is not kb+jwt",
           vp(header={"typ": "JWT"}), {}, (DENY, "AUTH_FAILED", "KB_TYP"), {})
    yield ("deny-kb-audience", "KB-JWT aud names another relying party",
           vp(aud="https://other.example"), {}, (DENY, "AUTH_FAILED", "KB_AUDIENCE"), {})
    yield ("challenge-nonce-unknown", "Nonce was not issued by this relying party",
           lambda: net.presentation("0" * 32), {}, (CHALLENGE, "CHALLENGE_REQUIRED", "NONCE_UNKNOWN"), {})
    yield ("challenge-kb-expired", "KB-JWT signed 200 seconds ago",
           vp(iat=NOW - 200), {}, (CHALLENGE, "CHALLENGE_REQUIRED", "KB_EXPIRED"), {})
    yield ("deny-sd-hash", "KB-JWT sd_hash does not cover the presented disclosures",
           vp(mutate=lambda p: p.update(sd_hash="AAAA")), {}, (DENY, "AUTH_FAILED", "SD_HASH_MISMATCH"), {})

    def dropped_disclosure():
        full = sdjwt.parse(net.presentation(NONCE))
        return sdjwt.serialize(full.jws.raw, [d.raw for d in full.disclosures[1:]], full.kb_jwt)
    yield ("deny-disclosure-dropped-after-binding", "A disclosure removed after the KB-JWT was signed",
           dropped_disclosure, {}, (DENY, "AUTH_FAILED", "SD_HASH_MISMATCH"), {})
    yield ("deny-kb-signature", "KB-JWT signed by a key other than cnf.jwk",
           vp(key=ec.generate_private_key(ec.SECP256R1())), {}, (DENY, "AUTH_FAILED", "KB_SIGNATURE"), {})

    def forged():
        jwt, *rest = a().split("~")
        h, p, s = jwt.split(".")
        body = jose.b64url_decode(p).replace(b"fs:quotes:create", b"fs:payments:initiate")
        return net.presentation(NONCE, credential="~".join([".".join([h, jose.b64url_encode(body), s]), *rest]))
    yield ("deny-agent-credential-tampered", "Scope added to a signed Agent Credential",
           forged, {}, (DENY, "AUTH_FAILED", "VC_SIGNATURE"), {})

    def fake_disclosure():
        parsed = sdjwt.parse(a())
        fake = sdjwt.Disclosure.create("operator_legal_name", "Big Bank Ltd")
        return net.presentation(NONCE, credential=sdjwt.serialize(parsed.jws.raw, [fake.raw]))
    yield ("deny-disclosure-forged", "A disclosure the issuer never signed a digest for",
           fake_disclosure, {}, (DENY, "AUTH_FAILED", "DISCLOSURE_INVALID"), {})
    yield ("deny-issuer-unlisted", "Agent Credential from an issuer not in the trust list",
           cred(signer=net.rogue_issuer), {}, (DENY, "ISSUER_UNTRUSTED", "ISSUER_NOT_LISTED"), {})

    def metadata_key_swapped():
        rogue = ec.generate_private_key(ec.SECP256R1())
        net.publish_issuer_metadata(net.issuer, mutate=lambda d: d["jwks"]["keys"][0].update(
            jose.key_to_jwk(rogue.public_key())))
        return net.presentation(NONCE)
    yield ("deny-metadata-key-not-pinned", "Issuer metadata serves a key the trust list does not pin",
           metadata_key_swapped, {}, (DENY, "ISSUER_UNTRUSTED", "ISSUER_KEY_NOT_LISTED"), {})

    def tier_not_accredited():
        net.publish_trust_list(lambda p: p["issuers"][0].update(tiers=["domain"]))
        return net.presentation(NONCE)
    yield ("deny-issuer-tier", "Issuer accredited for Domain tier only",
           tier_not_accredited, {}, (DENY, "ISSUER_UNTRUSTED", "ISSUER_NOT_ACCREDITED_FOR_TIER"), {})

    def untrusted_list():
        net.publish_trust_list(key=ec.generate_private_key(ec.SECP256R1()))
        return net.presentation(NONCE)
    yield ("deny-trust-list-signature", "Trust list signed by a key that is not pinned",
           untrusted_list, {}, (DENY, "VERIFICATION_UNAVAILABLE", "TRUST_LIST_UNAVAILABLE"), {})
    yield ("deny-agent-credential-expired", "Agent Credential past exp",
           cred(valid_from=NOW - 9 * 3600), {}, (DENY, "CREDENTIAL_EXPIRED", "VC_EXPIRED"), {})
    yield ("deny-agent-credential-lifetime", "Agent Credential lifetime 25 hours",
           cred(lifetime=25 * 3600), {}, (DENY, "AUTH_FAILED", "VC_LIFETIME"), {})

    def set_status(url, index, value):
        def build():
            net.set_status(url, index, value)
            return net.presentation(NONCE)
        return build
    yield ("deny-agent-revoked", "Agent Credential's status entry is INVALID",
           set_status(net.agent_status_url, 48213, status.INVALID), {}, (DENY, "AUTH_FAILED", "STATUS_REVOKED"), {})
    yield ("deny-agent-suspended", "Agent Credential's status entry is SUSPENDED",
           set_status(net.agent_status_url, 48213, status.SUSPENDED), {},
           (DENY, "AUTH_FAILED", "STATUS_SUSPENDED"), {})
    yield ("deny-operator-revoked", "The operator_status entry is INVALID",
           set_status(net.operator_status_url, 17, status.INVALID), {},
           (DENY, "AUTH_FAILED", "OPERATOR_REVOKED"), {})
    yield ("allow-neighbour-revoked", "Entries either side of the agent's are INVALID",
           lambda: (net.set_status(net.agent_status_url, 48212), net.set_status(net.agent_status_url, 48214),
                    net.presentation(NONCE))[-1], {}, (ALLOW, None, None), {})

    def rogue_status():
        net.publish_status_list(net.agent_status_url, signer=net.rogue_issuer)
        return net.presentation(NONCE)
    yield ("deny-status-list-signer", "Status list signed by another issuer",
           rogue_status, {}, (DENY, "VERIFICATION_UNAVAILABLE", "STATUS_UNAVAILABLE"), {})

    def stale_list():
        net.publish_status_list(net.agent_status_url, iat=NOW - 3600)
        return net.presentation(NONCE)
    yield ("allow-status-list-hour-old-low-risk", "Status list signed an hour ago; low-risk route",
           stale_list, {"risk": "low"}, (ALLOW, None, None), {})
    yield ("deny-status-list-stale-high-risk", "Status list signed an hour ago; high-risk route",
           stale_list, {"risk": "high"}, (DENY, "VERIFICATION_UNAVAILABLE", "STATUS_STALE"), {})
    yield ("deny-cnf-not-logged", "The cnf key has no logged add event (cnf_event missing)",
           cred(mutate=lambda c: c.pop("cnf_event")), {}, (DENY, "AUTH_FAILED", "KEY_NOT_LOGGED"), {})
    yield ("deny-scope-not-held", "Route needs a scope the agent was not delegated",
           vp(), {"scopes": ["fs:payments:initiate"]}, (DENY, "SCOPE_NOT_HELD", "SCOPE_NOT_HELD"), {})

    pay = cred(scopes=["fs:payments:initiate"], limits=LIMITS)
    yield ("allow-payment-within-limits", "R499.99 with R1,000 already paid today",
           pay, {"scopes": ["fs:payments:initiate"],
                 "payment": {"amount": "499.99", "currency": "ZAR", "spentToday": "1000"}},
           (ALLOW, None, None), {})
    yield ("ask-person-per-payment", "R500.01 against a R500 per-payment limit",
           pay, {"scopes": ["fs:payments:initiate"], "payment": {"amount": "500.01", "currency": "ZAR"}},
           (ASK, "LIMIT_PER_PAYMENT", "LIMIT_PER_PAYMENT"), {})
    yield ("ask-person-per-day", "R400 with R1,700 already paid against R2,000 a day",
           pay, {"scopes": ["fs:payments:initiate"],
                 "payment": {"amount": "400", "currency": "ZAR", "spentToday": "1700"}},
           (ASK, "LIMIT_PER_DAY", "LIMIT_PER_DAY"), {})


def attestation_cases(net: MockNetwork):
    """Pattern C. Each yields (name, description, build -> (attestation, clientId, dpopJkt), request, expected)."""
    ok = (net.agent.id, net.agent.jkt)
    yield ("allow-client-attestation", "Attestation for this client, bound to its DPoP key",
           lambda: (net.client_attestation(), *ok), {"scopes": ["fs:quotes:create"]}, (ALLOW, None, None))
    yield ("deny-attestation-other-client", "Attestation names another client_id",
           lambda: (net.client_attestation(), "https://operator.example/agents/other", net.agent.jkt), {},
           (DENY, "AUTH_FAILED", "CLIENT_MISMATCH"))
    yield ("deny-attestation-other-dpop-key", "The DPoP proof was made with a different key",
           lambda: (net.client_attestation(), net.agent.id, "x" * 43), {},
           (DENY, "AUTH_FAILED", "DPOP_KEY_MISMATCH"))

    def revoked():
        net.set_status(net.agent_status_url, 48213)
        return (net.client_attestation(), *ok)
    yield ("deny-attestation-revoked", "Revoking the Agent Credential revokes its attestation",
           revoked, {}, (DENY, "AUTH_FAILED", "STATUS_REVOKED"))


def assistant_cases(net: MockNetwork):
    """Known-assistant entries. Each yields (name, description, build -> (entry, clientId), expected)."""
    yield ("allow-known-assistant", "Entry for Claude, matched by its CIMD URL",
           lambda: (net.known_assistant(), CLAUDE_CIMD), (ALLOW, None, None))
    yield ("deny-known-assistant-other-client", "Entry does not list this client",
           lambda: (net.known_assistant(), "https://chatgpt.com/oauth/client.json"),
           (DENY, "AUTH_FAILED", "ASSISTANT_NOT_LISTED"))

    def suspended():
        net.set_status(net.assistant_status_url, 3, status.SUSPENDED)
        return (net.known_assistant(), CLAUDE_CIMD)
    yield ("deny-known-assistant-suspended", "The kill switch: the entry is SUSPENDED",
           suspended, (DENY, "AUTH_FAILED", "STATUS_SUSPENDED"))


def main() -> int:
    net = MockNetwork()
    base = net.snapshot()

    def capture(build):
        result = build()
        overrides = {u: b for u, b in net.snapshot().items() if base.get(u) != b}
        net.fetcher.files = {u: b.encode() for u, b in base.items()}
        net.status_values = {u: {} for u in net.status_values}
        return result, overrides

    def expected(triple):
        decision, code, reason = triple
        return {"decision": decision, "code": code, "reason": reason}

    cases = []
    for name, description, build, request, result, extra in presentation_cases(net):
        presentation, overrides = capture(build)
        cases.append({"name": name, "kind": "presentation", "description": description,
                      "policy": {"audience": AUDIENCE, "minTier": "organisation", **extra},
                      "request": request, "artefactOverrides": overrides,
                      "presentation": presentation, "expected": expected(result)})
    for name, description, build, request, result in attestation_cases(net):
        (attestation, client_id, jkt), overrides = capture(build)
        cases.append({"name": name, "kind": "client-attestation", "description": description,
                      "policy": {"audience": AUDIENCE, "minTier": "organisation"},
                      "request": request, "artefactOverrides": overrides,
                      "attestation": attestation, "clientId": client_id, "dpopJkt": jkt,
                      "expected": expected(result)})
    for name, description, build, result in assistant_cases(net):
        (entry, client_id), overrides = capture(build)
        cases.append({"name": name, "kind": "known-assistant", "description": description,
                      "policy": {"audience": AUDIENCE, "minTier": "organisation"}, "request": {},
                      "artefactOverrides": overrides, "entry": entry, "clientId": client_id,
                      "expected": expected(result)})

    # Domain tier: a separate network, so it carries its own full artefact set.
    domain = MockNetwork(tier="domain")
    low = {"name": "deny-tier-too-low", "kind": "presentation",
           "description": "Domain-tier agent on a route needing Organisation tier",
           "policy": {"audience": AUDIENCE, "minTier": "organisation"}, "request": {},
           "presentation": domain.presentation(NONCE),
           "expected": {"decision": DENY, "code": "TIER_TOO_LOW", "reason": "TIER_TOO_LOW"}}

    doc = {
        "about": ("Veridact verifier conformance vectors for specification v0.5 (SD-JWT VC, Token Status "
                  "List, HTTPS identifiers). Every case runs at 'now', with 'nonce' issued by the relying "
                  "party and unused. 'kind' says which verification to run. 'code' is normative; 'reason' "
                  "is the reference library's internal code and is informative. 'request.risk' defaults "
                  "to medium."),
        "now": NOW,
        "nonce": NONCE,
        "trustListUrl": TRUST_LIST_URL,
        "bundles": [
            {"name": "organisation-tier", "governanceKeys": net.governance_keys, "artefacts": base,
             "cases": cases},
            {"name": "domain-tier", "governanceKeys": domain.governance_keys,
             "artefacts": domain.snapshot(), "cases": [low]},
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    total = sum(len(b["cases"]) for b in doc["bundles"])
    print(f"wrote {total} cases to {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
