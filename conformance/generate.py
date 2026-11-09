"""Generate the Veridact verifier conformance vectors.

    python conformance/generate.py            # writes conformance/vectors/verifier-v0.1.json

The vectors are frozen: keys and signatures are random, so regenerating replaces
every value. Commit the output; implementations test against the committed file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify.testing.mock_network import (
    AUDIENCE,
    NOW,
    TRUST_LIST_URL,
    MockNetwork,
    make_party,
)

OUT = Path(__file__).parent / "vectors" / "verifier-v0.1.json"
NONCE = "9f2c41d0a7e3b5f8a1c2d3e4f5a6b7c8"
LIMITS = {"currency": "ZAR", "perPayment": "500.00", "perDay": "2000.00"}


def build_cases(net: MockNetwork):
    """Yield (name, description, build, request, expected). ``build`` may change
    published artefacts; the generator records those changes per case."""
    a, o = net.agent_credential, net.operator_credential

    def vp(**kw):
        return lambda: net.presentation(NONCE, **kw)

    def creds(agent=None, operator=None):
        return [agent or a(), operator or o()]

    yield ("allow-basic", "Valid presentation at Organisation tier",
           vp(), {"scopes": ["fs:claims:read-status"]}, ("allow", None, None))
    yield ("allow-no-scopes-requested", "Grants all held scopes when the route requests none",
           vp(), {}, ("allow", None, None))
    yield ("deny-vp-typ", "Presentation typ is not vp+jwt",
           vp(header={"typ": "JWT"}), {}, ("deny", "AUTH_FAILED", "VP_TYP"))
    yield ("deny-vp-audience", "aud names another relying party",
           vp(aud="https://other.example"), {}, ("deny", "AUTH_FAILED", "VP_AUDIENCE"))
    yield ("challenge-nonce-unknown", "Nonce was not issued by this relying party",
           lambda: net.presentation("0" * 32), {}, ("challenge", "CHALLENGE_REQUIRED", "NONCE_UNKNOWN"))
    yield ("challenge-vp-expired", "Presentation expired",
           vp(iat=NOW - 200, lifetime=100), {}, ("challenge", "CHALLENGE_REQUIRED", "VP_EXPIRED"))
    yield ("deny-vp-lifetime", "Presentation lifetime above 120 seconds",
           vp(lifetime=121), {}, ("deny", "AUTH_FAILED", "VP_LIFETIME"))
    yield ("deny-vp-signature", "Presentation signed by a key not in the agent DID",
           vp(key=ec.generate_private_key(ec.SECP256R1())), {}, ("deny", "AUTH_FAILED", "VP_SIGNATURE"))

    def tampered_log():
        log = net.fetcher.files[net.agent.log_url].decode()
        net.fetcher.put(net.agent.log_url, log.replace("authentication", "assertionMethod"))
        return net.presentation(NONCE)
    yield ("deny-did-log-tampered", "Agent DID log edited after signing",
           tampered_log, {}, ("deny", "AUTH_FAILED", "HOLDER_DID_UNRESOLVABLE"))

    yield ("deny-operator-credential-missing", "Presentation carries only the Agent Credential",
           vp(credentials=[a()]), {}, ("deny", "AUTH_FAILED", "VC_MISSING"))

    def forged():
        h, p, s = a().split(".")
        from veridact_verify.jose import b64url_decode, b64url_encode
        body = b64url_decode(p).replace(b"fs:quotes:create", b"fs:payments:initiate")
        return net.presentation(NONCE, credentials=[".".join([h, b64url_encode(body), s]), o()])
    yield ("deny-agent-credential-tampered", "Scope added to a signed Agent Credential",
           forged, {}, ("deny", "AUTH_FAILED", "VC_SIGNATURE"))
    yield ("deny-issuer-unlisted", "Agent Credential from an issuer not in the trust list",
           vp(credentials=creds(agent=a(signer=net.rogue_issuer))), {},
           ("deny", "ISSUER_UNTRUSTED", "ISSUER_NOT_LISTED"))

    def tier_not_accredited():
        net.publish_trust_list(lambda p: p["issuers"][0].update(tiers=["domain"]))
        return net.presentation(NONCE)
    yield ("deny-issuer-tier", "Issuer accredited for Domain tier only",
           tier_not_accredited, {}, ("deny", "ISSUER_UNTRUSTED", "ISSUER_NOT_ACCREDITED_FOR_TIER"))

    def untrusted_list():
        net.publish_trust_list(key=ec.generate_private_key(ec.SECP256R1()))
        return net.presentation(NONCE)
    yield ("deny-trust-list-signature", "Trust list signed by a key that is not pinned",
           untrusted_list, {}, ("deny", "VERIFICATION_UNAVAILABLE", "TRUST_LIST_UNAVAILABLE"))

    yield ("deny-agent-credential-expired", "Agent Credential past validUntil",
           vp(credentials=creds(agent=a(valid_from=NOW - 9 * 3600))), {},
           ("deny", "CREDENTIAL_EXPIRED", "VC_EXPIRED"))
    yield ("deny-agent-credential-lifetime", "Agent Credential lifetime 25 hours",
           vp(credentials=creds(agent=a(lifetime=25 * 3600))), {},
           ("deny", "AUTH_FAILED", "VC_LIFETIME"))

    def revoked_agent():
        net.revoke(net.agent_status_url, 48213)
        return net.presentation(NONCE)
    yield ("deny-agent-revoked", "Agent Credential's revocation bit is set",
           revoked_agent, {}, ("deny", "AUTH_FAILED", "STATUS_REVOKED"))

    def revoked_operator():
        net.revoke(net.operator_status_url, 17)
        return net.presentation(NONCE)
    yield ("deny-operator-revoked", "Operator Credential's revocation bit is set",
           revoked_operator, {}, ("deny", "AUTH_FAILED", "STATUS_REVOKED"))

    def rogue_status():
        net.publish_status_list(net.agent_status_url, signer=net.rogue_issuer)
        return net.presentation(NONCE)
    yield ("deny-status-list-signer", "Status list signed by another issuer",
           rogue_status, {}, ("deny", "VERIFICATION_UNAVAILABLE", "STATUS_UNAVAILABLE"))

    yield ("deny-cnf-mismatch", "cnf names a key other than the one that signed",
           vp(credentials=creds(agent=a(mutate=lambda p: p["credentialSubject"]["cnf"].update(
               kid=net.agent.did + "#key-2")))), {}, ("deny", "AUTH_FAILED", "CNF_MISMATCH"))

    other = make_party("operator.example:agents:zz9", "authentication")

    def other_agent():
        net.fetcher.put(other.log_url, other.log)
        cred = a(mutate=lambda p: p["credentialSubject"].update(id=other.did, cnf={"kid": other.kid}))
        return net.presentation(NONCE, credentials=[cred, o()])
    yield ("deny-holder-mismatch", "Agent presents a credential issued to another agent",
           other_agent, {}, ("deny", "AUTH_FAILED", "HOLDER_MISMATCH"))

    yield ("deny-operator-mismatch", "Operator Credential for a different operator",
           vp(credentials=creds(operator=o(mutate=lambda p: p["credentialSubject"].update(
               id="did:webvh:Qmother:other.example")))), {},
           ("deny", "AUTH_FAILED", "OPERATOR_MISMATCH"))
    yield ("deny-scope-not-held", "Route needs a scope the agent was not delegated",
           vp(), {"scopes": ["fs:payments:initiate"]}, ("deny", "SCOPE_NOT_HELD", "SCOPE_NOT_HELD"))

    pay = creds(agent=a(scopes=["fs:payments:initiate"], limits=LIMITS))
    yield ("allow-payment-within-limits", "R499.99 with R1,000 already paid today",
           vp(credentials=pay),
           {"scopes": ["fs:payments:initiate"],
            "payment": {"amount": "499.99", "currency": "ZAR", "spentToday": "1000"}},
           ("allow", None, None))
    yield ("ask-person-per-payment", "R500.01 against a R500 per-payment limit",
           vp(credentials=pay),
           {"scopes": ["fs:payments:initiate"], "payment": {"amount": "500.01", "currency": "ZAR"}},
           ("ask_person", "LIMIT_PER_PAYMENT", "LIMIT_PER_PAYMENT"))
    yield ("ask-person-per-day", "R400 with R1,700 already paid against R2,000 a day",
           vp(credentials=pay),
           {"scopes": ["fs:payments:initiate"],
            "payment": {"amount": "400", "currency": "ZAR", "spentToday": "1700"}},
           ("ask_person", "LIMIT_PER_DAY", "LIMIT_PER_DAY"))


def tier_case(name, description, policy, request, expected):
    """Cases that need a Domain-tier network."""
    net = MockNetwork(tier="domain")
    op = net.operator_credential(lifetime=60 * 86400)
    vp = net.presentation(NONCE, credentials=[net.agent_credential(), op])
    return net, {"name": name, "description": description, "policy": policy,
                 "request": request, "presentation": vp, "expected": expected}


def main() -> int:
    net = MockNetwork()
    base = net.snapshot()
    cases = []
    for name, description, build, request, (decision, code, reason) in build_cases(net):
        presentation = build()
        now_files = net.snapshot()
        overrides = {u: b for u, b in now_files.items() if base.get(u) != b}
        net.fetcher.files = {u: b.encode() for u, b in base.items()}
        cases.append({
            "name": name,
            "description": description,
            "policy": {"audience": AUDIENCE, "minTier": "organisation"},
            "request": request,
            "artefactOverrides": overrides,
            "presentation": presentation,
            "expected": {"decision": decision, "code": code, "reason": reason},
        })

    # Domain tier: a separate network, so it carries its own full artefact set.
    domain_net, low = tier_case(
        "deny-tier-too-low", "Domain-tier agent on a route needing Organisation tier",
        {"audience": AUDIENCE, "minTier": "organisation"}, {},
        {"decision": "deny", "code": "TIER_TOO_LOW", "reason": "TIER_TOO_LOW"})
    domain_bundle = {
        "governanceKeys": domain_net.governance_keys,
        "artefacts": domain_net.snapshot(),
        "cases": [low],
    }

    doc = {
        "about": ("Veridact verifier conformance vectors for specification v0.1 plus the v0.2 "
                  "proposals in docs/proposals/0.2-verifier-gaps.md. Every case runs at 'now', "
                  "with 'nonce' issued by the relying party and unused. 'code' is normative; "
                  "'reason' is the reference library's internal code and is informative."),
        "now": NOW,
        "nonce": NONCE,
        "trustListUrl": TRUST_LIST_URL,
        "bundles": [
            {"name": "organisation-tier", "governanceKeys": net.governance_keys,
             "artefacts": base, "cases": cases},
            {"name": "domain-tier", **domain_bundle},
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    total = sum(len(b["cases"]) for b in doc["bundles"])
    print(f"wrote {total} cases to {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
