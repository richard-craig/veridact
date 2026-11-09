"""Behaviour of the eight verification checks, one failure at a time."""

from __future__ import annotations

from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify import Outcome, Payment, PublicCode, Reason, Request, Risk, Verifier, jose
from veridact_verify.testing.mock_network import AUDIENCE, make_party

S = frozenset


async def run(env, build=None, request: Request = Request(), verifier: Verifier | None = None):
    verifier = verifier or env.verifier()
    nonce = verifier.nonces.issue()
    vp = (build or (lambda n: env.net.presentation(n)))(nonce)
    return await verifier.verify(vp, request)


def expect(decision, reason: Reason, code: PublicCode, outcome: Outcome = Outcome.DENY, check=None):
    assert decision.reason is reason, decision.log_record()
    assert decision.public_code is code
    assert decision.outcome is outcome
    assert decision.scopes_granted == []
    if check is not None:
        assert decision.check == check


# -- happy paths -----------------------------------------------------------------


async def test_allows_valid_presentation(env):
    d = await run(env, request=Request(scopes=S({"fs:claims:read-status"})))
    assert d.allowed, d.log_record()
    assert d.public() == {"decision": "allow"}
    assert d.agent == env.net.agent.did
    assert d.operator == env.net.operator.did
    assert d.operator_domains == ["operator.example"]
    assert d.tier == "organisation"
    assert d.scopes_granted == ["fs:claims:read-status"]
    assert d.accountable_role == "Head of Digital Claims"


async def test_grants_intersection_with_rp_policy(env):
    v = env.verifier(allowed_scopes=S({"fs:quotes:create", "fs:other"}))
    d = await run(env, verifier=v)
    assert d.allowed
    assert d.scopes_granted == ["fs:quotes:create"]


async def test_scopes_outside_taxonomy_are_dropped(env):
    cred = env.net.agent_credential(scopes=["fs:quotes:create", "made:up:scope"])
    d = await run(env, lambda n: env.net.presentation(
        n, credentials=[cred, env.net.operator_credential()]))
    assert d.allowed
    assert d.scopes_held == ["fs:quotes:create"]


async def test_warm_cache_makes_no_network_calls(env):
    v = env.verifier()
    assert (await run(env, verifier=v)).allowed
    before = len(env.net.fetcher.requests)
    assert (await run(env, verifier=v)).allowed
    assert len(env.net.fetcher.requests) == before


async def test_authorization_header_round_trip(env):
    v = env.verifier()
    nonce, header = v.challenge(Request(scopes=S({"fs:quotes:create"})), realm="claims-api")
    assert header == (f'Veridact realm="claims-api", nonce="{nonce}", tier="organisation", '
                      'scope="fs:quotes:create"')
    vp = env.net.presentation(nonce)
    assert Verifier.presentation_from_authorization(f'Veridact vp="{vp}"') == vp
    assert Verifier.presentation_from_authorization("Bearer abc") is None
    assert (await v.verify(vp)).allowed


# -- check 1: envelope -----------------------------------------------------------


async def test_malformed(env):
    expect(await run(env, lambda n: "not.a.jws"), Reason.VP_MALFORMED, PublicCode.AUTH_FAILED, check=1)


async def test_wrong_typ(env):
    d = await run(env, lambda n: env.net.presentation(n, header={"typ": "JWT"}))
    expect(d, Reason.VP_TYP, PublicCode.AUTH_FAILED)


@pytest.mark.parametrize("alg", ["none", "HS256", "ES384", "EdDSA"])
async def test_rejects_other_algorithms(env, alg):
    vp = env.net.presentation("x")
    header = jose.b64url_encode(f'{{"alg":"{alg}","typ":"vp+jwt"}}'.encode())
    tampered = header + vp[vp.index("."):]
    expect(await run(env, lambda n: tampered), Reason.VP_MALFORMED, PublicCode.AUTH_FAILED)


async def test_wrong_audience(env):
    d = await run(env, lambda n: env.net.presentation(n, aud="https://other.example"))
    expect(d, Reason.VP_AUDIENCE, PublicCode.AUTH_FAILED)


async def test_audience_list(env):
    assert (await run(env, lambda n: env.net.presentation(n, aud=["x", AUDIENCE]))).allowed


async def test_missing_nonce(env):
    d = await run(env, lambda n: env.net.presentation(n, mutate=lambda p: p.pop("nonce")))
    expect(d, Reason.NONCE_MISSING, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_nonce_not_issued_here(env):
    d = await run(env, lambda n: env.net.presentation("f" * 32))
    expect(d, Reason.NONCE_UNKNOWN, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_replay_is_refused(env):
    v = env.verifier()
    nonce = v.nonces.issue()
    vp = env.net.presentation(nonce)
    assert (await v.verify(vp)).allowed
    expect(await v.verify(vp), Reason.NONCE_UNKNOWN, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_expired_presentation(env):
    v = env.verifier()
    nonce = v.nonces.issue()
    vp = env.net.presentation(nonce, iat=int(env.clock.now) - 200, lifetime=100)
    expect(await v.verify(vp), Reason.VP_EXPIRED, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_presentation_lifetime_cap(env):
    d = await run(env, lambda n: env.net.presentation(n, lifetime=121))
    expect(d, Reason.VP_LIFETIME, PublicCode.AUTH_FAILED)


async def test_presentation_from_future(env):
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) + 90))
    expect(d, Reason.VP_NOT_YET_VALID, PublicCode.AUTH_FAILED)


# -- check 2: holder and signature -------------------------------------------------


async def test_presentation_signed_by_wrong_key(env):
    other = ec.generate_private_key(ec.SECP256R1())
    d = await run(env, lambda n: env.net.presentation(n, key=other))
    expect(d, Reason.VP_SIGNATURE, PublicCode.AUTH_FAILED, check=2)


async def test_failed_signature_does_not_burn_nonce(env):
    v = env.verifier()
    nonce = v.nonces.issue()
    bad = env.net.presentation(nonce, key=ec.generate_private_key(ec.SECP256R1()))
    assert (await v.verify(bad)).reason is Reason.VP_SIGNATURE
    assert (await v.verify(env.net.presentation(nonce))).allowed


async def test_kid_from_another_did(env):
    d = await run(env, lambda n: env.net.presentation(n, header={"kid": env.net.operator.kid}))
    expect(d, Reason.VP_KID_INVALID, PublicCode.AUTH_FAILED)


async def test_kid_not_in_authentication(env):
    d = await run(env, lambda n: env.net.presentation(n, header={"kid": env.net.agent.did + "#key-9"}))
    expect(d, Reason.VP_KID_INVALID, PublicCode.AUTH_FAILED)


async def test_tampered_did_log(env):
    log = env.net.fetcher.files[env.net.agent.log_url].decode()
    env.net.fetcher.put(env.net.agent.log_url, log.replace("authentication", "assertionMethod"))
    expect(await run(env), Reason.HOLDER_DID_UNRESOLVABLE, PublicCode.AUTH_FAILED)


async def test_did_log_for_a_different_did(env):
    # Serve the operator's genuine log at the agent's URL.
    env.net.fetcher.put(env.net.agent.log_url, env.net.operator.log)
    expect(await run(env), Reason.HOLDER_DID_UNRESOLVABLE, PublicCode.AUTH_FAILED)


# -- check 3: enveloped credentials ----------------------------------------------


async def test_missing_operator_credential(env):
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential()]))
    expect(d, Reason.VC_MISSING, PublicCode.AUTH_FAILED, check=3)


async def test_duplicate_credential_type(env):
    a = env.net.agent_credential()
    d = await run(env, lambda n: env.net.presentation(
        n, credentials=[a, a, env.net.operator_credential()]))
    expect(d, Reason.VC_MALFORMED, PublicCode.AUTH_FAILED)


async def test_tampered_agent_credential(env):
    cred = env.net.agent_credential()
    h, p, s = cred.split(".")
    payload = jose.b64url_decode(p).replace(b"fs:quotes:create", b"fs:payments:initiate")
    forged = ".".join([h, jose.b64url_encode(payload), s])
    d = await run(env, lambda n: env.net.presentation(
        n, credentials=[forged, env.net.operator_credential()]))
    expect(d, Reason.VC_SIGNATURE, PublicCode.AUTH_FAILED)


async def test_credential_wrong_typ(env):
    cred = env.net.agent_credential(header={"typ": "JWT"})
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_TYP, PublicCode.AUTH_FAILED)


async def test_bare_jwt_not_enveloped(env):
    def build(n):
        return env.net.presentation(n, mutate=lambda p: p.update(
            verifiableCredential=[env.net.agent_credential(), env.net.operator_credential()]))
    expect(await run(env, build), Reason.VC_MALFORMED, PublicCode.AUTH_FAILED)


# -- check 4: trust registry -----------------------------------------------------


async def test_unlisted_issuer(env):
    rogue = env.net.rogue_issuer
    cred = env.net.agent_credential(signer=rogue)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.ISSUER_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED, check=4)
    # The verifier never fetched the unlisted issuer's DID.
    assert rogue.log_url not in env.net.fetcher.requests


async def test_issuer_not_accredited_for_tier(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0].update(tiers=["domain"]))
    expect(await run(env), Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, PublicCode.ISSUER_UNTRUSTED)


async def test_issuer_key_epoch_not_listed(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0]["keys"][0].update(kid="did:x#old"))
    expect(await run(env), Reason.ISSUER_KEY_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_retired_key_still_valid_for_what_it_signed(env):
    # Key retired yesterday; the operator credential was signed 8 days ago, but the
    # agent credential an hour ago, after retirement, so it must fail.
    env.net.publish_trust_list(lambda p: p["issuers"][0]["keys"][0].update(notAfter=int(env.clock.now) - 86400))
    expect(await run(env), Reason.ISSUER_KEY_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_trust_list_signed_by_unknown_key(env):
    env.net.publish_trust_list(key=ec.generate_private_key(ec.SECP256R1()))
    expect(await run(env), Reason.TRUST_LIST_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_trust_list_expired(env):
    env.net.publish_trust_list(lambda p: p.update(exp=int(env.clock.now) - 1))
    expect(await run(env), Reason.TRUST_LIST_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_trust_list_rollback_refused(env):
    v = env.verifier()
    assert (await run(env, verifier=v)).allowed
    # A mirror later serves an older, validly signed list that drops the issuer.
    env.net.publish_trust_list(lambda p: p.update(iat=p["iat"] - 5000, issuers=[]))
    env.clock.now += 3601  # trust list cache expires; refresh returns the old list
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) - 5), verifier=v)
    assert d.allowed, d.log_record()  # rollback refused, newer cached list kept


# -- check 5: validity and status --------------------------------------------------


async def test_agent_credential_expired(env):
    cred = env.net.agent_credential(valid_from=int(env.clock.now) - 9 * 3600)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_EXPIRED, PublicCode.CREDENTIAL_EXPIRED, check=5)


async def test_agent_credential_not_yet_valid(env):
    cred = env.net.agent_credential(valid_from=int(env.clock.now) + 600)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_NOT_YET_VALID, PublicCode.CREDENTIAL_EXPIRED)


async def test_agent_credential_over_max_lifetime(env):
    cred = env.net.agent_credential(lifetime=25 * 3600)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_LIFETIME, PublicCode.AUTH_FAILED)


async def test_emergency_lifetime_extension_via_trust_list(env):
    env.net.publish_trust_list(lambda p: p["policy"].update(agentCredentialMaxLifetime=48 * 3600))
    cred = env.net.agent_credential(lifetime=25 * 3600)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    assert d.allowed


async def test_iat_must_equal_valid_from(env):
    cred = env.net.agent_credential(mutate=lambda p: p.update(iat=p["iat"] - 1))
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_TIME_CLAIMS, PublicCode.AUTH_FAILED)


async def test_revoked_agent_credential(env):
    env.net.revoke(env.net.agent_status_url, 48213)
    expect(await run(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_revoked_operator_credential(env):
    env.net.revoke(env.net.operator_status_url, 17)
    expect(await run(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_neighbouring_bit_does_not_revoke(env):
    env.net.revoke(env.net.agent_status_url, 48212)
    env.net.revoke(env.net.agent_status_url, 48214)
    assert (await run(env)).allowed


async def test_operator_status_entry_required(env):
    cred = env.net.operator_credential(mutate=lambda p: p.pop("credentialStatus"))
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.STATUS_ENTRY_MISSING, PublicCode.AUTH_FAILED)
    v = env.verifier(require_operator_status=False)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]), verifier=v)
    assert d.allowed


async def test_status_list_signed_by_rogue(env):
    env.net.publish_status_list(env.net.agent_status_url, signer=env.net.rogue_issuer)
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_substituted_from_another_url(env):
    body = env.net.fetcher.files[env.net.operator_status_url]
    env.net.fetcher.put(env.net.agent_status_url, body)
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_too_short(env):
    from veridact_verify.status import encode_bitstring
    env.net.publish_status_list(env.net.agent_status_url, mutate=lambda p: p["credentialSubject"].update(
        encodedList=encode_bitstring(bytes(1024))))
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_unavailable_cold(env):
    del env.net.fetcher.files[env.net.agent_status_url]
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


@pytest.mark.parametrize(
    "age,risk,expected",
    [
        (3600, Risk.LOW, "allow"),
        (3600, Risk.MEDIUM, "flag"),
        (3600, Risk.HIGH, "block"),
        (5 * 3600, Risk.LOW, "block"),
    ],
)
async def test_degraded_mode(env, age, risk, expected):
    v = env.verifier()
    assert (await run(env, verifier=v)).allowed  # warm the cache
    env.net.fetcher.offline = True
    env.clock.now += age

    # Fresh credentials and presentation relative to the advanced clock.
    now = int(env.clock.now)
    creds = [env.net.agent_credential(valid_from=now - 60), env.net.operator_credential()]
    d = await run(env, lambda n: env.net.presentation(n, credentials=creds, iat=now - 5),
                  request=Request(risk=risk), verifier=v)
    if expected == "block":
        if age > 4 * 3600:
            # DID logs are past their stale limit too, and fail first.
            expect(d, Reason.DID_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)
        else:
            expect(d, Reason.STATUS_STALE, PublicCode.VERIFICATION_UNAVAILABLE)
    else:
        assert d.allowed, d.log_record()
        assert ("STATUS_STALE_REVIEW" in d.flags) == (expected == "flag")


# -- checks 6 and 7: bindings ----------------------------------------------------


async def test_cnf_mismatch(env):
    cred = env.net.agent_credential(mutate=lambda p: p["credentialSubject"]["cnf"].update(
        kid=env.net.agent.did + "#key-2"))
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.CNF_MISMATCH, PublicCode.AUTH_FAILED, check=6)


async def test_credential_for_another_agent(env):
    other = make_party("operator.example:agents:zz9", "authentication")
    env.net.fetcher.put(other.log_url, other.log)
    cred = env.net.agent_credential(mutate=lambda p: p["credentialSubject"].update(
        id=other.did, cnf={"kid": other.kid}))
    # The real agent presents a credential issued to someone else.
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.HOLDER_MISMATCH, PublicCode.AUTH_FAILED)


async def test_operator_mismatch(env):
    cred = env.net.operator_credential(mutate=lambda p: p["credentialSubject"].update(
        id="did:webvh:Qmother:other.example"))
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.OPERATOR_MISMATCH, PublicCode.AUTH_FAILED, check=7)


async def test_operator_credential_id_mismatch(env):
    cred = env.net.operator_credential(mutate=lambda p: p.update(id="urn:uuid:other"))
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.OPERATOR_MISMATCH, PublicCode.AUTH_FAILED)


async def test_operator_tier_below_agent_tier(env):
    cred = env.net.operator_credential(mutate=lambda p: p["credentialSubject"].update(tier="domain"),
                                       lifetime=60 * 86400)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.OPERATOR_TIER_BELOW_AGENT, PublicCode.AUTH_FAILED)


# -- check 8: relying-party policy -------------------------------------------------


async def test_tier_too_low(domain_env):
    env = domain_env
    cred = env.net.operator_credential(lifetime=60 * 86400)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.TIER_TOO_LOW, PublicCode.TIER_TOO_LOW, check=8)
    v = env.verifier(min_tier="domain")
    assert (await run(env, lambda n: env.net.presentation(
        n, credentials=[env.net.agent_credential(), cred]), verifier=v)).allowed


async def test_route_can_raise_minimum_tier(domain_env):
    env = domain_env
    cred = env.net.operator_credential(lifetime=60 * 86400)
    v = env.verifier(min_tier="domain")
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]),
                  request=Request(min_tier="organisation"), verifier=v)
    expect(d, Reason.TIER_TOO_LOW, PublicCode.TIER_TOO_LOW)


async def test_operator_not_allowed(env):
    v = env.verifier(allowed_operators=S({"did:webvh:Qmsomeone:else.example"}))
    expect(await run(env, verifier=v), Reason.OPERATOR_NOT_ALLOWED, PublicCode.OPERATOR_NOT_ALLOWED)


async def test_scope_not_held(env):
    d = await run(env, request=Request(scopes=S({"fs:payments:initiate"})))
    expect(d, Reason.SCOPE_NOT_HELD, PublicCode.SCOPE_NOT_HELD)


async def test_scope_held_but_not_allowed_by_rp(env):
    v = env.verifier(allowed_scopes=S({"fs:claims:read-status"}))
    d = await run(env, request=Request(scopes=S({"fs:quotes:create"})), verifier=v)
    expect(d, Reason.SCOPE_NOT_HELD, PublicCode.SCOPE_NOT_HELD)


def _pay_env(env, limits):
    cred = env.net.agent_credential(scopes=["fs:payments:initiate"], limits=limits)
    return lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()])


LIMITS = {"currency": "ZAR", "perPayment": "500.00", "perDay": "2000.00"}
PAY = S({"fs:payments:initiate"})


async def test_payment_within_limits(env):
    d = await run(env, _pay_env(env, LIMITS),
                  request=Request(scopes=PAY, payment=Payment(Decimal("499.99"), "ZAR", Decimal("1000"))))
    assert d.allowed, d.log_record()


async def test_payment_above_per_payment_limit_asks_a_person(env):
    d = await run(env, _pay_env(env, LIMITS),
                  request=Request(scopes=PAY, payment=Payment(Decimal("500.01"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)
    assert d.context["intent"]["amount"] == "500.01"


async def test_payment_above_daily_limit_asks_a_person(env):
    d = await run(env, _pay_env(env, LIMITS),
                  request=Request(scopes=PAY, payment=Payment(Decimal("400"), "ZAR", Decimal("1700"))))
    expect(d, Reason.LIMIT_PER_DAY, PublicCode.LIMIT_PER_DAY, Outcome.ASK_PERSON)


async def test_payment_without_delegated_limits_asks_a_person(env):
    d = await run(env, _pay_env(env, None), request=Request(scopes=PAY, payment=Payment(Decimal("1"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


async def test_payment_in_other_currency_asks_a_person(env):
    d = await run(env, _pay_env(env, LIMITS), request=Request(scopes=PAY, payment=Payment(Decimal("1"), "USD")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


# -- output hygiene ----------------------------------------------------------------


async def test_public_output_hides_cryptographic_detail(env):
    other = ec.generate_private_key(ec.SECP256R1())
    d = await run(env, lambda n: env.net.presentation(n, key=other))
    assert d.public() == {"decision": "deny", "code": "AUTH_FAILED"}
    assert d.log_record()["reason"] == "VP_SIGNATURE"


async def test_rollback_check_is_real(env):
    # Control for the test above: a fresh verifier accepts the old list and so denies.
    env.net.publish_trust_list(lambda p: p.update(iat=p["iat"] - 5000, issuers=[]))
    expect(await run(env), Reason.ISSUER_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_credential_kid_from_another_did(env):
    # Claims the real issuer but is signed by the rogue issuer's key.
    cred = env.net.agent_credential(mutate=lambda p: p.update(issuer=env.net.issuer.did),
                                    signer=env.net.rogue_issuer)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[cred, env.net.operator_credential()]))
    expect(d, Reason.VC_KID_INVALID, PublicCode.AUTH_FAILED)


async def test_operator_credential_expired(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0]["keys"][0].update(notBefore=0))
    cred = env.net.operator_credential(valid_from=int(env.clock.now) - 366 * 86400, lifetime=365 * 86400)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.VC_EXPIRED, PublicCode.CREDENTIAL_EXPIRED)


async def test_operator_credential_over_tier_lifetime(env):
    cred = env.net.operator_credential(lifetime=400 * 86400)
    d = await run(env, lambda n: env.net.presentation(n, credentials=[env.net.agent_credential(), cred]))
    expect(d, Reason.VC_LIFETIME, PublicCode.AUTH_FAILED)
