"""Behaviour of the eight verification checks (specification v0.5), one failure at a time."""

from __future__ import annotations

from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify import Outcome, Payment, PublicCode, Reason, Request, Risk, Verifier, jose, sdjwt, status
from veridact_verify.testing.mock_network import AUDIENCE, CLAUDE_CIMD

S = frozenset


async def run(env, build=None, request: Request = Request(), verifier: Verifier | None = None):
    verifier = verifier or env.verifier()
    nonce = verifier.nonces.issue()
    presentation = (build or (lambda n: env.net.presentation(n)))(nonce)
    return await verifier.verify(presentation, request)


def with_cred(env, **kw):
    cred = env.net.agent_credential(**kw)
    return lambda n: env.net.presentation(n, credential=cred)


def expect(decision, reason: Reason, code: PublicCode, outcome: Outcome = Outcome.DENY, check=None):
    assert decision.reason is reason, decision.log_record()
    assert decision.public_code is code
    assert decision.outcome is outcome
    assert decision.scopes_granted == []
    if check is not None:
        assert decision.check == check, decision.log_record()


# -- happy paths -----------------------------------------------------------------------


async def test_allows_valid_presentation(env):
    d = await run(env, request=Request(scopes=S({"fs:claims:read-status"})))
    assert d.allowed, d.log_record()
    assert d.public() == {"decision": "allow"}
    assert d.agent == env.net.agent.id
    assert d.operator == env.net.operator.id
    assert d.operator_domains == ["operator.example"]
    assert d.tier == "organisation"
    assert d.scopes_granted == ["fs:claims:read-status"]
    assert d.accountable_role == "Head of Digital Claims"
    assert d.agent_key_id == env.net.agent.jkt
    assert d.agent_jwk == env.net.agent.jwk
    assert d.disclosed["operator_legal_name"] == "Operator Example (Pty) Ltd"


async def test_agent_may_withhold_disclosures(env):
    d = await run(env, lambda n: env.net.presentation(n, disclose=[]))
    assert d.allowed, d.log_record()
    assert d.disclosed == {}


async def test_grants_intersection_with_rp_policy(env):
    v = env.verifier(allowed_scopes=S({"fs:quotes:create", "fs:other"}))
    d = await run(env, verifier=v)
    assert d.allowed
    assert d.scopes_granted == ["fs:quotes:create"]


async def test_scopes_outside_taxonomy_are_dropped(env):
    d = await run(env, with_cred(env, scopes=["fs:quotes:create", "made:up:scope"]))
    assert d.allowed
    assert d.scopes_held == ["fs:quotes:create"]


async def test_warm_cache_makes_no_network_calls(env):
    v = env.verifier()
    assert (await run(env, verifier=v)).allowed
    before = len(env.net.fetcher.requests)
    assert (await run(env, verifier=v)).allowed
    assert len(env.net.fetcher.requests) == before


async def test_authorization_header_round_trip(env):
    v = env.verifier(required_disclosures=S({"operator_legal_name"}))
    nonce, header = v.challenge(Request(scopes=S({"fs:quotes:create"})), realm="claims-api")
    assert header == (f'Veridact realm="claims-api", nonce="{nonce}", tier="organisation", '
                      'scope="fs:quotes:create", disclose="operator_legal_name"')
    presentation = env.net.presentation(nonce)
    assert Verifier.presentation_from_authorization(f'Veridact sd-jwt="{presentation}"') == presentation
    assert Verifier.presentation_from_authorization(f'Veridact vp="{presentation}"') is None
    assert Verifier.presentation_from_authorization("Bearer abc") is None
    assert (await v.verify(presentation)).allowed


# -- check 1: the SD-JWT+KB -----------------------------------------------------------------


async def test_malformed(env):
    expect(await run(env, lambda n: "not a token"), Reason.SDJWT_MALFORMED, PublicCode.AUTH_FAILED, check=1)


async def test_sd_jwt_without_key_binding(env):
    expect(await run(env, lambda n: env.net.agent_credential()), Reason.KB_MISSING, PublicCode.AUTH_FAILED)


async def test_wrong_kb_typ(env):
    d = await run(env, lambda n: env.net.presentation(n, header={"typ": "JWT"}))
    expect(d, Reason.KB_TYP, PublicCode.AUTH_FAILED, check=1)


@pytest.mark.parametrize("alg", ["none", "HS256", "RS256", "ES384"])
async def test_rejects_other_algorithms(env, alg):
    good = env.net.presentation("x")
    jwt, *rest = good.split("~")
    h, p, s = jwt.split(".")
    header = jose.b64url_encode(f'{{"alg":"{alg}","typ":"dc+sd-jwt"}}'.encode())
    d = await run(env, lambda n: "~".join([".".join([header, p, s]), *rest]))
    expect(d, Reason.SDJWT_MALFORMED, PublicCode.AUTH_FAILED)


async def test_wrong_audience(env):
    d = await run(env, lambda n: env.net.presentation(n, aud="https://other.example"))
    expect(d, Reason.KB_AUDIENCE, PublicCode.AUTH_FAILED)


async def test_audience_list(env):
    assert (await run(env, lambda n: env.net.presentation(n, aud=["https://x.example", AUDIENCE]))).allowed


async def test_missing_nonce(env):
    d = await run(env, lambda n: env.net.presentation(n, mutate=lambda p: p.pop("nonce")))
    expect(d, Reason.NONCE_MISSING, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_nonce_not_issued_here(env):
    d = await run(env, lambda n: env.net.presentation("f" * 32))
    expect(d, Reason.NONCE_UNKNOWN, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_replay_is_refused(env):
    v = env.verifier()
    nonce = v.nonces.issue()
    presentation = env.net.presentation(nonce)
    assert (await v.verify(presentation)).allowed
    d = await v.verify(presentation)
    expect(d, Reason.NONCE_UNKNOWN, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_old_key_binding_jwt(env):
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) - 151))
    expect(d, Reason.KB_EXPIRED, PublicCode.CHALLENGE_REQUIRED, Outcome.CHALLENGE)


async def test_key_binding_jwt_within_skew_allowed(env):
    assert (await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) - 140))).allowed


async def test_key_binding_jwt_from_future(env):
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) + 120))
    expect(d, Reason.KB_NOT_YET_VALID, PublicCode.AUTH_FAILED)


async def test_sd_hash_must_cover_presented_disclosures(env):
    # KB-JWT signed over all disclosures, then one is dropped on the way.
    def build(n):
        full = sdjwt.parse(env.net.presentation(n))
        kept = [d.raw for d in full.disclosures[1:]]
        return sdjwt.serialize(full.jws.raw, kept, full.kb_jwt)
    expect(await run(env, build), Reason.SD_HASH_MISMATCH, PublicCode.AUTH_FAILED, check=1)


async def test_sd_hash_wrong(env):
    d = await run(env, lambda n: env.net.presentation(n, mutate=lambda p: p.update(sd_hash="x")))
    expect(d, Reason.SD_HASH_MISMATCH, PublicCode.AUTH_FAILED)


# -- checks 2 and 3: trust list first, then the issuer's signature ---------------------------


async def test_unlisted_issuer_is_never_fetched(env):
    d = await run(env, with_cred(env, signer=env.net.rogue_issuer))
    expect(d, Reason.ISSUER_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED, check=4)
    assert not any("rogue.example" in url for url in env.net.fetcher.requests)


async def test_tampered_agent_credential(env):
    def build(n):
        jwt, *rest = env.net.presentation(n).split("~")
        h, p, s = jwt.split(".")
        body = jose.b64url_decode(p).replace(b"fs:quotes:create", b"fs:payments:initiate")
        forged = "~".join([".".join([h, jose.b64url_encode(body), s]), *rest[:-1]])
        return sdjwt.key_binding_jwt(forged + "~", aud=AUDIENCE, nonce=n, iat=int(env.clock.now),
                                     sign=sdjwt.key_signer(env.net.agent.key))
    expect(await run(env, build), Reason.VC_SIGNATURE, PublicCode.AUTH_FAILED, check=3)


async def test_failed_signature_does_not_burn_nonce(env):
    v = env.verifier()
    nonce = v.nonces.issue()
    other = ec.generate_private_key(ec.SECP256R1())
    assert (await v.verify(env.net.presentation(nonce, key=other))).reason is Reason.KB_SIGNATURE
    assert (await v.verify(env.net.presentation(nonce))).allowed


async def test_tampered_disclosure(env):
    def build(n):
        parsed = sdjwt.parse(env.net.agent_credential())
        fake = sdjwt.Disclosure.create("operator_legal_name", "Big Bank Ltd")
        bad = sdjwt.serialize(parsed.jws.raw, [fake.raw])
        return sdjwt.key_binding_jwt(bad, aud=AUDIENCE, nonce=n, iat=int(env.clock.now),
                                     sign=sdjwt.key_signer(env.net.agent.key))
    expect(await run(env, build), Reason.DISCLOSURE_INVALID, PublicCode.AUTH_FAILED, check=3)


async def test_disclosure_cannot_overwrite_signed_claim(env):
    # An issuer bug, or a forgery attempt: a disclosure that names a claim already signed in clear.
    claims = env.net.agent_claims(valid_from=int(env.clock.now) - 60, lifetime=3600, status_index=48213,
                                  scopes=None, limits=None)
    fake = sdjwt.Disclosure.create("tier", "domain")
    claims.update(_sd=[fake.digest], _sd_alg="sha-256")
    jwt = env.net.issuer.sign({"typ": "dc+sd-jwt"}, claims)
    cred = sdjwt.serialize(jwt, [fake.raw])
    d = await run(env, lambda n: env.net.presentation(n, credential=cred))
    expect(d, Reason.DISCLOSURE_INVALID, PublicCode.AUTH_FAILED)


async def test_credential_wrong_typ(env):
    d = await run(env, with_cred(env, header={"typ": "vc+sd-jwt"}))
    expect(d, Reason.VC_TYP, PublicCode.AUTH_FAILED)


async def test_operator_credential_is_not_an_agent_credential(env):
    cred = env.net.operator_credential()
    d = await run(env, lambda n: env.net.presentation(n, credential=cred))
    expect(d, Reason.VCT_UNEXPECTED, PublicCode.AUTH_FAILED)


async def test_kid_not_pinned_in_trust_list(env):
    claims = env.net.agent_claims(valid_from=int(env.clock.now) - 60, lifetime=3600, status_index=48213,
                                  scopes=None, limits=None)
    cred = sdjwt.issue({}, claims, {}, lambda h, p: jose.sign({**h, "kid": "other"}, p, env.net.issuer.key))
    d = await run(env, lambda n: env.net.presentation(n, credential=cred))
    expect(d, Reason.ISSUER_KEY_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED, check=4)


async def test_metadata_key_must_match_pinned_key(env):
    # Someone who controls the issuer's web host swaps the key in its metadata.
    rogue = ec.generate_private_key(ec.SECP256R1())
    env.net.publish_issuer_metadata(env.net.issuer, mutate=lambda doc: doc["jwks"]["keys"][0].update(
        jose.key_to_jwk(rogue.public_key())))
    expect(await run(env), Reason.ISSUER_KEY_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_metadata_for_another_issuer(env):
    env.net.publish_issuer_metadata(env.net.issuer, mutate=lambda doc: doc.update(issuer="https://x.example"))
    expect(await run(env), Reason.ISSUER_METADATA_INVALID, PublicCode.AUTH_FAILED)


async def test_metadata_unavailable_cold(env):
    from veridact_verify.identifiers import issuer_metadata_url
    del env.net.fetcher.files[issuer_metadata_url(env.net.issuer.id)]
    expect(await run(env), Reason.ISSUER_METADATA_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_metadata_by_jwks_uri_refused(env):
    env.net.publish_issuer_metadata(env.net.issuer, mutate=lambda doc: doc.update(
        jwks_uri="https://veridact.example/jwks.json") or doc.pop("jwks"))
    expect(await run(env), Reason.ISSUER_METADATA_INVALID, PublicCode.AUTH_FAILED)


# -- check 4: trust registry -------------------------------------------------------------


async def test_issuer_not_accredited_for_tier(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0].update(tiers=["domain"]))
    expect(await run(env), Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, PublicCode.ISSUER_UNTRUSTED, check=4)


async def test_issuer_not_accredited_for_vct(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0].update(vcts=["https://veridact.net/vct/operator/v1"]))
    expect(await run(env), Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, PublicCode.ISSUER_UNTRUSTED)


async def test_retired_key_cannot_sign_new_credentials(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0]["keys"][0].update(notAfter=int(env.clock.now) - 86400))
    expect(await run(env), Reason.ISSUER_KEY_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_trust_list_keys_need_a_thumbprint(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0]["keys"][0].pop("jkt"))
    expect(await run(env), Reason.TRUST_LIST_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


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
    env.clock.now += 3601
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) - 5), verifier=v)
    assert d.allowed, d.log_record()  # rollback refused, newer cached list kept


async def test_rollback_check_is_real(env):
    # Control for the test above: a fresh verifier accepts the old list and so denies.
    env.net.publish_trust_list(lambda p: p.update(iat=p["iat"] - 5000, issuers=[]))
    expect(await run(env), Reason.ISSUER_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


# -- check 5: validity and status -----------------------------------------------------------


async def test_agent_credential_expired(env):
    d = await run(env, with_cred(env, valid_from=int(env.clock.now) - 9 * 3600))
    expect(d, Reason.VC_EXPIRED, PublicCode.CREDENTIAL_EXPIRED, check=5)


async def test_agent_credential_not_yet_valid(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.update(nbf=int(env.clock.now) + 600)))
    expect(d, Reason.VC_NOT_YET_VALID, PublicCode.CREDENTIAL_EXPIRED)


async def test_agent_credential_over_max_lifetime(env):
    d = await run(env, with_cred(env, lifetime=25 * 3600))
    expect(d, Reason.VC_LIFETIME, PublicCode.AUTH_FAILED)


async def test_emergency_lifetime_extension_via_trust_list(env):
    env.net.publish_trust_list(lambda p: p["policy"].update(agentCredentialMaxLifetime=48 * 3600))
    assert (await run(env, with_cred(env, lifetime=25 * 3600))).allowed


async def test_time_claims_must_be_integers(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.update(exp="tomorrow")))
    expect(d, Reason.VC_TIME_CLAIMS, PublicCode.AUTH_FAILED)


async def test_revoked_agent_credential(env):
    env.net.revoke(env.net.agent_status_url, 48213)
    expect(await run(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_suspended_agent_credential(env):
    env.net.set_status(env.net.agent_status_url, 48213, status.SUSPENDED)
    expect(await run(env), Reason.STATUS_SUSPENDED, PublicCode.AUTH_FAILED)


async def test_revoked_operator_stops_its_agents(env):
    env.net.revoke(env.net.operator_status_url, 17)
    expect(await run(env), Reason.OPERATOR_REVOKED, PublicCode.AUTH_FAILED, check=5)


async def test_suspended_operator(env):
    env.net.set_status(env.net.operator_status_url, 17, status.SUSPENDED)
    expect(await run(env), Reason.OPERATOR_SUSPENDED, PublicCode.AUTH_FAILED)


async def test_status_value_three_is_refused(env):
    env.net.set_status(env.net.agent_status_url, 48213, 3)
    expect(await run(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_neighbouring_entries_do_not_revoke(env):
    env.net.revoke(env.net.agent_status_url, 48212)
    env.net.revoke(env.net.agent_status_url, 48214)
    assert (await run(env)).allowed


async def test_operator_status_reference_required(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.pop("operator_status")))
    expect(d, Reason.STATUS_ENTRY_MISSING, PublicCode.AUTH_FAILED)
    v = env.verifier(require_operator_status=False)
    assert (await run(env, with_cred(env, mutate=lambda c: c.pop("operator_status")), verifier=v)).allowed


async def test_own_status_reference_required(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.pop("status")))
    expect(d, Reason.STATUS_ENTRY_MISSING, PublicCode.AUTH_FAILED)


async def test_status_list_signed_by_rogue(env):
    env.net.publish_status_list(env.net.agent_status_url, signer=env.net.rogue_issuer)
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_signed_with_real_iss_but_rogue_key(env):
    env.net.publish_status_list(env.net.agent_status_url, signer=env.net.rogue_issuer,
                                mutate=lambda p: p.update(iss=env.net.issuer.id))
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_substituted_from_another_url(env):
    body = env.net.fetcher.files[env.net.operator_status_url]
    env.net.fetcher.put(env.net.agent_status_url, body)
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_too_short(env):
    env.net.publish_status_list(env.net.agent_status_url, mutate=lambda p: p.update(
        status_list=status.encode_list(bytes(1024))))
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_one_bit_refused(env):
    env.net.publish_status_list(env.net.agent_status_url, mutate=lambda p: p["status_list"].update(bits=1))
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
    now = int(env.clock.now)
    cred = env.net.agent_credential(valid_from=now - 60)
    d = await run(env, lambda n: env.net.presentation(n, credential=cred, iat=now - 5),
                  request=Request(risk=risk), verifier=v)
    if expected == "block":
        if age > 4 * 3600:
            # Issuer metadata is past its stale limit too, and fails first.
            expect(d, Reason.ISSUER_METADATA_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)
        else:
            expect(d, Reason.STATUS_STALE, PublicCode.VERIFICATION_UNAVAILABLE)
    else:
        assert d.allowed, d.log_record()
        assert ("STATUS_STALE_REVIEW" in d.flags) == (expected == "flag")


async def test_status_age_is_measured_from_the_list_iat(env):
    # A mirror serves an hour-old list on first fetch: the cache is fresh, the list is not.
    env.net.publish_status_list(env.net.agent_status_url, iat=int(env.clock.now) - 3600)
    d = await run(env, request=Request(risk=Risk.MEDIUM))
    assert d.allowed and "STATUS_STALE_REVIEW" in d.flags
    d = await run(env, request=Request(risk=Risk.HIGH))
    expect(d, Reason.STATUS_STALE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_lifetime_over_four_hours_refused(env):
    env.net.publish_status_list(env.net.agent_status_url, mutate=lambda p: p.update(exp=p["iat"] + 4 * 3600 + 1))
    expect(await run(env), Reason.STATUS_UNAVAILABLE, PublicCode.VERIFICATION_UNAVAILABLE)


async def test_status_list_rollback_refused(env):
    v = env.verifier()
    env.net.revoke(env.net.agent_status_url, 48213)
    assert (await run(env, verifier=v)).reason is Reason.STATUS_REVOKED
    # A mirror serves an older, unrevoked list after the cache expires.
    env.net.status_values[env.net.agent_status_url].clear()
    env.net.publish_status_list(env.net.agent_status_url, iat=int(env.clock.now) - 180)
    env.clock.now += 301
    d = await run(env, lambda n: env.net.presentation(n, iat=int(env.clock.now) - 5), verifier=v)
    assert d.reason is Reason.STATUS_REVOKED


# -- check 6: key binding ---------------------------------------------------------------------


async def test_key_binding_signed_by_another_key(env):
    other = ec.generate_private_key(ec.SECP256R1())
    expect(await run(env, lambda n: env.net.presentation(n, key=other)),
           Reason.KB_SIGNATURE, PublicCode.AUTH_FAILED, check=6)


async def test_stolen_credential_without_the_key(env):
    # Someone copies the agent's SD-JWT and signs a KB-JWT with their own key.
    thief = ec.generate_private_key(ec.SECP256R1())
    d = await run(env, lambda n: sdjwt.present(env.net.agent_credential(), disclose=None, aud=AUDIENCE,
                                               nonce=n, iat=int(env.clock.now), sign=sdjwt.key_signer(thief)))
    expect(d, Reason.KB_SIGNATURE, PublicCode.AUTH_FAILED, check=6)


async def test_credential_without_cnf(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.pop("cnf")))
    expect(d, Reason.CNF_MISSING, PublicCode.AUTH_FAILED, check=6)


async def test_cnf_key_must_be_logged(env):
    d = await run(env, with_cred(env, mutate=lambda c: c.pop("cnf_event")))
    expect(d, Reason.KEY_NOT_LOGGED, PublicCode.AUTH_FAILED, check=6)


# -- check 7: disclosure ------------------------------------------------------------------------


async def test_route_requires_disclosure(env):
    request = Request(disclose=S({"operator_legal_name"}))
    d = await run(env, lambda n: env.net.presentation(n, disclose=["operator_jurisdiction"]), request=request)
    expect(d, Reason.CLAIMS_NOT_DISCLOSED, PublicCode.AUTH_FAILED, check=7)
    assert d.context["missingClaims"] == ["operator_legal_name"]
    d = await run(env, lambda n: env.net.presentation(n, disclose=["operator_legal_name"]), request=request)
    assert d.allowed and d.disclosed == {"operator_legal_name": "Operator Example (Pty) Ltd"}


async def test_policy_requires_disclosure(env):
    v = env.verifier(required_disclosures=S({"operator_registration"}))
    d = await run(env, lambda n: env.net.presentation(n, disclose=[]), verifier=v)
    expect(d, Reason.CLAIMS_NOT_DISCLOSED, PublicCode.AUTH_FAILED)


# -- check 8: relying-party policy ----------------------------------------------------------------


async def test_tier_too_low(domain_env):
    d = await run(domain_env)
    expect(d, Reason.TIER_TOO_LOW, PublicCode.TIER_TOO_LOW, check=8)
    v = domain_env.verifier(min_tier="domain")
    assert (await run(domain_env, verifier=v)).allowed


async def test_route_can_raise_minimum_tier(domain_env):
    v = domain_env.verifier(min_tier="domain")
    d = await run(domain_env, request=Request(min_tier="organisation"), verifier=v)
    expect(d, Reason.TIER_TOO_LOW, PublicCode.TIER_TOO_LOW)


async def test_operator_not_allowed(env):
    v = env.verifier(allowed_operators=S({"https://someone-else.example"}))
    expect(await run(env, verifier=v), Reason.OPERATOR_NOT_ALLOWED, PublicCode.OPERATOR_NOT_ALLOWED)


async def test_scope_not_held(env):
    d = await run(env, request=Request(scopes=S({"fs:payments:initiate"})))
    expect(d, Reason.SCOPE_NOT_HELD, PublicCode.SCOPE_NOT_HELD)
    assert d.context["missingScopes"] == ["fs:payments:initiate"]


async def test_scope_held_but_not_allowed_by_rp(env):
    v = env.verifier(allowed_scopes=S({"fs:quotes:create"}))
    d = await run(env, request=Request(scopes=S({"fs:claims:read-status"})), verifier=v)
    expect(d, Reason.SCOPE_NOT_HELD, PublicCode.SCOPE_NOT_HELD)


LIMITS = {"currency": "ZAR", "per_payment": "500.00", "per_day": "2000.00"}
PAY = S({"fs:payments:initiate"})


def pay(env, limits=LIMITS):
    return with_cred(env, scopes=["fs:payments:initiate"], limits=limits)


async def test_payment_within_limits(env):
    d = await run(env, pay(env), Request(scopes=PAY, payment=Payment(Decimal("499.99"), "ZAR", Decimal("1000"))))
    assert d.allowed, d.log_record()
    assert d.context["limits"]["per_payment"] == "500.00"
    assert d.limits == LIMITS


async def test_payment_above_per_payment_limit_asks_a_person(env):
    d = await run(env, pay(env), Request(scopes=PAY, payment=Payment(Decimal("500.01"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)
    assert d.context["intent"]["amount"] == "500.01"


async def test_payment_above_daily_limit_asks_a_person(env):
    d = await run(env, pay(env), Request(scopes=PAY, payment=Payment(Decimal("100"), "ZAR", Decimal("1950"))))
    expect(d, Reason.LIMIT_PER_DAY, PublicCode.LIMIT_PER_DAY, Outcome.ASK_PERSON)


async def test_payment_without_delegated_limits_asks_a_person(env):
    d = await run(env, pay(env, limits=None), Request(scopes=PAY, payment=Payment(Decimal("1"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


async def test_payment_in_other_currency_asks_a_person(env):
    d = await run(env, pay(env), Request(scopes=PAY, payment=Payment(Decimal("1"), "USD")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


async def test_v04_camel_case_limits_are_not_read(env):
    d = await run(env, pay(env, limits={"currency": "ZAR", "perPayment": "500.00", "perDay": "2000.00"}),
                  Request(scopes=PAY, payment=Payment(Decimal("1"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


# -- output hygiene -------------------------------------------------------------------------------


async def test_public_output_hides_cryptographic_detail(env):
    other = ec.generate_private_key(ec.SECP256R1())
    d = await run(env, lambda n: env.net.presentation(n, key=other))
    assert d.public() == {"decision": "deny", "code": "AUTH_FAILED"}
    assert d.log_record()["reason"] == "KB_SIGNATURE"


# -- pattern C: client attestations ------------------------------------------------------------------


async def attest(env, attestation=None, *, client_id=None, dpop_jkt=None, request=Request()):
    return await env.verifier().verify_client_attestation(
        attestation or env.net.client_attestation(), client_id=client_id or env.net.agent.id,
        dpop_jkt=dpop_jkt or env.net.agent.jkt, request=request)


async def test_client_attestation_admits_the_agent(env):
    d = await attest(env, request=Request(scopes=S({"fs:quotes:create"})))
    assert d.allowed, d.log_record()
    assert d.agent == env.net.agent.id and d.operator == env.net.operator.id
    assert d.agent_key_id == env.net.agent.jkt
    assert d.scopes_granted == ["fs:quotes:create"]


async def test_client_attestation_for_another_client(env):
    d = await attest(env, client_id="https://operator.example/agents/other")
    expect(d, Reason.CLIENT_MISMATCH, PublicCode.AUTH_FAILED, check=6)


async def test_client_attestation_with_another_dpop_key(env):
    d = await attest(env, dpop_jkt="not-the-agent-key")
    expect(d, Reason.DPOP_KEY_MISMATCH, PublicCode.AUTH_FAILED)


async def test_client_attestation_revoked_with_its_credential(env):
    env.net.revoke(env.net.agent_status_url, 48213)
    expect(await attest(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_client_attestation_operator_revoked(env):
    env.net.revoke(env.net.operator_status_url, 17)
    expect(await attest(env), Reason.OPERATOR_REVOKED, PublicCode.AUTH_FAILED)


async def test_client_attestation_wrong_typ(env):
    token = env.net.issuer.sign({"typ": "JWT"}, jose.parse(env.net.client_attestation()).payload)
    expect(await attest(env, token), Reason.VC_TYP, PublicCode.AUTH_FAILED)


async def test_client_attestation_scope_not_held(env):
    d = await attest(env, request=Request(scopes=S({"fs:payments:initiate"})))
    expect(d, Reason.SCOPE_NOT_HELD, PublicCode.SCOPE_NOT_HELD)


async def test_client_attestation_payment_limits(env):
    att = env.net.client_attestation(limits=LIMITS, mutate=lambda c: c["veridact"].update(
        scopes=["fs:payments:initiate"]))
    d = await attest(env, att, request=Request(scopes=PAY, payment=Payment(Decimal("600"), "ZAR")))
    expect(d, Reason.LIMIT_PER_PAYMENT, PublicCode.LIMIT_PER_PAYMENT, Outcome.ASK_PERSON)


# -- known-assistant entries -------------------------------------------------------------------------


async def assistant(env, entry=None, client_id=CLAUDE_CIMD):
    return await env.verifier().verify_known_assistant(entry or env.net.known_assistant(), client_id=client_id)


async def test_known_assistant_entry(env):
    d = await assistant(env)
    assert d.allowed, d.log_record()
    assert d.operator == "Anthropic PBC"
    assert d.context["maxLevel"] == "approved_payer"
    assert d.context["platform"] == CLAUDE_CIMD


async def test_known_assistant_matches_any_of_its_client_metadata_urls(env):
    assert (await assistant(env, client_id="https://claude.ai/oauth/claude-code-client-metadata.json")).allowed


async def test_known_assistant_for_another_client(env):
    d = await assistant(env, client_id="https://chatgpt.com/oauth/client.json")
    expect(d, Reason.ASSISTANT_NOT_LISTED, PublicCode.AUTH_FAILED, check=6)


async def test_known_assistant_suspended_is_the_kill_switch(env):
    env.net.set_status(env.net.assistant_status_url, 3, status.SUSPENDED)
    expect(await assistant(env), Reason.STATUS_SUSPENDED, PublicCode.AUTH_FAILED, check=5)


async def test_known_assistant_withdrawn(env):
    env.net.revoke(env.net.assistant_status_url, 3)
    expect(await assistant(env), Reason.STATUS_REVOKED, PublicCode.AUTH_FAILED)


async def test_known_assistant_needs_organisation_accreditation(env):
    env.net.publish_trust_list(lambda p: p["issuers"][0].update(tiers=["domain"]))
    expect(await assistant(env), Reason.ISSUER_NOT_ACCREDITED_FOR_TIER, PublicCode.ISSUER_UNTRUSTED)


async def test_known_assistant_from_unlisted_issuer(env):
    expect(await assistant(env, env.net.known_assistant(signer=env.net.rogue_issuer)),
           Reason.ISSUER_NOT_LISTED, PublicCode.ISSUER_UNTRUSTED)


async def test_agent_credential_is_not_a_known_assistant_entry(env):
    expect(await assistant(env, env.net.agent_credential(), client_id=env.net.agent.id),
           Reason.VCT_UNEXPECTED, PublicCode.AUTH_FAILED)
