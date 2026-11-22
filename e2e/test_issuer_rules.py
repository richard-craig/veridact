"""What the issuer refuses. Each test is one way to get a credential you should not have."""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import aiohttp
import pytest
from vbot import AcmeClient, AcmeError, Vbot, VbotError
from vbot.keys import SoftwareKey
from veridact_verify import jose, sdjwt
from veridact_verify import status as tsl
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ISSUER_HOST, OPERATOR_DOMAIN, Network
from test_issuance import onboard


Refused = (AcmeError, VbotError)


def claims(token: str) -> dict:
    """Claims of an SD-JWT (disclosures applied) or of a plain JWT."""
    return sdjwt.parse(token).claims() if "~" in token else jose.parse(token).payload


def resign_delegation(bot, agent_id: str, payload: dict, *, key=None) -> None:
    op = bot.operator()
    key = key or bot.keys.get("operator")
    bot.agent(agent_id)["delegation"] = sdjwt.issue(
        {}, payload, {}, lambda h, p: key.sign({**h, "kid": op["jkt"]}, p))


# -- ACME envelope -------------------------------------------------------------------------


async def test_acme_envelope_rules(network: Network):
    key = SoftwareKey(ec.generate_private_key(ec.SECP256R1()))
    async with AcmeClient(network.directory, key, routes=network.routes) as acme:
        directory = await acme.directory()
        # Signed for one URL, sent to another.
        nonce = await acme._fresh_nonce()
        body = acme._jws(directory["newOrder"], nonce, {"termsOfServiceAgreed": True}, True)
        async with acme.session.post(acme._route(directory["newAccount"]), data=body,
                                     headers={"Content-Type": "application/jose+json"}) as r:
            assert r.status == 401
            assert (await r.json())["type"].endswith(":unauthorized")
        # A nonce works once.
        nonce = await acme._fresh_nonce()
        body = acme._jws(directory["newAccount"], nonce, {"termsOfServiceAgreed": True}, True)
        for expected in (201, 400):
            async with acme.session.post(acme._route(directory["newAccount"]), data=body,
                                         headers={"Content-Type": "application/jose+json"}) as r:
                assert r.status == expected
                if expected == 400:
                    assert (await r.json())["type"].endswith(":badNonce")
        # Only ES256.
        header = jose.b64url_encode(json.dumps({"alg": "HS256", "nonce": "x", "url": "y"}).encode())
        async with acme.session.post(acme._route(directory["newAccount"]),
                                     data=json.dumps({"protected": header, "payload": "", "signature": "AA"}),
                                     headers={"Content-Type": "application/jose+json"}) as r:
            assert (await r.json())["type"].endswith(":badSignatureAlgorithm")


async def test_terms_must_be_agreed(network: Network):
    key = SoftwareKey(ec.generate_private_key(ec.SECP256R1()))
    async with AcmeClient(network.directory, key, routes=network.routes) as acme:
        with pytest.raises(Refused, match="terms"):
            await acme.register(agree_tos=False)


async def test_accounts_cannot_see_each_others_orders(network: Network):
    bot, _ = await onboard(network)
    other = SoftwareKey(ec.generate_private_key(ec.SECP256R1()))
    async with AcmeClient(network.directory, other, routes=network.routes) as acme:
        await acme.register()
        with pytest.raises(AcmeError) as err:
            await acme.download(bot.state["operator"]["credentialUrl"])
        assert err.value.status == 404
        with pytest.raises(AcmeError):
            await acme.revoke(bot.state["operator"]["credential"])


# -- operator validation ----------------------------------------------------------------


async def test_dns01(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)

    async def publish(name: str, value: str) -> None:
        network.txt.records[name] = [value]

    op = await bot.obtain_operator_credential(challenge="dns-01", before_respond=publish)
    cred = claims(op["credential"])
    assert cred["domains"] == [OPERATOR_DOMAIN]
    assert cred["sub"] == f"https://{OPERATOR_DOMAIN}"
    assert jose.jwk_thumbprint(cred["cnf"]["jwk"]) == op["jkt"]


async def test_dns01_wrong_record(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)

    async def publish(name: str, value: str) -> None:
        network.txt.records[name] = ["not-the-value"]

    with pytest.raises(Refused, match="incorrectResponse|TXT"):
        await bot.obtain_operator_credential(challenge="dns-01", before_respond=publish)


async def test_operator_document_must_name_this_operator(network: Network):
    """A domain's veridact-operator.json must say it is that domain's operator."""
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)
    path = network.vbot_home / "publish/.well-known/veridact-operator.json"
    doc = json.loads(path.read_text())
    doc["operator"] = "https://elsewhere.veridact.test"
    path.write_text(json.dumps(doc))
    with pytest.raises(Refused, match="different operator"):
        await bot.obtain_operator_credential()


async def test_operator_keys01_names_a_listed_key(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)
    bot.state["operator"]["jkt"] = "not-a-listed-key"
    with pytest.raises(Refused, match="name the delegation key"):
        await bot.obtain_operator_credential()


async def test_operator_finalize_needs_the_operator_key(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)
    bot.keys.dir.joinpath("operator.pem").unlink()  # finalize will sign with a fresh, unlisted key
    bot.keys.get_or_create("operator")
    with pytest.raises(Refused, match="badCSR|not a key the subject publishes"):
        await bot.obtain_operator_credential()


# -- agent issuance --------------------------------------------------------------------------


async def test_agent_credential_claims(network: Network):
    bot, agent_id = await onboard(network)
    bot.delegate(agent_id, ["fs:claims:read-status"], role="Ops", max_lifetime=1800)
    agent = await bot.issue(agent_id, lifetime=24 * 3600)
    assert agent["exp"] - agent["iat"] == 1800  # capped by the delegation
    cred = claims(agent["credential"])
    assert sdjwt.parse(agent["credential"]).jws.typ == "dc+sd-jwt"
    assert cred["vct"] == "https://veridact.net/vct/agent/v1"
    assert cred["iss"] == network.issuer.identity.id
    assert jose.jwk_thumbprint(cred["cnf"]["jwk"]) == agent["jkt"]
    assert cred["operator_credential"] == bot.operator()["credentialId"]
    assert cred["operator_status"] == claims(bot.operator()["credential"])["status"]
    assert cred["cnf_event"].startswith("veridact-staging-log-0/")
    assert cred["nbf"] == cred["iat"]


@pytest.mark.parametrize("change, match", [
    ({"scopes": ["fs:made:up"]}, "scopes not allowed"),
    ({"environment": "production"}, "environment"),
    ({"limits": {"currency": "ZAR", "per_payment": "5000.00", "per_day": "9000.00"}}, "two approvers"),
    ({"limits": {"currency": "ZAR", "per_payment": 500, "per_day": "900.00"}}, "decimal string"),
    ({"limits": {"currency": "ZAR", "perPayment": "5.00", "perDay": "9.00"}}, "per_payment"),
    ({"accountable_role": ""}, "accountable_role"),
    ({"vct": "https://veridact.net/vct/agent/v1"}, "vct"),
])
async def test_delegation_rules(network: Network, change, match):
    bot, agent_id = await onboard(network)
    payload = {**claims(bot.agent(agent_id)["delegation"]), **change}
    resign_delegation(bot, agent_id, payload)
    with pytest.raises(Refused, match=match):
        await bot.issue(agent_id)


async def test_delegation_over_90_days_refused(network: Network):
    bot, agent_id = await onboard(network)
    payload = claims(bot.agent(agent_id)["delegation"])
    payload["exp"] = payload["iat"] + 120 * 86400
    resign_delegation(bot, agent_id, payload)
    with pytest.raises(Refused, match="90 days"):
        await bot.issue(agent_id)


async def test_delegation_must_come_from_the_operator_key(network: Network):
    bot, agent_id = await onboard(network)
    payload = claims(bot.agent(agent_id)["delegation"])
    # Signed by the agent's own key, claiming the operator's kid.
    resign_delegation(bot, agent_id, payload, key=bot.keys.get(f"agent-{agent_id}"))
    with pytest.raises(Refused, match="signature"):
        await bot.issue(agent_id)


async def test_delegation_for_another_agent(network: Network):
    bot, agent_id = await onboard(network)
    payload = claims(bot.agent(agent_id)["delegation"])
    payload["sub"] = f"https://{OPERATOR_DOMAIN}/agents/someone-else"
    resign_delegation(bot, agent_id, payload)
    with pytest.raises(Refused, match="different agent"):
        await bot.issue(agent_id)


async def test_delegation_cannot_be_used_by_another_account(network: Network):
    """A leaked delegation is useless to anyone without the operator's account."""
    bot, agent_id = await onboard(network)
    thief_key = SoftwareKey(ec.generate_private_key(ec.SECP256R1()))
    async with AcmeClient(network.directory, thief_key, routes=network.routes) as acme:
        await acme.register()
        with pytest.raises(Refused, match="no valid Operator Credential"):
            await acme.new_order({"type": "agent", "value": bot.agent(agent_id)["id"]})


@pytest.mark.parametrize("url", [
    "https://elsewhere.veridact.test/agents/a1b2c3",
    f"https://{OPERATOR_DOMAIN}/bots/a1b2c3",
    f"https://{ISSUER_HOST}/agents/someone-elses-slug/a1b2c3",
    f"https://{OPERATOR_DOMAIN}/agents/A1?x=1",
])
async def test_agent_must_live_with_its_operator(network: Network, url):
    bot, _ = await onboard(network)
    async with bot.client() as acme:
        with pytest.raises(Refused, match="agent URL must be"):
            await acme.new_order({"type": "agent", "value": url})


async def test_agent_key_must_be_in_its_client_metadata(network: Network):
    bot, agent_id = await onboard(network, hosted=False)
    agent = bot.agent(agent_id)
    path = network.vbot_home / "publish/agents" / agent_id
    doc = json.loads(path.read_text())
    doc["jwks"]["keys"][0].update(jose.key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key()))
    path.write_text(json.dumps(doc))
    with pytest.raises(Refused, match="badCSR|not a key the subject publishes"):
        await bot.issue(agent_id)
    path.write_text(json.dumps({**doc, "client_id": agent["id"] + "-x"}))
    with pytest.raises(Refused, match="client_id"):
        await bot.issue(agent_id)


async def test_finalize_key_binding_rules(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    key = bot.keys.get(f"agent-{agent_id}")
    async with bot.client() as acme:
        for bad in ("aud", "nonce", "iat", "iss"):
            order_url, order = await acme.new_order({"type": "agent", "value": agent["id"]})
            authz = await acme.get(order["authorizations"][0])
            await acme.respond(authz["challenges"][0]["url"], {"delegation": agent["delegation"]})

            def kb(nonce: str, bad=bad, order=order) -> str:
                claims_ = {"iss": agent["id"], "aud": order["finalize"], "nonce": nonce,
                           "iat": int(time.time())}
                claims_[bad] = {"aud": "https://elsewhere", "nonce": "stale", "iat": 1,
                                "iss": "https://elsewhere.example"}[bad]
                return key.sign({"typ": "veridact-kb+jwt", "kid": agent["jkt"]}, claims_)

            with pytest.raises(Refused, match="badCSR|key binding"):
                await acme.finalize(order, kb)
            assert (await acme.get(order_url))["status"] == "invalid"


# -- client attestations (pattern C) ----------------------------------------------------------


async def test_client_attestation_form(network: Network):
    bot, agent_id = await onboard(network)
    agent = await bot.issue(agent_id, attestation=True)
    att = jose.parse(agent["attestation"])
    cred = claims(agent["credential"])
    assert att.typ == "oauth-client-attestation+jwt"
    for name in ("iss", "sub", "iat", "exp", "cnf", "status"):
        assert att.payload[name] == cred[name]
    assert att.payload["veridact"]["credential"] == cred["jti"]
    assert att.payload["veridact"]["operator_status"] == cred["operator_status"]


async def test_client_attestation_not_ordered(network: Network):
    bot, agent_id = await onboard(network)
    async with bot.client() as acme:
        with pytest.raises(AcmeError) as err:
            await acme.download(bot.agent(agent_id)["credentialUrl"] + "/attestation")
        assert err.value.status == 404
        with pytest.raises(Refused, match="formats"):
            await acme.new_order({"type": "agent", "value": bot.agent(agent_id)["id"]},
                                 formats=["client-attestation"])


# -- key events ----------------------------------------------------------------------------------


async def test_key_compromise_revokes_every_credential_with_that_key(network: Network):
    bot, agent_id = await onboard(network)
    first = bot.agent(agent_id)["credential"]
    second = (await bot.issue(agent_id))["credential"]
    event = await bot.retire_key(agent_id, compromised=True)
    assert event["action"] == "compromise"
    store = network.issuer.store
    for token in (first, second):
        cred = store.credential(claims(token)["jti"].removeprefix("urn:uuid:"))
        assert cred["revoked"] == 1
        assert network.issuer.status.value(cred["status_list"], cred["status_index"]) == tsl.INVALID
    # The key cannot come back, and the issuer will not sign it again.
    with pytest.raises(Refused, match="compromised and cannot return|no longer"):
        await bot.issue(agent_id)


async def test_key_events_are_logged_before_they_take_effect(network: Network):
    bot, agent_id = await onboard(network)
    await bot.retire_key(agent_id)
    entries = network.issuer.store.tlog_range(1, 100)
    events = [e["entry"] for e in entries if e["entry"]["type"] == "key-event"]
    assert [(e["subject"], e["action"]) for e in events] == [
        (bot.operator()["id"], "add"), (bot.agent(agent_id)["id"], "add"), (bot.agent(agent_id)["id"], "retire")]


async def test_key_event_for_someone_elses_subject(network: Network):
    bot, agent_id = await onboard(network)
    other = Vbot.create(network.tmp / "other", network.directory, network.routes)
    await other.register()
    async with other.client() as acme:
        with pytest.raises(Refused, match="does not belong"):
            await acme.key_event(bot.agent(agent_id)["id"], bot.agent(agent_id)["jkt"], "compromise")


async def test_operator_key_retirement_revokes_the_operator(network: Network):
    """The Operator Credential names the operator key, so retiring the key revokes it, and with
    it (through operator_status) every agent of that operator."""
    bot, agent_id = await onboard(network)
    await bot.retire_key("operator")
    op = network.issuer.store.credential(bot.operator()["credentialId"].removeprefix("urn:uuid:"))
    assert op["revoked"] == 1
    with pytest.raises(Refused, match="no valid Operator Credential"):
        await bot.issue(agent_id)


# -- Veridact-hosted agent metadata ----------------------------------------------------------------


async def test_hosted_metadata_rules(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    hosted = network.issuer.store.hosted_agent(urlsplit(agent["id"]).path)
    assert json.loads(hosted["doc"])["client_id"] == agent["id"]
    # Another account cannot write under this account's slug or take this agent id.
    other = Vbot.create(network.tmp / "other", network.directory, network.routes)
    await other.register()
    key = jose.key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key())
    from veridact_verify.identifiers import client_metadata_document
    async with other.client() as acme:
        squat = client_metadata_document(agent["id"], [key])
        with pytest.raises(Refused, match="client_id"):
            await acme.upload_metadata(agent_id, squat)


async def test_hosted_metadata_key_rotation_retires_the_old_key(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    from veridact_verify.identifiers import client_metadata_document
    new_key = bot.keys.get_or_create(f"agent-{agent_id}-next")
    async with bot.client() as acme:
        await acme.upload_metadata(agent_id, client_metadata_document(agent["id"], [new_key.jwk]))
    issuer = network.issuer
    assert not issuer.key_is_logged(agent["id"], agent["jkt"])
    assert issuer.key_is_logged(agent["id"], new_key.jkt)
    cred = issuer.store.credential(claims(agent["credential"])["jti"].removeprefix("urn:uuid:"))
    assert cred["revoked"] == 1


# -- known-assistant entries -------------------------------------------------------------------------


CLAUDE = {
    "sub": "https://claude.ai/oauth/claude-client-metadata.json",
    "client_metadata_urls": ["https://claude.ai/oauth/claude-client-metadata.json"],
    "operator": {"name": "Anthropic PBC", "jurisdiction": "US", "verified": "2026-11-20"},
    "redirect_hosts": ["claude.ai"],
    "token_endpoint_auth": {"method": "none"},
    "max_level": "approved_payer",
}


async def test_known_assistant_needs_organisation_tier(network: Network):
    with pytest.raises(ValueError, match="Organisation"):
        network.issuer.issue_known_assistant("claude", CLAUDE)


async def test_known_assistant_issue_suspend_restore(tmp_path):
    from veridact_issuer import Issuer, IssuerConfig
    from veridact_verify import RelyingPartyPolicy, StaticFetcher, Verifier
    from veridact_verify.identifiers import issuer_metadata_url
    config = IssuerConfig(base_url="https://issuer.veridact.test", data_dir=str(tmp_path),
                          tiers=("domain", "organisation"))
    issuer = Issuer(config)
    token = issuer.issue_known_assistant("claude", CLAUDE)
    with pytest.raises(ValueError, match="unknown"):
        issuer.issue_known_assistant("x", {**CLAUDE, "tier": "organisation"})
    row = issuer.store.assistant("claude")
    files = {config.trust_list_url: issuer.trust.signed(issuer.now()),  # type: ignore[union-attr]
             issuer_metadata_url(issuer.identity.id): json.dumps(issuer.identity.metadata())}

    async def check():
        files[row["status_list"]] = issuer.status.signed(row["status_list"], issuer.now())
        verifier = Verifier(RelyingPartyPolicy(audience="https://bank.example"),
                            governance_keys=issuer.identity.governance_jwks, fetcher=StaticFetcher(files),
                            trust_list_url=config.trust_list_url)
        return await verifier.verify_known_assistant(token, client_id=CLAUDE["sub"])

    d = await check()
    assert d.allowed, d.log_record()
    assert d.operator == "Anthropic PBC"
    issuer.set_assistant_status("claude", tsl.SUSPENDED)
    assert (await check()).reason.value == "STATUS_SUSPENDED"
    issuer.set_assistant_status("claude", tsl.VALID)
    assert (await check()).allowed
    issuer.set_assistant_status("claude", tsl.INVALID)
    with pytest.raises(ValueError, match="withdrawn"):
        issuer.set_assistant_status("claude", tsl.VALID)
    issuer.store.close()


# -- publication ------------------------------------------------------------------------------


async def test_published_artefacts(network: Network):
    bot, agent_id = await onboard(network)
    base = network.routes[ISSUER_HOST]
    issuer_id = network.issuer.identity.id
    async with aiohttp.ClientSession() as http:
        async with http.get(f"{base}/log/entries") as r:
            entries = [e["entry"] for e in (await r.json())["entries"]]
        assert [e["type"] for e in entries] == [
            "key-event", "https://veridact.net/vct/operator/v1", "key-event", "https://veridact.net/vct/agent/v1"]
        assert entries[1]["domains"] == [OPERATOR_DOMAIN]
        op_cred = claims(bot.operator()["credential"])
        assert op_cred["log_entry"].endswith("/000000002")
        cred_id = bot.agent(agent_id)["credentialId"].removeprefix("urn:uuid:")
        async with http.get(f"{base}/acme/renewal-info/{cred_id}") as r:
            window = (await r.json())["suggestedWindow"]
        assert window["start"] < window["end"]
        async with http.get(f"{base}/trust-list.jwt") as r:
            trust = jose.parse(await r.text())
        assert trust.typ == "trust-list+jwt"
        listed = trust.payload["issuers"][0]
        assert listed["id"] == issuer_id
        assert listed["keys"][0]["jkt"] == network.issuer.identity.jkt
        async with http.get(f"{base}/.well-known/jwt-vc-issuer/issuers/{network.issuer.config.issuer_name}") as r:
            metadata = await r.json()
        assert metadata["issuer"] == issuer_id
        assert jose.jwk_thumbprint(metadata["jwks"]["keys"][0]) == listed["keys"][0]["jkt"]
        status_url = claims(bot.agent(agent_id)["credential"])["status"]["status_list"]["uri"]
        async with http.get(base + status_url.split(ISSUER_HOST, 1)[1]) as r:
            assert r.content_type == "application/statuslist+jwt"
            status = jose.parse(await r.text())
        assert status.typ == "statuslist+jwt"
        assert status.payload["sub"] == status_url
        assert status.payload["status_list"]["bits"] == 2
        assert status.payload["exp"] - status.payload["iat"] <= 4 * 3600


async def test_status_lists_resign_when_stale(network: Network):
    now = [time.time()]
    issuer = network.issuer
    url, _ = issuer.status.allocate("agents")
    first = issuer.status.signed(url, int(now[0]))
    assert issuer.status.signed(url, int(now[0]) + 60) == first
    later = issuer.status.signed(url, int(now[0]) + 300)
    assert later != first and claims(later)["iat"] == int(now[0]) + 300
