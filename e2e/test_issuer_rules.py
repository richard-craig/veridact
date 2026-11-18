"""What the issuer refuses. Each test is one way to get a credential you should not have."""

from __future__ import annotations

import json
import time

import aiohttp
import pytest
from vbot import AcmeClient, AcmeError, Vbot, VbotError
from vbot.keys import SoftwareKey
from veridact_verify import jose, provision
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ISSUER_HOST, OPERATOR_DOMAIN, Network
from test_issuance import onboard


Refused = (AcmeError, VbotError)


def claims(jwt: str) -> dict:
    return jose.parse(jwt).payload


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
    assert claims(op["credential"])["credentialSubject"]["domains"] == [OPERATOR_DOMAIN]


async def test_dns01_wrong_record(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)

    async def publish(name: str, value: str) -> None:
        network.txt.records[name] = ["not-the-value"]

    with pytest.raises(Refused, match="incorrectResponse|TXT"):
        await bot.obtain_operator_credential(challenge="dns-01", before_respond=publish)


async def test_did_config_must_name_a_did_at_this_domain(network: Network, tmp_path):
    """A domain cannot vouch for a DID hosted somewhere else."""
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)
    # Swap in a linkage signed by a DID that lives on another domain.
    elsewhere = provision.provision("elsewhere.veridact.test", {"key-1": bot.keys.get("operator").public_key()},
                                    {"assertionMethod": ["key-1"]}, provision.new_update_key())
    cfg = network.vbot_home / "publish/.well-known/did-configuration.json"
    now = int(time.time())
    linkage = bot.keys.get("operator").sign({"kid": f"{elsewhere.did}#key-1"}, {
        "iss": elsewhere.did, "sub": elsewhere.did, "exp": now + 3600,
        "vc": {"type": ["VerifiableCredential", "DomainLinkageCredential"],
               "credentialSubject": {"id": elsewhere.did, "origin": f"https://{OPERATOR_DOMAIN}"}}})
    cfg.write_text(json.dumps({"linked_dids": [linkage]}))
    bot.state["operator"]["did"] = elsewhere.did
    with pytest.raises(Refused, match="not an operator DID"):
        await bot.obtain_operator_credential()


async def test_operator_finalize_needs_the_operator_key(network: Network):
    bot = Vbot.create(network.vbot_home, network.directory, network.routes)
    await bot.register()
    bot.create_operator(OPERATOR_DOMAIN)
    bot.keys.dir.joinpath("operator.pem").unlink()  # finalize will sign with a fresh, unlisted key
    bot.keys.get_or_create("operator")
    with pytest.raises(Refused, match="key binding signature|badCSR"):
        await bot.obtain_operator_credential()


# -- agent issuance --------------------------------------------------------------------------


async def test_agent_lifetime_capped_by_delegation(network: Network):
    bot, agent_id = await onboard(network)
    bot.delegate(agent_id, ["fs:claims:read-status"], role="Ops", max_lifetime=1800)
    agent = await bot.issue(agent_id, lifetime=24 * 3600)
    assert agent["exp"] - agent["iat"] == 1800
    cred = claims(agent["credential"])
    assert cred["credentialSubject"]["cnf"]["kid"] == agent["kid"]
    assert cred["credentialSubject"]["operatorCredential"] == bot.operator()["credentialId"]


@pytest.mark.parametrize("change, match", [
    ({"scopes": ["fs:made:up"]}, "scopes not allowed"),
    ({"environment": "production"}, "environment"),
    ({"limits": {"currency": "ZAR", "perPayment": "5000.00", "perDay": "9000.00"}}, "two approvers"),
    ({"limits": {"currency": "ZAR", "perPayment": 500, "perDay": "900.00"}}, "decimal string"),
    ({"accountableRole": ""}, "accountableRole"),
])
async def test_delegation_rules(network: Network, change, match):
    bot, agent_id = await onboard(network)
    op = bot.operator()
    agent = bot.agent(agent_id)
    payload = claims(agent["delegation"])
    payload["credentialSubject"].update(change)
    agent["delegation"] = bot.keys.get("operator").sign({"typ": "vc+jwt", "kid": op["kid"]}, payload)
    with pytest.raises(Refused, match=match):
        await bot.issue(agent_id)


async def test_delegation_over_90_days_refused(network: Network):
    bot, agent_id = await onboard(network)
    op, agent = bot.operator(), bot.agent(agent_id)
    payload = claims(agent["delegation"])
    payload["exp"] = payload["iat"] + 120 * 86400
    agent["delegation"] = bot.keys.get("operator").sign({"typ": "vc+jwt", "kid": op["kid"]}, payload)
    with pytest.raises(Refused, match="90 days"):
        await bot.issue(agent_id)


async def test_delegation_must_come_from_the_operator(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    payload = claims(agent["delegation"])
    # Signed by the agent's own key instead of the operator's.
    agent["delegation"] = bot.keys.get(f"agent-{agent_id}").sign(
        {"typ": "vc+jwt", "kid": bot.operator()["kid"]}, payload)
    with pytest.raises(Refused, match="signature|cannot use"):
        await bot.issue(agent_id)


async def test_delegation_cannot_be_used_by_another_account(network: Network, tmp_path):
    """A leaked delegation is useless to anyone without the operator's account."""
    bot, agent_id = await onboard(network)
    thief_key = SoftwareKey(ec.generate_private_key(ec.SECP256R1()))
    async with AcmeClient(network.directory, thief_key, routes=network.routes) as acme:
        await acme.register()
        with pytest.raises(Refused, match="no valid Operator Credential"):
            await acme.new_order({"type": "agent-did", "value": bot.agent(agent_id)["did"]})


async def test_agent_did_must_live_with_its_operator(network: Network):
    bot, agent_id = await onboard(network)
    stray = provision.provision("elsewhere.veridact.test:agents:a1b2c3",
                                {"key-1": bot.keys.get(f"agent-{agent_id}").public_key()},
                                {"authentication": ["key-1"]}, provision.new_update_key())
    async with bot.client() as acme:
        with pytest.raises(Refused, match="agent DID must be"):
            await acme.new_order({"type": "agent-did", "value": stray.did})


async def test_finalize_key_binding_rules(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    key = bot.keys.get(f"agent-{agent_id}")
    async with bot.client() as acme:
        for bad in ("aud", "nonce", "iat"):
            order_url, order = await acme.new_order({"type": "agent-did", "value": agent["did"]})
            authz = await acme.get(order["authorizations"][0])
            await acme.respond(authz["challenges"][0]["url"], {"delegation": agent["delegation"]})

            def kb(nonce: str, bad=bad, order=order) -> str:
                claims_ = {"iss": agent["did"], "aud": order["finalize"], "nonce": nonce,
                           "iat": int(time.time())}
                claims_[bad] = {"aud": "https://elsewhere", "nonce": "stale", "iat": 1}[bad]
                return key.sign({"typ": "veridact-kb+jwt", "kid": agent["kid"]}, claims_)

            with pytest.raises(Refused, match="badCSR|key binding"):
                await acme.finalize(order, kb)
            assert (await acme.get(order_url))["status"] == "invalid"


# -- hosted DIDs ----------------------------------------------------------------------------


async def test_hosted_did_upload_rules(network: Network):
    bot, agent_id = await onboard(network)
    agent = bot.agent(agent_id)
    async with bot.client() as acme:
        # Rewriting history is refused.
        replacement = provision.provision(agent["did"].split(":", 3)[3],
                                          {"key-1": ec.generate_private_key(ec.SECP256R1()).public_key()},
                                          {"authentication": ["key-1"]}, provision.new_update_key())
        with pytest.raises(AcmeError):
            await acme.upload_did(agent_id, replacement.log)
    # Another account cannot write under this account's slug.
    other = Vbot.create(network.tmp / "other", network.directory, network.routes)
    await other.register()
    path = f"{other.state['hostedDidPrefix']}:{bot.state['slug']}:zz9999"
    squat = provision.provision(path, {"key-1": ec.generate_private_key(ec.SECP256R1()).public_key()},
                                {"authentication": ["key-1"]}, provision.new_update_key())
    async with other.client() as acme:
        with pytest.raises(Refused, match="agent DID must be"):
            await acme.upload_did("zz9999", squat.log)


# -- publication ------------------------------------------------------------------------------


async def test_published_artefacts(network: Network):
    bot, agent_id = await onboard(network)
    base = network.routes[ISSUER_HOST]
    async with aiohttp.ClientSession() as http:
        async with http.get(f"{base}/log/entries") as r:
            entries = (await r.json())["entries"]
        assert [e["entry"]["type"] for e in entries] == ["VeridactOperatorCredential",
                                                          "VeridactAgentCredential"]
        assert entries[0]["entry"]["domains"] == [OPERATOR_DOMAIN]
        op_cred = claims(bot.operator()["credential"])
        assert op_cred["credentialSubject"]["transparencyLogEntry"].endswith("/000000001")
        cred_id = bot.agent(agent_id)["credentialId"].removeprefix("urn:uuid:")
        async with http.get(f"{base}/acme/renewal-info/{cred_id}") as r:
            window = (await r.json())["suggestedWindow"]
        assert window["start"] < window["end"]
        async with http.get(f"{base}/trust-list.jwt") as r:
            trust = jose.parse(await r.text())
        assert trust.typ == "trust-list+jwt"
        assert trust.payload["issuers"][0]["id"] == network.issuer.identity.did
        status_url = claims(bot.agent(agent_id)["credential"])["credentialStatus"]["statusListCredential"]
        async with http.get(base + status_url.split(ISSUER_HOST, 1)[1]) as r:
            status = jose.parse(await r.text()).payload
        assert status["id"] == status_url
        assert status["exp"] - status["iat"] <= 4 * 3600


async def test_status_lists_resign_when_stale(network: Network):
    now = [time.time()]
    issuer = network.issuer
    issuer.status.config  # noqa: B018
    url, _ = issuer.status.allocate("agents")
    first = issuer.status.signed(url, int(now[0]))
    assert issuer.status.signed(url, int(now[0]) + 60) == first
    later = issuer.status.signed(url, int(now[0]) + 300)
    assert later != first and claims(later)["iat"] == int(now[0]) + 300
