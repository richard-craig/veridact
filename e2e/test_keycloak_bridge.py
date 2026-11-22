"""Pattern A with Keycloak: vbot trades a presentation for a DPoP-bound Keycloak access token."""

from __future__ import annotations

import json

import aiohttp
import pytest
from aiohttp.test_utils import TestServer
from veridact_bridge import Bridge, BridgeConfig, KeycloakConfig, agent_username, create_app
from veridact_verify import jose
from vbot import Vbot, dpop_proof, exchange

from conftest import Network
from fake_keycloak import FakeKeycloak, thumbprint
from test_issuance import onboard

BRIDGE = "https://bridge.veridact.test"


@pytest.fixture
async def kc_net(network: Network):
    kc = FakeKeycloak(realm="bank", idp_alias="veridact", idp_issuer=BRIDGE,
                      idp_jwks_url=f"{BRIDGE}/.well-known/jwks.json", fetcher=network.fetcher())
    kc_server = TestServer(kc.app())
    await kc_server.start_server()
    network.servers.append(kc_server)
    kc.base = str(kc_server.make_url("")).rstrip("/")
    config = BridgeConfig(
        base_url=BRIDGE, verifier=network.rp_config(BRIDGE), data_dir=str(network.tmp / "bridge"),
        keycloak=KeycloakConfig(url=kc.base, realm="bank", client_id="veridact-bridge",
                                client_secret="bridge-secret", admin_client_id="veridact-admin",
                                admin_client_secret="admin-secret"))
    bridge = Bridge(config)
    await network.serve("bridge.veridact.test", create_app(bridge))
    kc.fetcher.routes = network.routes  # include the bridge, which started after the fetcher
    yield network, kc, bridge
    await kc.fetcher.close()


def claims(token: str) -> dict:
    return json.loads(jose.b64url_decode(token.split(".")[1]))


async def test_presentation_for_a_dpop_bound_keycloak_token(kc_net):
    network, kc, bridge = kc_net
    bot, agent_id = await onboard(network)
    result = await exchange(bot, BRIDGE, agent_id=agent_id, scopes=["fs:claims:read-status"])
    assert result.status == 200, result.body
    assert result.body["token_type"] == "DPoP"
    assert result.body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    access = claims(result.access_token)
    agent_jwk = jose.key_to_jwk(bot.keys.get(f"agent-{agent_id}").public_key())
    assert access["cnf"]["jkt"] == thumbprint(agent_jwk)  # bound to the agent's Veridact key
    assert access["scope"] == "fs:claims:read-status"
    agent_did = bot.agent(agent_id)["id"]
    (user,) = kc.users.values()
    assert user["username"] == agent_username(agent_did) == access["preferred_username"]
    assert user["links"] == {"veridact": agent_did}
    assert user["attributes"]["veridactOperatorDomains"] == ["operator.veridact.test"]

    # Again: same user, no duplicate, all held scopes when none are asked for.
    again = await exchange(bot, BRIDGE, agent_id=agent_id)
    assert again.status == 200, again.body
    assert len(kc.users) == 1
    assert set(claims(again.access_token)["scope"].split()) == {"fs:claims:read-status", "fs:quotes:create"}


async def _raw_exchange(network, bot, agent_id, *, scope=None, dpop="agent", replay_vp=None):
    base = network.routes["bridge.veridact.test"]
    async with aiohttp.ClientSession() as http:
        async with http.get(f"{base}/.well-known/veridact-bridge") as r:
            meta = await r.json()
        form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"}
        if scope:
            form["scope"] = scope
        async with http.post(f"{base}/token", data=form) as r:
            assert r.status == 400 and (await r.json())["error"] == "use_veridact_nonce"
            nonce = r.headers["Veridact-Nonce"]
        vp = replay_vp or bot.presentation(agent_id, aud=BRIDGE, nonce=nonce)
        form.update(subject_token=vp, subject_token_type="urn:veridact:params:oauth:token-type:sd-jwt-kb")
        headers = {}
        if dpop == "agent":
            headers["DPoP"] = dpop_proof(bot, agent_id, method="POST", url=meta["dpop_htu"])
        elif dpop is not None:
            headers["DPoP"] = dpop
        async with http.post(f"{base}/token", data=form, headers=headers) as r:
            return r.status, await r.json(), vp


async def test_dpop_is_required_and_must_use_the_agent_key(kc_net):
    network, kc, _ = kc_net
    bot, agent_id = await onboard(network)
    status, body, _ = await _raw_exchange(network, bot, agent_id, dpop=None)
    assert (status, body["error"]) == (400, "invalid_dpop_proof")

    other = await bot.create_agent()  # a real Veridact key, but not this agent's
    stranger = dpop_proof(bot, other["id"], method="POST", url=f"{kc.token_endpoint}")
    assert other["jkt"] != bot.agent(agent_id)["jkt"]
    status, body, _ = await _raw_exchange(network, bot, agent_id, dpop=stranger)
    assert (status, body["error"]) == (400, "invalid_dpop_proof")
    assert "not the agent's Veridact key" in body["error_description"]
    assert not kc.users  # nothing provisioned for a refused exchange


async def test_refusals_map_to_oauth_errors(kc_net):
    network, kc, _ = kc_net
    bot, agent_id = await onboard(network)
    status, body, _ = await _raw_exchange(network, bot, agent_id, scope="fs:payments:initiate")
    assert (status, body) == (400, {"error": "invalid_scope", "error_description": "SCOPE_NOT_HELD"})

    status, body, vp = await _raw_exchange(network, bot, agent_id)
    assert status == 200
    # The same presentation again: its nonce is spent, so the bridge offers a fresh one.
    status, body, _ = await _raw_exchange(network, bot, agent_id, replay_vp=vp)
    assert body["error"] == "use_veridact_nonce"

    await bot.revoke(agent_id)
    status, body, _ = await _raw_exchange(network, bot, agent_id)
    assert (status, body) == (400, {"error": "invalid_grant", "error_description": "AUTH_FAILED"})


async def test_pattern_c_client_attestation(kc_net):
    """attest_jwt_client_auth_dpop: the Client Attestation names the client, the DPoP proof proves the key."""
    network, kc, _ = kc_net
    bot, agent_id = await onboard(network)
    agent = await bot.issue(agent_id, attestation=True)
    base = network.routes["bridge.veridact.test"]
    async with aiohttp.ClientSession() as http:
        async with http.get(f"{base}/.well-known/veridact-bridge") as r:
            meta = await r.json()
        assert "attest_jwt_client_auth_dpop" in meta["token_endpoint_auth_methods_supported"]

        async def token(client_id: str, attestation: str, dpop_agent: str = agent_id):
            headers = {"OAuth-Client-Attestation": attestation,
                       "DPoP": dpop_proof(bot, dpop_agent, method="POST", url=meta["dpop_htu"])}
            form = {"grant_type": "client_credentials", "client_id": client_id, "scope": "fs:quotes:create"}
            async with http.post(f"{base}/token", data=form, headers=headers) as r:
                return r.status, await r.json()

        status, body = await token(agent["id"], agent["attestation"])
        assert status == 200, body
        access = claims(body["access_token"])
        assert access["scope"] == "fs:quotes:create"
        assert access["cnf"]["jkt"] == agent["jkt"]
        status, body = await token(agent["id"] + "x", agent["attestation"])
        assert (status, body["error"]) == (400, "invalid_grant")
        other = await bot.create_agent()
        status, body = await token(agent["id"], agent["attestation"], dpop_agent=other["id"])
        assert (status, body["error"]) == (400, "invalid_grant")


async def test_keycloak_trusts_only_the_bridge_key(kc_net, tmp_path):
    """An assertion signed by any other key is refused by Keycloak, not just by the bridge."""
    network, kc, bridge = kc_net
    bot, agent_id = await onboard(network)
    assert (await exchange(bot, BRIDGE, agent_id=agent_id)).status == 200
    from cryptography.hazmat.primitives.asymmetric import ec
    bridge.key = ec.generate_private_key(ec.SECP256R1())  # not the key in the published JWKS
    result = await exchange(bot, BRIDGE, agent_id=agent_id)
    assert result.status == 400
    assert result.body["error_description"] == "Invalid signature"


async def test_metadata_and_jwks(kc_net):
    network, kc, bridge = kc_net
    base = network.routes["bridge.veridact.test"]
    async with aiohttp.ClientSession() as http:
        async with http.get(f"{base}/.well-known/veridact-bridge") as r:
            meta = await r.json()
        async with http.get(f"{base}/.well-known/jwks.json") as r:
            jwks = await r.json()
    assert meta["token_endpoint"] == f"{BRIDGE}/token"
    assert meta["dpop_htu"] == kc.token_endpoint
    assert jwks["keys"][0]["kid"] == bridge.kid and "d" not in jwks["keys"][0]


async def test_cli_token(kc_net, capsys):
    network, kc, _ = kc_net
    bot, agent_id = await onboard(network)
    from test_sandbox import _parse
    from vbot.cli import run
    code = await run(_parse(["--home", str(network.vbot_home), "token", BRIDGE,
                             "--scope", "fs:quotes:create"]))
    assert code == 0
    assert '"token_type": "DPoP"' in capsys.readouterr().out
    assert Vbot.load(network.vbot_home).agent(agent_id)
