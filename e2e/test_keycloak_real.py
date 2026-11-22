"""Pattern A against a real Keycloak (26.6+). Runs when KEYCLOAK_URL is set, as in CI:

    docker run -d --network host -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \\
        -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.6 start-dev
    KEYCLOAK_URL=http://127.0.0.1:8080 pytest e2e/test_keycloak_real.py
"""

from __future__ import annotations

import json
import os
import uuid

import pytest
from veridact_bridge import Bridge, BridgeConfig, KeycloakConfig, agent_username, create_app
from veridact_bridge.setup_realm import configure
from veridact_verify import jose
from vbot import exchange

from conftest import Network
from fake_keycloak import thumbprint
from test_issuance import onboard

KEYCLOAK = os.environ.get("KEYCLOAK_URL")
pytestmark = pytest.mark.skipif(not KEYCLOAK, reason="set KEYCLOAK_URL to run against a real Keycloak")
BRIDGE = "https://bridge.veridact.test"


@pytest.fixture
async def real_kc(network: Network):
    realm = "veridact-" + uuid.uuid4().hex[:8]
    # The bridge must be reachable from Keycloak for its JWKS: start it before configuring the realm.
    holder: dict = {}

    async def late_jwks(request):
        from aiohttp import web
        return web.json_response({"keys": [holder["bridge"].jwk]})

    from aiohttp import web
    from aiohttp.test_utils import TestServer
    jwks_app = web.Application()
    jwks_app.router.add_get("/jwks.json", late_jwks)
    jwks_server = TestServer(jwks_app, host="127.0.0.1")
    await jwks_server.start_server()
    network.servers.append(jwks_server)

    kc_block = await configure(keycloak=KEYCLOAK, realm=realm, admin_user="admin",
                               admin_password=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
                               bridge_issuer=BRIDGE, jwks_url=str(jwks_server.make_url("/jwks.json")),
                               ssl_required="none")
    config = BridgeConfig(base_url=BRIDGE, verifier=network.rp_config(BRIDGE),
                          data_dir=str(network.tmp / "bridge"), keycloak=KeycloakConfig(**kc_block))
    holder["bridge"] = bridge = Bridge(config)
    await network.serve("bridge.veridact.test", create_app(bridge))
    yield network, bridge


async def test_real_keycloak_issues_a_dpop_bound_token(real_kc):
    network, bridge = real_kc
    bot, agent_id = await onboard(network)
    result = await exchange(bot, BRIDGE, agent_id=agent_id, scopes=["fs:claims:read-status"])
    assert result.status == 200, result.body
    assert result.body["token_type"].lower() == "dpop"
    access = json.loads(jose.b64url_decode(result.access_token.split(".")[1]))
    agent_jwk = jose.key_to_jwk(bot.keys.get(f"agent-{agent_id}").public_key())
    assert access["cnf"]["jkt"] == thumbprint(agent_jwk)
    assert "fs:claims:read-status" in access["scope"].split()
    assert access["preferred_username"] == agent_username(bot.agent(agent_id)["id"])

    # A second exchange reuses the provisioned user; Keycloak refuses replayed assertions on its own.
    again = await exchange(bot, BRIDGE, agent_id=agent_id)
    assert again.status == 200, again.body
