"""The ten-minute developer path: vbot against the sandbox relying party, and the sidecar."""

from __future__ import annotations

import aiohttp
from vbot import Vbot, call

from conftest import Network
from test_issuance import onboard


async def test_vbot_call_walks_the_challenge(network: Network):
    sandbox = await network.start_sandbox()
    bot, agent_id = await onboard(network)

    # Allowed: the scope is delegated.
    result = await call(bot, f"{sandbox}/claims/CLM-1001/status", agent_id=agent_id)
    assert result.status == 200, result.body
    assert result.challenge and result.challenge["scope"] == "fs:claims:read-status"
    body = result.json()
    assert body["decision"] == "allow"
    assert body["data"]["status"] == "approved"
    assert body["explain"]["operatorDomains"] == ["operator.veridact.test"]

    # Not delegated: payments.
    result = await call(bot, f"{sandbox}/payments", agent_id=agent_id, method="POST",
                        json_body={"amount": "100.00", "currency": "ZAR"})
    assert result.status == 403
    assert result.json()["code"] == "SCOPE_NOT_HELD"
    assert "vbot delegate" in result.json()["hint"]


async def test_payment_limits_and_ask_person(network: Network):
    sandbox = await network.start_sandbox()
    bot, agent_id = await onboard(network)
    bot.delegate(agent_id, ["fs:payments:initiate"], role="Claims Payments Lead",
                 limits={"currency": "ZAR", "perPayment": "500.00", "perDay": "800.00"})
    await bot.issue(agent_id)

    async def pay(amount: str):
        return await call(bot, f"{sandbox}/payments", agent_id=agent_id, method="POST",
                          json_body={"amount": amount, "currency": "ZAR", "claim": "CLM-1001"})

    ok = await pay("450.00")
    assert ok.status == 201, ok.body
    assert ok.json()["data"]["spentToday"] == "450.00"

    over_one = await pay("600.00")
    assert over_one.status == 403
    assert over_one.json()["decision"] == "ask_person"
    assert over_one.json()["code"] == "LIMIT_PER_PAYMENT"
    assert over_one.json()["intent"]["amount"] == "600.00"

    over_day = await pay("400.00")  # 450 + 400 > 800
    assert over_day.json()["code"] == "LIMIT_PER_DAY"


async def test_revocation_takes_effect(network: Network):
    sandbox = await network.start_sandbox()
    bot, agent_id = await onboard(network)
    url = f"{sandbox}/claims/CLM-1002/status"
    assert (await call(bot, url, agent_id=agent_id)).status == 200

    await bot.revoke(agent_id, "key compromise drill")
    denied = await call(bot, url, agent_id=agent_id)
    assert denied.status == 401
    body = denied.json()
    assert body["code"] == "AUTH_FAILED"  # revocation is deliberately not disclosed
    assert body["explain"]["reason"] == "STATUS_REVOKED"

    # A fresh credential works again: the agent was revoked, not the operator.
    await bot.issue(agent_id)
    assert (await call(bot, url, agent_id=agent_id)).status == 200


async def test_revoking_the_operator_stops_every_agent(network: Network):
    sandbox = await network.start_sandbox()
    bot, agent_id = await onboard(network)
    await bot.revoke("operator", "offboarded")
    denied = await call(bot, f"{sandbox}/claims/CLM-1001/status", agent_id=agent_id)
    assert denied.json()["explain"]["reason"] == "STATUS_REVOKED"
    # And the issuer refuses new agent credentials under it.
    import pytest
    from vbot import AcmeError
    with pytest.raises(AcmeError, match="Operator Credential"):
        await bot.issue(agent_id)


async def test_sidecar_challenge_and_verify(network: Network):
    audience = "https://api.bank.veridact.test"
    sidecar = await network.start_sidecar(audience, token="s3cret")
    bot, agent_id = await onboard(network)
    auth = {"Authorization": "Bearer s3cret"}
    async with aiohttp.ClientSession() as http:
        async with http.post(f"{sidecar}/v1/challenge", json={"scopes": ["fs:quotes:create"]}) as r:
            assert r.status == 401  # token required
        async with http.post(f"{sidecar}/v1/challenge", headers=auth,
                             json={"scopes": ["fs:quotes:create"], "realm": "quotes"}) as r:
            challenge = await r.json()
        assert challenge["wwwAuthenticate"].startswith('Veridact realm="quotes"')
        header = bot.authorization(agent_id, aud=audience, nonce=challenge["nonce"])
        async with http.post(f"{sidecar}/v1/verify", headers=auth,
                             json={"authorization": header, "scopes": ["fs:quotes:create"]}) as r:
            decision = await r.json()
        assert decision["decision"] == "allow", decision
        assert decision["public"] == {"decision": "allow"}
        assert decision["scopesGranted"] == ["fs:quotes:create"]
        assert decision["agentKeyId"] == bot.agent(agent_id)["kid"]

        # Replaying the same presentation fails: the nonce is single use.
        async with http.post(f"{sidecar}/v1/verify", headers=auth,
                             json={"authorization": header}) as r:
            replay = await r.json()
        assert replay["public"] == {"decision": "challenge", "code": "CHALLENGE_REQUIRED"}
        assert "log" in replay  # for the relying party's own logs, never the caller


async def test_cli_end_to_end(network: Network, capsys):
    """The commands a developer types, in order."""
    from vbot.cli import run
    sandbox = await network.start_sandbox()
    home = str(network.vbot_home)
    routes = sum((["--route", f"{h}={u}"] for h, u in network.routes.items()), [])

    async def vbot(*args: str) -> int:
        # vbot's main() calls asyncio.run, which cannot nest inside this test's loop,
        # so parse with main's own parser and await the command directly.
        return await run(_parse(["--home", home, *args]))

    assert await vbot("init", "--issuer", network.directory, "--domain", "operator.veridact.test",
                      *routes) == 0
    assert await vbot("operator") == 0
    assert await vbot("agent", "new") == 0
    assert await vbot("delegate", "--scope", "fs:claims:read-status", "--role", "Claims Ops") == 0
    assert await vbot("issue") == 0
    assert await vbot("call", f"{sandbox}/claims/CLM-1003/status") == 0
    out = capsys.readouterr().out
    assert "awaiting_documents" in out
    assert await vbot("run", "--once") == 0
    status = Vbot.load(home).status()
    assert list(status["agents"].values())[0]["scopes"] == ["fs:claims:read-status"]


def _parse(argv: list[str]):
    """Run vbot.cli's argument parser without executing the command."""
    from unittest import mock
    from vbot import cli
    captured = {}
    with mock.patch.object(cli.asyncio, "run", lambda coro: captured.setdefault("c", coro) and 0):
        cli.main(argv)
    coro = captured["c"]
    args = coro.cr_frame.f_locals["args"]
    coro.close()
    return args
