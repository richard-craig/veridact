"""vbot obtains credentials from the issuer, and the unmodified reference verifier accepts them."""

from __future__ import annotations

import json

from veridact_verify import RelyingPartyPolicy, Request, Verifier
from veridact_verify.nonce import InMemoryNonceStore
from vbot import Vbot

from conftest import OPERATOR_DOMAIN, Network

AUD = "https://api.bank.veridact.test"
S = frozenset


async def onboard(net: Network, *, hosted: bool = True) -> tuple[Vbot, str]:
    bot = Vbot.create(net.vbot_home, net.directory, net.routes)
    await bot.register(["mailto:ops@operator.veridact.test"])
    bot.create_operator(OPERATOR_DOMAIN)
    await bot.obtain_operator_credential()
    agent = await bot.create_agent(hosted=hosted)
    bot.delegate(agent["id"], ["fs:claims:read-status", "fs:quotes:create"],
                 role="Head of Digital Claims",
                 limits={"currency": "ZAR", "perPayment": "500.00", "perDay": "2000.00"})
    await bot.issue(agent["id"])
    return bot, agent["id"]


def verifier(net: Network, **policy) -> Verifier:
    governance = json.loads(json.dumps(net.issuer.identity.governance_jwks))
    return Verifier(RelyingPartyPolicy(audience=AUD, **policy), governance_keys=governance,
                    fetcher=net.fetcher(), trust_list_url=net.issuer.config.trust_list_url,
                    nonces=InMemoryNonceStore(), status_ttl=0, did_ttl=0)


async def present(bot: Vbot, agent_id: str, v: Verifier, request: Request = Request()):
    nonce = v.nonces.issue()
    try:
        return await v.verify(bot.presentation(agent_id, aud=AUD, nonce=nonce), request)
    finally:
        await v.fetcher.close()


async def test_hosted_agent_verifies(network: Network):
    bot, agent_id = await onboard(network, hosted=True)
    decision = await present(bot, agent_id, verifier(network),
                             Request(scopes=S({"fs:claims:read-status"})))
    assert decision.allowed, decision.log_record()
    assert decision.operator == bot.operator()["did"]
    assert decision.operator_domains == [OPERATOR_DOMAIN]
    assert decision.tier == "domain"
    assert decision.scopes_granted == ["fs:claims:read-status"]
    assert decision.accountable_role == "Head of Digital Claims"


async def test_agent_on_operator_domain_verifies(network: Network):
    bot, agent_id = await onboard(network, hosted=False)
    assert ":operator.veridact.test:agents:" in bot.agent(agent_id)["did"]
    decision = await present(bot, agent_id, verifier(network))
    assert decision.allowed, decision.log_record()
