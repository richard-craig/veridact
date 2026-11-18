"""RoutedFetcher (development routes) and shared did:webvh provisioning."""

from __future__ import annotations

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify import RoutedFetcher, StaticFetcher, provision
from veridact_verify.did import WebvhResolver
from veridact_verify.fetch import ArtefactCache, FetchError, parse_routes, route_url


def test_parse_and_route():
    routes = parse_routes(["staging.veridact.test=http://issuer:8080/"])
    assert routes == {"staging.veridact.test": "http://issuer:8080"}
    assert route_url("https://staging.veridact.test/status/agents/1?x=1", routes) == \
        "http://issuer:8080/status/agents/1?x=1"
    assert route_url("https://other.example/a", routes) == "https://other.example/a"
    with pytest.raises(ValueError):
        parse_routes(["no-equals-sign"])
    with pytest.raises(ValueError):
        parse_routes({"h.test": "ftp://x"})


async def test_routed_fetcher_serves_canonical_https_from_route():
    async def hello(request: web.Request) -> web.Response:
        return web.Response(text="hi")

    app = web.Application()
    app.router.add_get("/hello", hello)
    server = TestServer(app)
    await server.start_server()
    fetcher = RoutedFetcher({"api.veridact.test": str(server.make_url("")).rstrip("/")})
    try:
        assert await fetcher.fetch("https://api.veridact.test/hello") == b"hi"
        with pytest.raises(FetchError, match="only https"):
            await fetcher.fetch("http://api.veridact.test/hello")
        with pytest.raises(FetchError):  # no route: goes to the real network, https only
            await fetcher.fetch("https://unrouted.invalid/x")
    finally:
        await fetcher.close()
        await server.close()


async def test_provisioned_did_resolves_with_pre_rotation():
    key = ec.generate_private_key(ec.SECP256R1())
    update, nxt = provision.new_update_key(), provision.new_update_key()
    made = provision.provision("operator.example:agents:a1b2c3", {"key-1": key.public_key()},
                               {"authentication": ["key-1"]}, update, next_update_key=nxt)
    assert made.log_url == "https://operator.example/agents/a1b2c3/did.jsonl"
    resolved = await WebvhResolver(StaticFetcher({made.log_url: made.log}), ArtefactCache()).resolve(made.did)
    assert resolved.key_for(f"{made.did}#key-1", "authentication").public_numbers() == \
        key.public_key().public_numbers()
    params = __import__("json").loads(made.log.splitlines()[0])["parameters"]
    assert params["nextKeyHashes"] == [provision.next_key_hash(nxt)]
    assert provision.update_key_from_jwk(provision.update_key_to_jwk(update)).multikey == update.multikey


def test_provision_rejects_unknown_relationship_keys():
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError):
        provision.provision("operator.example", {"key-1": key.public_key()},
                            {"assertionMethod": ["key-2"]}, provision.new_update_key())
