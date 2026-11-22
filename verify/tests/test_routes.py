"""RoutedFetcher (development routes) and the HTTPS identifier helpers."""

from __future__ import annotations

import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric import ec

from veridact_verify import RoutedFetcher, jose
from veridact_verify.fetch import FetchError, parse_routes, route_url
from veridact_verify.identifiers import (
    IdentifierError,
    check_https_url,
    client_metadata_document,
    issuer_metadata_url,
    operator_metadata_document,
    parse_client_metadata,
    parse_operator_metadata,
)


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
        return web.Response(text=request.path)

    app = web.Application()
    app.router.add_get("/{tail:.*}", hello)
    server = TestServer(app)
    await server.start_server()
    try:
        fetcher = RoutedFetcher({"staging.veridact.test": str(server.make_url("")).rstrip("/")})
        assert await fetcher.fetch("https://staging.veridact.test/a/b") == b"/a/b"
        with pytest.raises(FetchError):
            await fetcher.fetch("http://staging.veridact.test/a")
        await fetcher.close()
    finally:
        await server.close()


def test_issuer_metadata_url_puts_well_known_before_the_path():
    assert issuer_metadata_url("https://veridact.net/issuers/org-2026b") == \
        "https://veridact.net/.well-known/jwt-vc-issuer/issuers/org-2026b"
    assert issuer_metadata_url("https://issuer.example") == "https://issuer.example/.well-known/jwt-vc-issuer"


@pytest.mark.parametrize("url", ["http://a.example", "https://A.example", "https://a.example/x?q=1",
                                 "https://u@a.example", "https://a.example/x/", "did:web:a.example"])
def test_identifiers_are_plain_https(url):
    with pytest.raises(IdentifierError):
        check_https_url(url)


def test_client_metadata_document():
    key = jose.key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key())
    url = "https://operator.example/agents/a1"
    doc = client_metadata_document(url, [key], name="Claims agent")
    assert doc["client_id"] == url
    assert "attest_jwt_client_auth_dpop" in doc["token_endpoint_auth_methods_supported"]
    keys = parse_client_metadata(url, json.dumps(doc).encode())
    assert list(keys) == [jose.jwk_thumbprint(key)]
    with pytest.raises(IdentifierError):
        parse_client_metadata(url + "x", json.dumps(doc).encode())


def test_operator_metadata_document():
    key = jose.key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key())
    doc = operator_metadata_document("https://operator.example", [key])
    assert list(parse_operator_metadata("https://operator.example", json.dumps(doc).encode())) == \
        [jose.jwk_thumbprint(key)]
    with pytest.raises(IdentifierError):
        parse_operator_metadata("https://other.example", json.dumps(doc).encode())
