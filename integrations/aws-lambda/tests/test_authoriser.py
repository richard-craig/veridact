"""The authoriser against a mock Veridact network and a moto DynamoDB table."""

from __future__ import annotations

import json
import threading

import boto3
import pytest
from moto import mock_aws
from veridact_sidecar import VerifierConfig
from veridact_verify.testing import NOW, MockNetwork
from veridact_verify.testing.mock_network import AUDIENCE, TRUST_LIST_URL

from veridact_lambda import Authoriser, DynamoNonceStore, Routes
import importlib

handler_module = importlib.import_module("veridact_lambda.handler")

ARN = "arn:aws:execute-api:af-south-1:123456789012:abc123/prod/GET/claims/CLM-1/status"
TABLE = "veridact-nonces"
ROUTES = {
    "GET /claims/{id}/status": {"scopes": ["fs:claims:read-status"], "risk": "low"},
    "POST /payments": {"scopes": ["fs:payments:initiate"], "risk": "high"},
}


@pytest.fixture
def dynamo():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="af-south-1")
        client.create_table(TableName=TABLE, BillingMode="PAY_PER_REQUEST",
                            KeySchema=[{"AttributeName": "nonce", "KeyType": "HASH"}],
                            AttributeDefinitions=[{"AttributeName": "nonce", "AttributeType": "S"}])
        yield client


@pytest.fixture
def net():
    return MockNetwork()


def make(net: MockNetwork, dynamo, **kw) -> Authoriser:
    config = VerifierConfig(audience=AUDIENCE, governance_keys=net.governance_keys,
                            trust_list_url=TRUST_LIST_URL, min_tier="domain")
    nonces = DynamoNonceStore(TABLE, client=dynamo, clock=lambda: NOW)
    return Authoriser(config, Routes(kw.pop("routes", ROUTES)), realm="claims-api",
                      verifier=config.build(fetcher=net.fetcher, nonces=nonces, clock=lambda: NOW))


def event(method="GET", resource="/claims/{id}/status", auth: str | None = None) -> dict:
    headers = {"Host": "api.bank.example"}
    if auth is not None:
        headers["Authorization"] = auth
    return {"type": "REQUEST", "methodArn": ARN, "httpMethod": method, "resource": resource,
            "headers": headers, "requestContext": {"apiId": "abc123"}}


def nonce_of(result: dict) -> str:
    header = result["context"]["wwwAuthenticate"]
    return header.split('nonce="', 1)[1].split('"', 1)[0]


def effect(result: dict) -> str:
    return result["policyDocument"]["Statement"][0]["Effect"]


def test_no_presentation_gets_a_challenge(net, dynamo):
    result = make(net, dynamo)(event())
    assert effect(result) == "Deny"
    assert result["context"]["decision"] == "challenge"
    assert result["context"]["code"] == "CHALLENGE_REQUIRED"
    assert result["context"]["wwwAuthenticate"].startswith('Veridact realm="claims-api", nonce="')
    assert 'scope="fs:claims:read-status"' in result["context"]["wwwAuthenticate"]
    stored = dynamo.get_item(TableName=TABLE, Key={"nonce": {"S": nonce_of(result)}})
    assert "Item" in stored


def test_valid_presentation_is_allowed_once(net, dynamo):
    auth = make(net, dynamo)
    nonce = nonce_of(auth(event()))
    header = f'Veridact sd-jwt="{net.presentation(nonce)}"'
    allowed = auth(event(auth=header))
    assert effect(allowed) == "Allow", allowed
    assert allowed["principalId"] == net.agent.id
    ctx = allowed["context"]
    assert ctx["veridactOperator"] == net.operator.id
    assert ctx["veridactScopes"] == "fs:claims:read-status"
    assert ctx["veridactAgentKeyId"] == net.agent.jkt
    assert all(isinstance(v, (str, int, float, bool)) for v in ctx.values())
    # The same presentation again: the nonce was consumed in DynamoDB.
    replay = auth(event(auth=header))
    assert effect(replay) == "Deny"
    assert replay["context"]["code"] == "CHALLENGE_REQUIRED"
    assert replay["context"]["wwwAuthenticate"]  # a fresh challenge to retry with


def test_nonce_from_one_instance_works_on_another(net, dynamo):
    first, second = make(net, dynamo), make(net, dynamo)
    nonce = nonce_of(first(event()))
    assert effect(second(event(auth=f'Veridact sd-jwt="{net.presentation(nonce)}"'))) == "Allow"


def test_scope_not_held_is_denied_without_a_challenge(net, dynamo):
    auth = make(net, dynamo)
    nonce = nonce_of(auth(event("POST", "/payments")))
    result = auth(event("POST", "/payments", auth=f'Veridact sd-jwt="{net.presentation(nonce)}"'))
    assert effect(result) == "Deny"
    assert result["context"] == {"decision": "deny", "code": "SCOPE_NOT_HELD", "wwwAuthenticate": ""}


def test_unconfigured_route_fails_closed(net, dynamo):
    result = make(net, dynamo)(event("DELETE", "/claims/{id}"))
    assert effect(result) == "Deny"
    assert result["context"]["code"] == "AUTH_FAILED"


def test_tampered_presentation_is_auth_failed(net, dynamo):
    auth = make(net, dynamo)
    nonce = nonce_of(auth(event()))
    vp = net.presentation(nonce)
    result = auth(event(auth=f'Veridact sd-jwt="{vp[:-4]}AAAA"'))
    assert effect(result) == "Deny"
    assert result["context"]["code"] == "AUTH_FAILED"


def test_parallel_replays_consume_once(net, dynamo):
    store = DynamoNonceStore(TABLE, client=dynamo, clock=lambda: NOW)
    nonce = store.issue()
    results = []
    threads = [threading.Thread(target=lambda: results.append(store.consume(nonce))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_expired_and_malformed_nonces(net, dynamo):
    clock = [NOW]
    store = DynamoNonceStore(TABLE, client=dynamo, ttl=120, clock=lambda: clock[0])
    nonce = store.issue()
    clock[0] += 121
    assert not store.is_live(nonce)
    assert not store.consume(nonce)
    assert not store.is_live("../../etc") and not store.consume("x" * 32)


def test_route_config_rejects_bad_keys():
    with pytest.raises(ValueError):
        Routes({"claims": {"scopes": []}})


def test_handler_from_environment(net, dynamo, monkeypatch):
    monkeypatch.setenv("VERIDACT_CONFIG_JSON", json.dumps({
        "audience": AUDIENCE, "governance_keys": net.governance_keys, "trust_list_url": TRUST_LIST_URL}))
    monkeypatch.setenv("VERIDACT_ROUTES", json.dumps(ROUTES))
    monkeypatch.setenv("VERIDACT_NONCE_TABLE", TABLE)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "af-south-1")
    monkeypatch.setattr(handler_module, "_authoriser", None)
    result = handler_module.handler(event())
    assert result["context"]["code"] == "CHALLENGE_REQUIRED"
    assert 'realm="abc123"' in result["context"]["wwwAuthenticate"]
    assert handler_module._authoriser is not None
    monkeypatch.setattr(handler_module, "_authoriser", None)
