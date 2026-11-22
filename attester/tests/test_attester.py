"""The known-assistant attester: entries verify, the status list says what the admin set, and the admin is guarded."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from veridact_verify import jose

from veridact_attester import sdjwt
from veridact_attester.app import LIST_PATH, VCT, Config, create_app

SECRET = "admin-secret-for-tests"


@pytest.fixture
async def client(aiohttp_client, tmp_path):
    app = create_app(Config(issuer="https://veridact.test", data_dir=tmp_path, admin_secret=SECRET, ttl=10))
    return await aiohttp_client(app)


async def _keys(client) -> dict:
    meta = await (await client.get("/.well-known/jwt-vc-issuer")).json()
    assert meta["issuer"] == "https://veridact.test"
    return {k["kid"]: jose.key_from_jwk({x: k[x] for x in ("kty", "crv", "x", "y")}) for k in meta["jwks"]["keys"]}


async def _status(client, keys) -> dict:
    token = await (await client.get(LIST_PATH)).text()
    jws = jose.parse(token)
    assert jws.typ == "statuslist+jwt"
    jose.verify(jws, keys[jws.kid])
    assert jws.payload["sub"] == "https://veridact.test" + LIST_PATH and jws.payload["ttl"] == 10
    return jws.payload["status_list"]


async def test_the_claude_entry_is_an_sd_jwt_vc_signed_by_the_published_key(client):
    keys = await _keys(client)
    raw = await (await client.get("/known-assistants/claude")).text()
    issuer_jwt, *rest = raw.split("~")
    assert rest == [""]                                   # no disclosures, no key binding JWT
    jws = jose.parse(issuer_jwt)
    assert jws.typ == "dc+sd-jwt"
    jose.verify(jws, keys[jws.kid])
    c = jws.payload
    assert c["iss"] == "https://veridact.test" and c["vct"] == VCT and c["sub"] == "claude"
    assert c["operator"]["name"] == "Anthropic PBC" and c["max_level"] == "approved_payer"
    assert c["exp"] > c["iat"] and c["status"]["status_list"]["uri"].endswith(LIST_PATH)
    lst = await _status(client, keys)
    assert sdjwt.decode_status(lst["lst"], c["status"]["status_list"]["idx"]) == sdjwt.VALID


async def test_suspend_restore_and_withdraw(client):
    keys = await _keys(client)
    entry = jose.parse((await (await client.get("/known-assistants/claude")).text()).split("~")[0]).payload
    idx = entry["status"]["status_list"]["idx"]
    anon = await client.post("/admin/known-assistants/claude/status", json={"status": "suspended"})
    assert anon.status == 401
    headers = {"Authorization": f"Bearer {SECRET}"}
    for status, value in (("suspended", sdjwt.SUSPENDED), ("valid", sdjwt.VALID), ("withdrawn", sdjwt.INVALID)):
        r = await client.post("/admin/known-assistants/claude/status", json={"status": status, "reason": "test"},
                              headers=headers)
        assert r.status == 200 and (await r.json())["status"] == status
        assert sdjwt.decode_status((await _status(client, keys))["lst"], idx) == value
    again = await client.post("/admin/known-assistants/claude/status", json={"status": "valid"}, headers=headers)
    assert again.status == 400                            # withdrawn is final


async def test_the_admin_page_form_needs_the_secret(client):
    page = await (await client.get("/admin")).text()
    assert "Anthropic PBC" in page and "Suspend" in page
    wrong = await client.post("/admin/known-assistants/claude/status", data={"secret": "nope", "status": "suspended"})
    assert wrong.status == 401
    ok = await client.post("/admin/known-assistants/claude/status", data={"secret": SECRET, "status": "suspended"},
                           allow_redirects=False)
    assert ok.status == 303


def test_status_list_encoding_round_trips_two_bits_per_entry():
    lst = sdjwt.encode_status_list({0: 1, 1: 2, 5: 1, 131_071: 2}, 131_072)
    assert [sdjwt.decode_status(lst, i) for i in (0, 1, 2, 5, 131_071)] == [1, 2, 0, 1, 2]


def test_disclosures_are_bound_by_their_digest():
    d, h = sdjwt.disclosure("jurisdiction", "US")
    salt, name, value = json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))
    assert (name, value) == ("jurisdiction", "US") and salt
    assert h == jose.b64url_encode(hashlib.sha256(d.encode()).digest())
