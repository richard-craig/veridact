"""Token Status Lists and the SD-JWT building blocks."""

import zlib

import pytest

from veridact_verify import jose, sdjwt, status
from veridact_verify.fetch import ArtefactCache
from veridact_verify.status import StatusError, StatusLists, StatusRef
from veridact_verify.testing import NOW, MockNetwork


def test_two_bit_entries_least_significant_first():
    entries = status.empty()
    status.put(entries, 0, status.INVALID)
    status.put(entries, 3, status.SUSPENDED)
    status.put(entries, 5, 3)
    assert entries[0] == 0b10_00_00_01
    assert entries[1] == 0b00_00_11_00
    _, decoded = status.decode_list(status.encode_list(bytes(entries)))
    assert [status.get(decoded, i) for i in range(6)] == [1, 0, 0, 2, 0, 3]
    status.put(entries, 0, status.VALID)  # clearing works too
    assert status.get(entries, 0) == 0


def test_zlib_bomb_refused():
    bomb = jose.b64url_encode(zlib.compress(bytes(64 * 1024 * 1024), 9))
    with pytest.raises(StatusError):
        status.decode_list({"bits": 2, "lst": bomb})


def test_reference_parsing():
    assert status.parse_ref(None) is None
    assert status.parse_ref(status.ref_claim(4, "https://s.example/1")) == StatusRef(4, "https://s.example/1")
    for bad in ({"status_list": {"idx": -1, "uri": "https://s"}}, {"status_list": {"idx": 1, "uri": "http://s"}},
                {"status_list": {"idx": True, "uri": "https://s"}}, {"bitstring": {}}):
        with pytest.raises(StatusError):
            status.parse_ref(bad)


async def test_list_must_name_its_own_uri():
    net = MockNetwork()
    lists = StatusLists(net.fetcher, ArtefactCache(lambda: NOW))
    body = net.fetcher.files[net.operator_status_url]
    net.fetcher.put(net.agent_status_url, body)

    async def ok(_):
        return None

    with pytest.raises(StatusError, match="sub"):
        await lists.check(StatusRef(1, net.agent_status_url), ok)


def test_sd_jwt_round_trip_and_selection():
    key = jose.b64url_encode  # noqa: F841 (keeps the import obviously used)
    from cryptography.hazmat.primitives.asymmetric import ec
    signer = ec.generate_private_key(ec.SECP256R1())
    token = sdjwt.issue({"kid": "k"}, {"iss": "https://i.example", "sub": "https://a.example"},
                        {"a": 1, "b": {"c": [1, 2]}}, sdjwt.key_signer(signer), decoys=3)
    parsed = sdjwt.parse(token)
    assert parsed.jws.typ == "dc+sd-jwt"
    assert len(parsed.jws.payload["_sd"]) == 5
    assert parsed.claims() == {"iss": "https://i.example", "sub": "https://a.example", "a": 1, "b": {"c": [1, 2]}}
    only_a = parsed.select(["a"])
    assert only_a.claims() == {"iss": "https://i.example", "sub": "https://a.example", "a": 1}
    assert only_a.sd_hash != parsed.sd_hash


def test_sd_jwt_refuses_reserved_and_clashing_names():
    from cryptography.hazmat.primitives.asymmetric import ec
    sign = sdjwt.key_signer(ec.generate_private_key(ec.SECP256R1()))
    for claims, disclosable in (({"a": 1}, {"a": 2}), ({}, {"cnf": {}}), ({}, {"status": 1})):
        with pytest.raises(sdjwt.SdJwtError):
            sdjwt.issue({}, claims, disclosable, sign)
    with pytest.raises(sdjwt.SdJwtError):
        sdjwt.Disclosure.parse(jose.b64url_encode(b'["salt", "_sd", 1]'))


def test_sd_jwt_refuses_repeated_and_unreferenced_disclosures():
    from cryptography.hazmat.primitives.asymmetric import ec
    sign = sdjwt.key_signer(ec.generate_private_key(ec.SECP256R1()))
    token = sdjwt.issue({}, {"iss": "https://i.example"}, {"a": 1}, sign)
    jwt, disclosure, _ = token.split("~")
    with pytest.raises(sdjwt.SdJwtError):
        sdjwt.parse(f"{jwt}~{disclosure}~{disclosure}~")
    stray = sdjwt.Disclosure.create("b", 2).raw
    with pytest.raises(sdjwt.SdJwtError):
        sdjwt.parse(f"{jwt}~{disclosure}~{stray}~").claims()


def test_array_element_disclosures():
    element = sdjwt.Disclosure.create(None, "DE")
    payload = {"nationalities": [{"...": element.digest}, "ZA"], "_sd_alg": "sha-256"}
    assert sdjwt.resolve(payload, [element]) == {"nationalities": ["DE", "ZA"]}
    assert sdjwt.resolve(payload, []) == {"nationalities": ["ZA"]}
