import pytest

from veridact_verify.fetch import ArtefactCache
from veridact_verify.status import (
    MIN_LIST_BITS,
    StatusEntry,
    StatusError,
    StatusLists,
    decode_bitstring,
    encode_bitstring,
)
from veridact_verify.testing import NOW, MockNetwork


def test_bit_order_is_left_most_first():
    bits = bytearray(MIN_LIST_BITS // 8)
    bits[0] = 0x80  # index 0
    bits[1] = 0x01  # index 15
    decoded = decode_bitstring(encode_bitstring(bytes(bits)))
    from veridact_verify.status import StatusList
    sl = StatusList("u", "i", "revocation", decoded, None)  # type: ignore[arg-type]
    assert [i for i in range(16) if sl.is_set(i)] == [0, 15]


def test_gzip_bomb_refused():
    import gzip

    from veridact_verify import jose
    bomb = "u" + jose.b64url_encode(gzip.compress(bytes(32 * 1024 * 1024)))
    with pytest.raises(StatusError):
        decode_bitstring(bomb)


async def test_cached_list_checked_against_each_credentials_issuer():
    net = MockNetwork()
    lists = StatusLists(net.fetcher, ArtefactCache(lambda: NOW))
    entry = StatusEntry("revocation", 1, net.agent_status_url)

    async def ok(_):
        return None

    await lists.check(entry, ok, expected_issuer=net.issuer.did)
    with pytest.raises(StatusError):
        await lists.check(entry, ok, expected_issuer=net.rogue_issuer.did)
