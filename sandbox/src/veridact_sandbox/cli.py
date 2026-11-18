"""veridact-sandbox: run the Veridact Insurance sandbox relying party.

    veridact-sandbox --config sandbox.json
    veridact-sandbox --audience https://sandbox.veridact.net \\
        --trust-list https://staging.veridact.net/trust-list.jwt \\
        --governance-keys-url https://staging.veridact.net/governance-keys.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging

from aiohttp import web
from veridact_sidecar import VerifierConfig

from .app import create_app


async def _fetch_governance_keys(config_raw: dict, url: str) -> dict:
    """Staging convenience: read the staging governance keys from the issuer.

    A production relying party pins its governance keys from an out-of-band source.
    """
    from veridact_verify import HttpFetcher, RoutedFetcher

    fetcher = RoutedFetcher(config_raw.get("routes") or {}) if config_raw.get("routes") else HttpFetcher()
    try:
        return json.loads(await fetcher.fetch(url))["keys"]
    finally:
        await fetcher.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veridact-sandbox", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config")
    parser.add_argument("--audience")
    parser.add_argument("--trust-list")
    parser.add_argument("--governance-keys-url", help="staging only")
    parser.add_argument("--route", action="append", metavar="HOST=URL")
    parser.add_argument("--status-ttl", type=float,
                        help="seconds to cache status lists (default 300, as the spec allows); "
                             "0 shows revocations at once")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8070)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    raw: dict = json.loads(open(args.config).read()) if args.config else {}
    if args.audience:
        raw["audience"] = args.audience
    if args.trust_list:
        raw["trust_list_url"] = args.trust_list
    if args.status_ttl is not None:
        raw["status_ttl"] = args.status_ttl
    if args.route:
        raw["routes"] = dict(r.split("=", 1) for r in args.route)
    keys_url = args.governance_keys_url or raw.pop("governance_keys_url", None)
    if keys_url and not raw.get("governance_keys"):
        raw["governance_keys"] = asyncio.run(_fetch_governance_keys(raw, keys_url))
    raw.setdefault("min_tier", "domain")
    config = VerifierConfig.from_dict(raw)
    web.run_app(create_app(config), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
