"""veridact-issuer: run a staging ACME-A issuer.

    veridact-issuer init  --config issuer.json      create keys and the issuer DID
    veridact-issuer serve --config issuer.json      serve ACME-A and the published files
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from aiohttp import web

from .app import Issuer, create_app
from .config import IssuerConfig
from .keys import load_or_create_identity


def _config(args: argparse.Namespace) -> IssuerConfig:
    overrides = {}
    if args.base_url:
        overrides["base_url"] = args.base_url
    if args.data_dir:
        overrides["data_dir"] = args.data_dir
    if args.route:
        overrides["routes"] = dict(r.split("=", 1) for r in args.route)
    if args.config:
        return IssuerConfig.from_file(args.config, **overrides)
    return IssuerConfig.from_dict(overrides)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veridact-issuer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["init", "serve"])
    parser.add_argument("--config", default=os.environ.get("VERIDACT_ISSUER_CONFIG"))
    parser.add_argument("--base-url", help="canonical https origin, e.g. https://staging.veridact.net")
    parser.add_argument("--data-dir")
    parser.add_argument("--route", action="append", metavar="HOST=URL",
                        help="development: fetch https://HOST from URL instead")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = _config(args)

    if args.command == "init":
        identity = load_or_create_identity(config)
        print(json.dumps({
            "issuer": identity.did,
            "signingKey": identity.signer.kid,
            "governanceKeys": identity.governance_jwks,
            "trustList": config.trust_list_url if config.publish_trust_list else None,
        }, indent=2))
        return 0

    issuer = Issuer(config)
    print(f"Veridact {config.environment} issuer {issuer.identity.did}", file=sys.stderr)
    print(f"  directory: {config.base_url}/directory (listening on {args.host}:{args.port})",
          file=sys.stderr)
    web.run_app(create_app(issuer), host=args.host, port=args.port, print=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
