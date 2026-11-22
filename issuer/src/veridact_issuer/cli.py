"""veridact-issuer: run a staging ACME-A issuer (specification v0.5).

    veridact-issuer init  --config issuer.json      create the issuer key and identity
    veridact-issuer serve --config issuer.json      serve ACME-A and the published files

    veridact-issuer assistant issue   ID --entry entry.json   issue or reissue a known-assistant entry
    veridact-issuer assistant suspend ID                      the kill switch: suspend at every bank
    veridact-issuer assistant restore ID                      lift a suspension
    veridact-issuer assistant withdraw ID                     withdraw for good
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
    parser.add_argument("command", choices=["init", "serve", "assistant"])
    parser.add_argument("action", nargs="?", choices=["issue", "suspend", "restore", "withdraw"])
    parser.add_argument("entry_id", nargs="?", metavar="ID")
    parser.add_argument("--entry", help="assistant issue: a JSON file with the entry's claims")
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
            "issuer": identity.id,
            "signingKey": identity.signer.kid,
            "governanceKeys": identity.governance_jwks,
            "trustList": config.trust_list_url if config.publish_trust_list else None,
        }, indent=2))
        return 0

    issuer = Issuer(config)
    if args.command == "assistant":
        from veridact_verify import status
        if not args.action or not args.entry_id:
            parser.error("assistant needs an action and an ID")
        if args.action == "issue":
            if not args.entry:
                parser.error("assistant issue needs --entry FILE")
            with open(args.entry) as fh:
                token = issuer.issue_known_assistant(args.entry_id, json.load(fh))
            print(json.dumps({"id": args.entry_id, "url": f"{config.base_url}/assistants/{args.entry_id}",
                              "credential": token}, indent=2))
        else:
            value = {"suspend": status.SUSPENDED, "restore": status.VALID, "withdraw": status.INVALID}[args.action]
            issuer.set_assistant_status(args.entry_id, value)
            print(json.dumps({"id": args.entry_id, "status": args.action}))
        issuer.store.close()
        return 0
    print(f"Veridact {config.environment} issuer {issuer.identity.id}", file=sys.stderr)
    print(f"  directory: {config.base_url}/directory (listening on {args.host}:{args.port})",
          file=sys.stderr)
    web.run_app(create_app(issuer), host=args.host, port=args.port, print=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
