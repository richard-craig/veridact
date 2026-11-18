"""veridact-sidecar: the Veridact verifier over HTTP.

    veridact-sidecar --config rp.json --port 8090
    VERIDACT_CONFIG=rp.json VERIDACT_SIDECAR_TOKEN=... veridact-sidecar
"""

from __future__ import annotations

import argparse
import logging
import os

from aiohttp import web

from .app import create_app
from .config import VerifierConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veridact-sidecar", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="JSON config (or VERIDACT_CONFIG / VERIDACT_* variables)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address; keep it private, the sidecar trusts its callers")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = VerifierConfig.from_file(args.config) if args.config else VerifierConfig.from_env()
    token = os.environ.get("VERIDACT_SIDECAR_TOKEN") or None
    web.run_app(create_app(config, api_token=token), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
