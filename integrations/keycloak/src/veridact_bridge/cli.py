"""veridact-keycloak-bridge: Veridact token exchange in front of Keycloak.

    veridact-keycloak-bridge --config bridge.json --port 8095
"""

from __future__ import annotations

import argparse
import logging

from aiohttp import web

from .app import Bridge, create_app
from .config import BridgeConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veridact-keycloak-bridge", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8095)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    bridge = Bridge(BridgeConfig.from_file(args.config))
    web.run_app(create_app(bridge), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
