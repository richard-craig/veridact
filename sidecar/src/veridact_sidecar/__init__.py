"""veridact-sidecar: the Veridact verifier as an HTTP service."""

from .app import create_app
from .config import ConfigError, VerifierConfig, decision_body, parse_request

__all__ = ["ConfigError", "VerifierConfig", "create_app", "decision_body", "parse_request"]
__version__ = "0.5.0a1"
