"""veridact-sandbox: Veridact Insurance, a sandbox relying party for trying agents against."""

from .app import CLAIMS, create_app

__all__ = ["CLAIMS", "create_app"]
__version__ = "0.1.0a1"
