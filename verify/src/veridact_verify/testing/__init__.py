"""Test tooling: a self-contained mock Veridact network.

Not for production. It holds private keys in memory and signs whatever it is told.
"""

from .mock_network import NOW, MockNetwork

__all__ = ["MockNetwork", "NOW"]
