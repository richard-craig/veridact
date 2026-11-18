"""vbot: the Veridact agent client.

    from vbot import Vbot, call
    bot = Vbot.load("~/.vbot")
    result = await call(bot, "https://sandbox.veridact.net/claims/CLM-1001/status", agent_id="a1b2c3")
"""

from .acme import AcmeClient, AcmeError
from .core import Vbot, VbotError
from .http import audience_for, call, parse_challenge

__all__ = ["AcmeClient", "AcmeError", "Vbot", "VbotError", "audience_for", "call", "parse_challenge"]
__version__ = "0.1.0a1"
