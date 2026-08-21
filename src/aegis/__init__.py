"""AEGIS — AI incident-response orchestrator.

The model proposes. A deterministic verifier decides. Nothing here executes infrastructure actions.
"""

__version__ = "0.4.0"

from .graph import run
from .models import Alert, RunReport

__all__ = ["Alert", "RunReport", "__version__", "run"]
