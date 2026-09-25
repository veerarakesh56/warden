"""WARDEN — AI incident-response orchestrator.

The model proposes. A deterministic verifier decides. Nothing executes infrastructure actions unless
live remediation is explicitly armed (WARDEN_REMEDIATION=live) AND the remediation gate passes.
"""

__version__ = "0.8.0"

from .graph import run
from .models import Alert, RunReport

__all__ = ["Alert", "RunReport", "__version__", "run"]
