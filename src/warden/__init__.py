"""WARDEN — AI incident-response orchestrator.

The model proposes. A deterministic verifier decides. Nothing executes infrastructure actions unless
live remediation is explicitly armed (WARDEN_REMEDIATION=live) AND the remediation gate passes.
"""

__version__ = "0.9.0"

__all__ = ["Alert", "RunReport", "__version__", "run"]


def __getattr__(name: str):
    # Lazy on purpose: importing the package must not import the graph (LangGraph, HTTP clients).
    # Temporal's workflow sandbox re-imports `warden` for every workflow, and those modules are not
    # sandbox-safe; `from warden import run` still works exactly as before.
    if name == "run":
        from .graph import run
        return run
    if name in ("Alert", "RunReport"):
        from . import models
        return getattr(models, name)
    raise AttributeError(f"module 'warden' has no attribute {name!r}")
