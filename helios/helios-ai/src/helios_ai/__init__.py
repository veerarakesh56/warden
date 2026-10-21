"""helios-ai — Claude-powered explanation shell for the Helios simulator."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("helios-ai")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"
