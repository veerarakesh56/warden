"""Make the test suite hermetic regardless of the ambient environment.

The Makefile exports ``WARDEN_MOCK=1`` for ``make test``, but a bare ``pytest`` inherits the shell.
If a real provider key (``GEMINI_API_KEY``, ``ANTHROPIC_API_KEY``, ...) happens to be exported, the
pipeline tests resolve a *live* provider and either spend money or fail on auth — a footgun that has
bitten in practice. Tests must never depend on ambient credentials.

``setdefault`` (not overwrite) so an integration run that deliberately sets ``WARDEN_MOCK=0`` to
exercise the live path is still honoured; this only supplies the default the Makefile otherwise would.
"""

import os

os.environ.setdefault("WARDEN_MOCK", "1")
