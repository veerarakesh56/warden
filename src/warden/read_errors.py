"""How a read of the cloud can fail, as one tuple to catch: AWS's own errors (botocore, when it is installed), the
network's (DNS and timeouts included) and an answer of the wrong shape. Readers that must turn any such failure into
"not read" - never into health - catch exactly these, not every exception (a bug still raises)."""

from __future__ import annotations


def _read_errors() -> tuple[type[BaseException], ...]:
    shape = (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError)
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return shape
    return (BotoCoreError, ClientError, *shape)


READ_ERRORS = _read_errors()
