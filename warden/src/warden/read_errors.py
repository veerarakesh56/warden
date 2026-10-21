"""How a read of the cloud can fail, as one tuple to catch: AWS's own errors (botocore, when it is installed), the
network's (DNS and timeouts included) and an answer that is not JSON. Readers catch exactly these at the call, and
check an answer's shape themselves; any other exception is a bug, and it still raises."""

from __future__ import annotations


def _read_errors() -> tuple[type[BaseException], ...]:
    found: list[type[BaseException]] = [OSError, ValueError]
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return tuple(found)
    found += [BotoCoreError, ClientError]
    return tuple(found)


READ_ERRORS = _read_errors()
