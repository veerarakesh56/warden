"""Change freezes (register C6, policy P19-FREEZE): no remediation is applied inside a declared window.

Read from data/freeze.yaml, or WARDEN_FREEZE_FILE. A window that cannot be read refuses the change rather than
letting it through: a freeze that silently fails open is no freeze.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml


def _text(path: str | None) -> str:
    path = path or os.environ.get("WARDEN_FREEZE_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8")
    return (resources.files("warden") / "data" / "freeze.yaml").read_text(encoding="utf-8")


def active(environment: str, now: datetime, *, path: str | None = None) -> list[str]:
    """P19 reasons for a change in `environment` at `now` (aware); empty when no window covers it."""
    try:
        windows = (yaml.safe_load(_text(path)) or {}).get("windows") or []
    except (OSError, yaml.YAMLError) as exc:
        return [f"P19-FREEZE: the freeze file cannot be read ({type(exc).__name__}); no change is applied"]
    if not isinstance(windows, list):
        return ["P19-FREEZE: the freeze file's `windows` is not a list; no change is applied"]
    reasons = []
    for w in windows:
        name = str(w.get("name", "?")) if isinstance(w, dict) else "?"
        try:
            zone = ZoneInfo(str(w["zone"]))
            start = datetime.fromisoformat(str(w["start"])).replace(tzinfo=zone)
            end = datetime.fromisoformat(str(w["end"])).replace(tzinfo=zone)
            envs = {str(e) for e in w["environments"]}
        except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError) as exc:
            reasons.append(f"P19-FREEZE: window {name!r} cannot be read ({type(exc).__name__}); no change is applied")
            continue
        if environment in envs and start <= now.astimezone(zone) <= end:
            reasons.append(f"P19-FREEZE: {environment} is in the change freeze {name!r} until "
                           f"{end.astimezone(UTC):%Y-%m-%d %H:%M} UTC ({end:%Y-%m-%d %H:%M} {w['zone']})")
    return reasons
