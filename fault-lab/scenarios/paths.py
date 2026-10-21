"""Where a path named on a command line may point: WARDEN's own rule (warden/src/warden/paths.py, Sonar pythonsecurity:S8707),
loaded from its file as region.py reads environments.yaml - never `import warden`, so the harness shares no package,
settings or state with the tool it measures. That file is stdlib only; one copy of the rule, not two to keep in step
(a byte-for-byte copy was 48 duplicated lines, Sonar's quality gate, 2026-10-17)."""

from __future__ import annotations

import importlib.util
import pathlib

RULE = pathlib.Path(__file__).resolve().parents[2] / "warden" / "src" / "warden" / "paths.py"
_spec = importlib.util.spec_from_file_location("scenarios._warden_paths", RULE)
_rule = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rule)

bench_dir = _rule.bench_dir
inside = _rule.inside
work_roots = _rule.work_roots
