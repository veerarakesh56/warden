"""Manual probe: what does KubernetesBackend actually see right now?

Not a test. A way to read the evidence with your own eyes before trusting a verdict built on it.

    WARDEN_BACKEND=k8s python scripts/probe_cluster.py [service] [namespace]
"""

from __future__ import annotations

import json
import sys

from warden.k8s_backend import KubernetesBackend
from warden.models import Alert, Severity
from warden.tools import gather

service = sys.argv[1] if len(sys.argv) > 1 else "checkout"
namespace = sys.argv[2] if len(sys.argv) > 2 else "default"

alert = Alert(
    alert_id="probe", name="Probe", severity=Severity.high, service=service,
    environment="prod", summary="manual probe", started_at="1970-01-01T00:00:00Z",
    labels={"namespace": namespace},
)

backend = KubernetesBackend()
ctx = gather(alert, backend, timeout=20.0)

print(f"=== {namespace}/{service} via {backend.name} ===")
print("METRICS:")
print(json.dumps(ctx.metrics, indent=2))
print(f"\nRECENT DEPLOYS ({len(ctx.recent_deploys)}):")
for d in ctx.recent_deploys:
    print("  ", d)
print(f"\nLOG LINES ({len(ctx.logs)}) - first 8:")
for line in ctx.logs[:8]:
    print("  ", line[:140])
print(f"\nTOOL ERRORS ({len(ctx.tool_errors)}):")
for e in ctx.tool_errors:
    print("  ", e)
print(f"\nis_empty={ctx.is_empty()}")
