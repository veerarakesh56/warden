"""The NEGATIVE Pod Security test's pod, built when the test runs (2026-10-20; was k8s/test/privileged-must-fail.yaml).

    python scripts/negative_pod.py | kubectl apply --dry-run=server -f -     # must be REFUSED: "violates PodSecurity"

A positive test (the Job is admitted) cannot tell "restricted is enforced" from "the namespace label is mistyped and
nothing is enforced". This pod can: privileged, root, none of the hardening the real workloads carry, in the `warden`
namespace - exactly what its restricted Pod Security must refuse. CI (ci-tool.yml, k3d) and scripts/aws_proof.sh (EKS)
pipe it into a server-side dry run and fail if the API server ACCEPTS it, or refuses it for any other reason. It is
never created.

Built here, not kept as a manifest in the repository (owner, 2026-10-20, Sonar kubernetes:S6428): no file in the tree
asks for a privileged container, so no linter needs a skip and nothing can apply it by mistake; the test is unchanged.
Standard library only: it runs before the job installs anything.
"""

from __future__ import annotations

import json
import sys

NAMESPACE = "warden"
# The same small image as the other test workloads, by digest.
IMAGE = "busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"


def manifest() -> dict:
    """What restricted Pod Security must refuse: a privileged container running as root."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "warden-privileged-must-fail", "namespace": NAMESPACE},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "bad",
                "image": IMAGE,
                "command": ["sh", "-c", "id"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi", "ephemeral-storage": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "securityContext": {"privileged": True, "runAsUser": 0},
            }],
        },
    }


def main() -> int:
    json.dump(manifest(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
