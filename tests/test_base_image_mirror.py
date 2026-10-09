"""CI and the images pull Docker's official images from AWS's public mirror (public.ecr.aws/docker/library), same
digests: Docker Hub refused GitHub's shared runners with 429 Too Many Requests and turned CI red twice (2026-10-10).
rancher/k3s has no mirror there and stays on Docker Hub."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OFFICIAL = r"(python|postgres|mysql|redis|mongo)"


def test_official_images_come_from_the_mirror_pinned_by_digest():
    for f in ("Dockerfile", "Dockerfile.runtime", ".github/workflows/ci-tool.yml"):
        text = (ROOT / f).read_text(encoding="utf-8")
        refs = re.findall(rf"(?:FROM |image: )(\S*{OFFICIAL}:\S+)", text)
        assert refs, f
        for ref, _ in refs:
            assert ref.startswith("public.ecr.aws/docker/library/") and "@sha256:" in ref, (f, ref)
