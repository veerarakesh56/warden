"""CI and the images pull Docker's official images from this repository's own mirror (ghcr.io/<owner>/warden-mirror,
filled by mirror-images.yml), same digests. Docker Hub refused GitHub's shared runners with 429 Too Many Requests
(2026-10-10), and so did AWS's public mirror, six times ("Data limit exceeded", 2026-10-10 to 2026-10-15).
rancher/k3s comes from Docker Hub into the same mirror (a Docker Hub pull failed the k3d job, 2026-10-15)."""

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
            assert ref.startswith("ghcr.io/veerarakesh56/warden-mirror/"), (f, ref)
            assert "@sha256:" in ref, (f, ref)



def test_the_mirror_workflow_copies_exactly_the_images_in_use_by_digest():
    """mirror-images.yml copies each image CI and the Dockerfiles use into this repository's registry, by digest
    (public.ecr.aws refused GitHub's shared runners six times, 2026-10-10 to 2026-10-15). Its list and the
    references stay equal, so a digest bump cannot skip the mirror."""
    pinned = rf"({OFFICIAL}:[^@\s]+@sha256:[0-9a-f]{{64}})"
    used = set()
    for f in ("Dockerfile", "Dockerfile.runtime", ".github/workflows/ci-tool.yml"):
        text = (ROOT / f).read_text(encoding="utf-8")
        used |= {m.group(1) for m in re.finditer(r"(?:FROM |image: )\S*/" + pinned, text)}
    flow = (ROOT / ".github/workflows/mirror-images.yml").read_text(encoding="utf-8")
    listed = {m.group(1) for m in re.finditer(r"(?m)^\s+" + pinned + "$", flow)}
    assert {u.split("@")[0] for u in used} >= {"python:3.13-slim", "postgres:16", "mysql:8", "redis:7", "mongo:7"}
    assert used == listed, (used ^ listed)
    assert "--preserve-digests" in flow
    assert "packages: write" in flow


def test_the_k3d_cluster_image_comes_from_the_mirror_and_is_in_its_list():
    ci = (ROOT / ".github/workflows/ci-tool.yml").read_text(encoding="utf-8")
    ref = re.search(r"K3S_IMAGE: (\S+)", ci).group(1)
    assert ref.startswith("ghcr.io/veerarakesh56/warden-mirror/rancher/k3s:"), ref
    assert "@sha256:" in ref, ref
    flow = (ROOT / ".github/workflows/mirror-images.yml").read_text(encoding="utf-8")
    assert ref.removeprefix("ghcr.io/veerarakesh56/warden-mirror/") in flow
