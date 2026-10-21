"""CI and the images pull Docker's official images from this repository's own mirror (ghcr.io/<owner>/warden-mirror,
filled by mirror-images.yml), same digests. Docker Hub and AWS's public mirror both refuse GitHub's shared runners with
429 Too Many Requests often enough to fail builds; rancher/k3s comes from Docker Hub into the same mirror.

The mirror is the repository owner's, never a literal account: workflows name it with `github.repository_owner`, and
the Dockerfiles take the registry as the build argument BASE_IMAGE_REGISTRY (Docker's own `docker.io/library` by
default, so a build outside CI needs no mirror), with the digest pinned in the Dockerfile itself."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OFFICIAL = r"(python|postgres|mysql|redis|mongo)"
MIRROR = "ghcr.io/${{ github.repository_owner }}/warden-mirror/"
DOCKERFILES = ("Dockerfile", "Dockerfile.runtime")
BUILD_ARG = '--build-arg "BASE_IMAGE_REGISTRY=ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/warden-mirror"'


def test_official_images_come_from_the_mirror_pinned_by_digest():
    ci = (ROOT / ".github/workflows/ci-tool.yml").read_text(encoding="utf-8")
    refs = re.findall(rf"image: ([^\n]*?{OFFICIAL}:\S+)", ci)
    assert refs
    for ref, _ in refs:
        assert ref.startswith(MIRROR), ref
        assert "@sha256:" in ref, ref
    for f in DOCKERFILES:
        text = (ROOT / f).read_text(encoding="utf-8")
        assert "ARG BASE_IMAGE_REGISTRY=docker.io/library\n" in text, f
        assert text.index("ARG BASE_IMAGE_REGISTRY") < text.index("FROM "), f  # a global ARG, before the first FROM
        refs = re.findall(rf"FROM (\S*{OFFICIAL}:\S+)", text)
        assert refs, f
        for ref, _ in refs:
            assert ref.startswith("${BASE_IMAGE_REGISTRY}/"), (f, ref)
            assert "@sha256:" in ref, (f, ref)


def test_every_build_of_the_images_passes_the_mirror():
    """Each docker build in CI and in the runtime pipeline names the owner's mirror, lower-cased as GHCR requires."""
    for f in (".github/workflows/ci-tool.yml", ".github/workflows/runtime.yml"):
        text = (ROOT / f).read_text(encoding="utf-8")
        builds = re.findall(r"docker build [^\n]*", text)
        assert builds, f
        for build in builds:
            assert BUILD_ARG in build, (f, build)


def test_no_image_names_a_literal_registry_owner():
    for f in (*DOCKERFILES, ".github/workflows/ci-tool.yml", ".github/workflows/runtime.yml"):
        text = (ROOT / f).read_text(encoding="utf-8")
        assert not re.search(r"ghcr\.io/(?!\$\{|astral-sh/|k3d-io/)[\w.-]+/warden-mirror", text), f


def test_the_mirror_workflow_copies_exactly_the_images_in_use_by_digest():
    """mirror-images.yml copies each image CI and the Dockerfiles use into this repository's registry, by digest. Its
    list and the references stay equal, so a digest bump cannot skip the mirror."""
    pinned = rf"({OFFICIAL}:[^@\s]+@sha256:[0-9a-f]{{64}})"
    used = set()
    for f in (*DOCKERFILES, ".github/workflows/ci-tool.yml"):
        text = (ROOT / f).read_text(encoding="utf-8")
        used |= {m.group(1) for m in re.finditer(r"(?:FROM |image: )[^\n]*?/" + pinned, text)}
    flow = (ROOT / ".github/workflows/mirror-images.yml").read_text(encoding="utf-8")
    listed = {m.group(1) for m in re.finditer(r"(?m)^\s+" + pinned + "$", flow)}
    assert {u.split("@")[0] for u in used} >= {"python:3.13-slim", "postgres:16", "mysql:8", "redis:7", "mongo:7"}
    assert used == listed, (used ^ listed)
    assert "--preserve-digests" in flow
    assert "packages: write" in flow


def test_the_k3d_cluster_image_comes_from_the_mirror_and_is_in_its_list():
    ci = (ROOT / ".github/workflows/ci-tool.yml").read_text(encoding="utf-8")
    ref = re.search(r"K3S_IMAGE: ([^\n]+)", ci).group(1).strip()
    assert ref.startswith(MIRROR + "rancher/k3s:"), ref
    assert "@sha256:" in ref, ref
    flow = (ROOT / ".github/workflows/mirror-images.yml").read_text(encoding="utf-8")
    assert ref.removeprefix(MIRROR) in flow
