"""CI and the images pull Docker's official images from this repository's own mirror (ghcr.io/<owner>/warden-mirror,
filled by mirror-images.yml), same digests. Docker Hub and AWS's public mirror both refuse GitHub's shared runners with
429 Too Many Requests often enough to fail builds; rancher/k3s comes from Docker Hub into the same mirror.

The mirror is never a literal account: every workflow names it with ONE expression, the repository variable
IMAGE_MIRROR or else ghcr.io/<repository owner>/warden-mirror, and shell lines lower-case it (GHCR names are lower-case
and an expression cannot lower-case one; an owner whose name has capitals sets IMAGE_MIRROR). The Dockerfiles take the
registry as the build argument BASE_IMAGE_REGISTRY (Docker's own `docker.io/library` by
default, so a build outside CI needs no mirror), with the digest pinned in the Dockerfile itself."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OFFICIAL = r"(python|postgres|mysql|redis|mongo)"
MIRROR_EXPR = "${{ vars.IMAGE_MIRROR || format('ghcr.io/{0}/warden-mirror', github.repository_owner) }}"
MIRROR = MIRROR_EXPR + "/"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCKERFILES = ("Dockerfile", "Dockerfile.runtime")
BUILD_ARG = '--build-arg "BASE_IMAGE_REGISTRY=${IMAGE_MIRROR,,}"'


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
    """Each docker build in CI and in the runtime pipeline names the mirror, lower-cased as GHCR requires."""
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


def test_every_workflow_names_the_mirror_through_the_one_expression():
    """A mirror path written any other way (the owner's name alone, a literal, a second variable) would bypass
    IMAGE_MIRROR and break for an owner whose name has capitals. In YAML values the path is the expression itself; in
    shell it is the IMAGE_MIRROR environment variable - set to that expression at the workflow's top level or the job's
    env - lower-cased."""
    seen = 0
    for f in WORKFLOWS:
        text = f.read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        rest = code.replace(MIRROR_EXPR, "")
        assert "warden-mirror" not in rest, f"{f.name}: a mirror path outside the IMAGE_MIRROR expression"
        assert "vars.IMAGE_MIRROR" not in rest, f"{f.name}: vars.IMAGE_MIRROR used outside the one expression"
        for m in re.finditer(r"^\s*IMAGE_MIRROR:\s*(.+?)\s*$", code, re.MULTILINE):
            assert m.group(1) == MIRROR_EXPR, (f.name, m.group(1))
        for m in re.finditer(r"\$\{?IMAGE_MIRROR[^}]*\}?", rest):
            assert m.group(0) == "${IMAGE_MIRROR,,}", (f.name, m.group(0))
        seen += code.count(MIRROR_EXPR)
    assert seen >= 8  # ci-tool: env, K3S_IMAGE, four services; runtime.yml and mirror-images.yml: env


def test_the_one_expression_guard_catches_a_mirror_named_another_way(tmp_path, monkeypatch):
    """Plant-check of the test above, on copies of the workflows."""
    import sys

    import pytest

    plants = [
        "        image: ghcr.io/${{ github.repository_owner }}/warden-mirror/redis:7\n",
        '        run: docker build --build-arg "BASE_IMAGE_REGISTRY=$IMAGE_MIRROR" .\n',
        "  IMAGE_MIRROR: ghcr.io/${{ github.repository_owner }}/warden-mirror\n",
    ]
    for plant in plants:
        d = tmp_path / str(plants.index(plant))
        d.mkdir()
        for f in WORKFLOWS:
            (d / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        with (d / "ci-tool.yml").open("a", encoding="utf-8") as out:
            out.write(plant)
        monkeypatch.setattr(sys.modules[__name__], "WORKFLOWS", sorted(d.glob("*.yml")))
        with pytest.raises(AssertionError):
            test_every_workflow_names_the_mirror_through_the_one_expression()


def test_dependabots_reading_copy_names_exactly_the_mirrored_images():
    """Dependabot cannot read `FROM ${BASE_IMAGE_REGISTRY}/...` or workflow YAML, so .github/base-images/Dockerfile
    names the same images at their upstream for it. When Dependabot moves a digest or tag there, this fails until the
    same reference is in mirror-images.yml - and through the test above, in the Dockerfiles and ci-tool.yml."""
    ref = (ROOT / ".github/base-images/Dockerfile").read_text(encoding="utf-8")
    named = re.findall(r"(?m)^FROM (\S+)$", ref)
    assert all(line.startswith(("#", "FROM ")) or not line for line in ref.splitlines())
    flow = (ROOT / ".github/workflows/mirror-images.yml").read_text(encoding="utf-8")
    listed = re.findall(r"(?m)^\s+(\S+@sha256:[0-9a-f]{64})$", flow)
    assert sorted(named) == sorted(listed), set(named) ^ set(listed)
    dependabot = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    assert "- /.github/base-images" in dependabot
