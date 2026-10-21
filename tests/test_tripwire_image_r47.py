"""The cloud runtime carries the injection tripwire (register R47).

Prompt Guard 2 was once measured locally for weeks while the cloud image had no detector and every environment had it
off. These pin each link: the guard extra in
the image with CPU-only torch, the pinned weights fetched at build with the token as a build secret and checked against
the measured copy, offline use at run time, the token's place in the pipeline, the read zone sized for the model, and
the detector on in every environment.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import uuid

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bake_tripwire  # after the sys.path line above

from warden import tripwire

DOCKERFILE = re.sub(r"\\\n\s*", "", (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8"))  # continuations joined


def test_the_image_installs_the_detector_with_cpu_only_torch():
    sync = next(line for line in DOCKERFILE.splitlines() if line.startswith("RUN uv sync"))
    assert "--locked" in sync
    assert "--extra guard" in sync
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'url = "https://download.pytorch.org/whl/cpu"' in pyproject
    assert "explicit = true" in pyproject
    assert 'torch = [{ index = "pytorch-cpu", marker = "sys_platform == \'linux\'" }]' in pyproject
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert 'version = "2.14.1+cpu"' in lock
    assert not re.search(r'^name = "(nvidia-|cuda-|triton)', lock, re.MULTILINE)  # no GPU stack in the image


def test_the_weights_are_baked_at_build_from_the_pinned_revision_with_the_token_as_a_build_secret():
    assert ('RUN --mount=type=secret,id=hf_token /opt/warden/bin/python bake_tripwire.py hf "$WARDEN_DETECTOR"'
            ' && chmod -R a+rX hf' in DOCKERFILE)
    assert "ARG WARDEN_DETECTOR=baked" in DOCKERFILE
    assert "WORKDIR /app" in DOCKERFILE.split("bake_tripwire.py hf")[0].splitlines()  # so hf/ is /app/hf, copied below
    # The script reaches the build: .dockerignore keeps scripts/ out but these two (a deploy once failed on it).
    assert "!scripts/bake_tripwire.py" in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "ARG HF" not in DOCKERFILE
    assert "HF_TOKEN" not in DOCKERFILE  # never a build argument or an image variable
    assert "COPY --from=build /app/hf /opt/hf" in DOCKERFILE
    for setting in ("HF_HUB_CACHE=/opt/hf", "HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1", "HF_HOME=/tmp/hf"):
        assert setting in DOCKERFILE, setting
    assert bake_tripwire.SECRET == pathlib.Path("/run/secrets/hf_token")
    # Every file the detector loads, each pinned to the copy every measurement in tripwire.py was made on.
    assert sorted(bake_tripwire.FILES) == ["config.json", "model.safetensors", "special_tokens_map.json",
                                           "tokenizer.json", "tokenizer_config.json"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in bake_tripwire.FILES.values())
    assert tripwire.REVISION == "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"


def test_the_bake_refuses_a_copy_that_is_not_the_measured_one(tmp_path, monkeypatch):
    import types

    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    for name in bake_tripwire.FILES:
        (snapshot / name).write_bytes(b"not the measured weights")
    fake_hub = types.SimpleNamespace(snapshot_download=lambda *a, **k: str(snapshot))
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    try:
        bake_tripwire.fetch(tmp_path, "t")
    except SystemExit as exc:
        assert "is not the measured copy's" in str(exc)
    else:
        raise AssertionError("a changed weight file was accepted")


def test_the_pipeline_passes_the_token_as_a_build_secret_only_and_deploys_no_image_without_the_weights():
    wf = (ROOT / ".github" / "workflows" / "runtime.yml").read_text(encoding="utf-8")
    assert "HF_TOKEN: ${{ secrets.HF_TOKEN }}" in wf
    assert '--secret id=hf_token,env=HF_TOKEN -f Dockerfile.runtime' in wf
    # Never WARDEN_DETECTOR=absent, never the token as an argument: the one build argument is the base image's
    # registry: the workflow's IMAGE_MIRROR (the base-image mirror), lower-cased.
    registry = '--build-arg "BASE_IMAGE_REGISTRY=${IMAGE_MIRROR,,}"'
    assert wf.count(registry) == 1
    assert "--build-arg" not in wf.replace(registry, "")
    assert "rglob('model.safetensors')), 'no tripwire weights'" in wf
    # CI's check build has no token and says so; it is never deployed.
    ci = (ROOT / ".github" / "workflows" / "ci-tool.yml").read_text(encoding="utf-8")
    assert "--build-arg WARDEN_DETECTOR=absent -f Dockerfile.runtime -t warden-runtime:ci" in ci


def test_the_bake_without_a_token_fails_unless_the_build_says_absent(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bake_tripwire, "SECRET", tmp_path / "no-such-secret")
    try:
        bake_tripwire.main(["bake_tripwire.py", str(tmp_path / "hf"), "baked"])
    except SystemExit as exc:
        assert "no Hugging Face token" in str(exc)
    else:
        raise AssertionError("a bake without a token passed")
    assert bake_tripwire.main(["bake_tripwire.py", str(tmp_path / "hf"), "absent"]) == 0
    assert "NOT baked" in capsys.readouterr().out
    assert not any((tmp_path / "hf").iterdir())
    # The cache dir comes from the command line: one outside the working directory and the temp folder is refused.
    # A folder of its own, named for this run only: a regression harms nothing, and only what it wrote is removed.
    outside = pathlib.Path.home() / f".warden-test-outside-bake-{uuid.uuid4().hex}"
    try:
        bake_tripwire.main(["bake_tripwire.py", str(outside / "hf"), "absent"])
    except SystemExit as exc:
        assert "refused" in str(exc)
    else:
        raise AssertionError("a cache dir outside the build's folders was accepted")
    finally:
        written = outside.exists()
        shutil.rmtree(outside, ignore_errors=True)
    assert not written
    for bad in (["bake_tripwire.py", "x"], ["bake_tripwire.py", "x", "maybe"]):
        try:
            bake_tripwire.main(bad)
        except SystemExit:
            continue
        raise AssertionError(bad)


def test_the_read_zone_has_room_for_the_model():
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "variables.tf").read_text(encoding="utf-8")
    read = re.search(r"read\s*=\s*\{\s*cpu\s*=\s*(\d+),\s*memory\s*=\s*(\d+)\s*\}", tf)
    assert int(read.group(1)) >= 1024
    assert int(read.group(2)) >= 3072  # 1.1 GB of weights, torch, the worker


def test_every_environment_scans():
    envs = yaml.safe_load((ROOT / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8"))
    modes = {name: e.get("tripwire") for name, e in envs["environments"].items()}
    assert modes, modes
    assert all(m in ("on", "required") for m in modes.values()), modes
