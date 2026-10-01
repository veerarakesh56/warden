"""Every install is pinned to a hash and every image to a digest (audit A-I-9, A-I-24; fourth review E).

Unpinned `pip install` ran while deploy jobs held cloud credentials, and images were pulled by tags that
can be moved to other content. These keep it that way."""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
UV_VERSION = re.search(r'required-version = "==([\d.]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8")).group(1)


def _steps():
    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_id, job in (doc.get("jobs") or {}).items():
            yield wf.name, job_id, job.get("steps") or [], job


def _code(run: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in run.splitlines())


def test_no_workflow_installs_with_pip():
    found = [(wf, job) for wf, job, steps, _ in _steps() for st in steps
             if re.search(r"\bpip3? install\b", _code(st.get("run", "")))]
    assert not found, found


def test_every_uv_sync_is_locked():
    syncs = [(wf, job, line) for wf, job, steps, _ in _steps() for st in steps
             for line in _code(st.get("run", "")).splitlines() if re.search(r"\buv sync\b", line)]
    assert syncs, "no job installs from uv.lock"
    assert all("--locked" in line for _, _, line in syncs), [s for s in syncs if "--locked" not in s[2]]


def test_uv_is_pinned_and_checksum_verified_everywhere():
    uses = [(wf, job, st) for wf, job, steps, _ in _steps() for st in steps
            if str(st.get("uses", "")).startswith("astral-sh/setup-uv@")]
    assert uses
    for wf, job, st in uses:
        assert re.fullmatch(r"astral-sh/setup-uv@[0-9a-f]{40}", st["uses"]), (wf, job)
        assert st["with"]["version"] == UV_VERSION, (wf, job, st["with"]["version"], UV_VERSION)
        assert re.fullmatch(r"[0-9a-f]{64}", st["with"]["checksum"]), (wf, job)
    assert len({st["with"]["checksum"] for _, _, st in uses}) == 1


def test_packages_are_installed_before_any_cloud_credentials():
    for wf, job, steps, _ in _steps():
        names = [str(st.get("uses", "")) + " " + st.get("run", "") for st in steps]
        creds = next((i for i, n in enumerate(names) if "configure-aws-credentials" in n), None)
        if creds is None:
            continue
        late = [n for n in names[creds:] if re.search(r"\buv sync\b|\bpip3? install\b", n)]
        assert not late, (wf, job, late)


def test_every_image_is_pinned_by_digest():
    images = [(wf, svc["image"]) for wf, _, _, job in _steps() for svc in (job.get("services") or {}).values()]
    for dockerfile in [ROOT / "Dockerfile", *ROOT.glob("scenarios/**/Dockerfile")]:
        images += [(dockerfile.name, m) for m in re.findall(r"^FROM\s+(\S+)", dockerfile.read_text(encoding="utf-8"),
                                                              re.MULTILINE)]
    # The workloads CI applies to its cluster; `warden:local` is built in the job and imported, never pulled.
    for manifest in (ROOT / "k8s" / "test").glob("*.yaml"):
        images += [(manifest.name, m) for m in re.findall(r"^\s*image:\s*(\S+)", manifest.read_text(encoding="utf-8"),
                                                           re.MULTILINE) if m != "warden:local"]
    assert len(images) >= 10, images
    loose = [i for i in images if not re.search(r"@sha256:[0-9a-f]{64}$", i[1])]
    assert not loose, loose


@pytest.mark.parametrize("req", sorted(ROOT.glob("scenarios/**/requirements.txt")), ids=lambda p: p.parent.name)
def test_every_app_requirement_carries_hashes(req):
    """pip turns on hash checking for the whole file once any line has a hash; each pin must have one."""
    text = req.read_text(encoding="utf-8")
    pins = re.findall(r"^([A-Za-z0-9_.\[\]-]+==\S+)((?:\s*\\\n\s+--hash=sha256:[0-9a-f]{64})+)", text, re.MULTILINE)
    lines = [ln for ln in text.splitlines() if re.match(r"^[A-Za-z0-9]", ln)]
    assert lines and len(pins) == len(lines), (req, len(pins), len(lines))
    assert (req.parent / "requirements.in").is_file()


def test_the_build_downloads_no_unpinned_tool():
    """setuptools was fetched by build isolation outside uv.lock's hashes; uv builds with its own copy."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'build-backend = "uv_build"', text)
    assert re.search(rf'requires = \["uv_build>={re.escape(UV_VERSION)},<', text)
    assert (ROOT / "uv.lock").is_file()


def test_the_image_build_context_is_an_allowlist():
    lines = [ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.startswith("#")]
    assert lines[0] == "*"
    copied = set(re.findall(r"^COPY (?!--from)(.+?) \S+$", (ROOT / "Dockerfile").read_text(encoding="utf-8"),
                            re.MULTILINE))
    allowed = {ln[1:].rstrip("/") for ln in lines if ln.startswith("!")}
    assert {f for c in copied for f in c.split()} <= allowed, (copied, allowed)


def _requirement(req: str) -> tuple[str, tuple[str, ...], str]:
    m = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)(?:\[([^\]]+)\])?\s*(.*?)\s*", req)
    name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
    extras = tuple(sorted(e.strip() for e in (m.group(2) or "").split(",") if e.strip()))
    return name, extras, m.group(3).replace(" ", "")


def test_the_lock_was_made_from_this_pyproject():
    """uv.lock records the requirements it was resolved from. A group added after the last `uv lock` turned
    every pipeline red on 2026-10-01 (`uv sync --locked` refuses a stale lock); this fails it locally."""
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    meta = next(p for p in lock["package"] if p["name"] == "warden")["metadata"]

    def locked(entries):
        return {(re.sub(r"[-_.]+", "-", e["name"]).lower(), tuple(sorted(e.get("extras", []))),
                 e.get("specifier", "")) for e in entries}

    want = {(*_requirement(r), "") for r in project["project"]["dependencies"]}
    want |= {(*_requirement(r), x) for x, reqs in project["project"]["optional-dependencies"].items() for r in reqs}
    have = {(re.sub(r"[-_.]+", "-", d["name"]).lower(), tuple(sorted(d.get("extras", []))), d.get("specifier", ""),
             re.search(r"extra == '([^']+)'", d["marker"]).group(1) if d.get("marker") else "")
            for d in meta["requires-dist"]}
    assert want == have, (sorted(want - have), sorted(have - want))
    groups = {g: {_requirement(r) for r in reqs} for g, reqs in project["dependency-groups"].items()}
    assert groups == {g: locked(reqs) for g, reqs in meta["requires-dev"].items()}


def test_a_workflow_that_installs_from_the_lock_runs_when_the_lock_changes():
    """CI · apps and CI · infra install from uv.lock but ran only on their own paths, so a stale lock stayed
    hidden from them until an apps or infra file changed (2026-10-01)."""
    def installs(wf: pathlib.Path) -> bool:
        text = wf.read_text(encoding="utf-8")
        called = re.findall(r"uses: \$/\.github/workflows/(\S+\.yml)|uses: \./\.github/workflows/(\S+\.yml)", text)
        return "uv sync" in text or any(installs(wf.parent / (a or b)) for a, b in called)

    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        on = doc.get("on", doc.get(True)) or {}
        if not isinstance(on, dict) or not installs(wf):
            continue
        for event in ("push", "pull_request"):
            paths = (on.get(event) or {}).get("paths")
            if paths is not None:
                assert {"uv.lock", "pyproject.toml"} <= set(paths), (wf.name, event)
