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
UV_RANGE = re.search(r'required-version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8")).group(1)


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
    from packaging.specifiers import SpecifierSet

    for wf, job, st in uses:
        assert re.fullmatch(r"astral-sh/setup-uv@[0-9a-f]{40}", st["uses"]), (wf, job)
        assert st["with"]["version"] in SpecifierSet(UV_RANGE), (wf, job, st["with"]["version"], UV_RANGE)
        assert re.fullmatch(r"[0-9a-f]{64}", st["with"]["checksum"]), (wf, job)
    # One uv everywhere: one version, one checksum.
    assert len({st["with"]["version"] for _, _, st in uses}) == 1
    assert len({st["with"]["checksum"] for _, _, st in uses}) == 1


def test_dependabot_can_run_the_uv_the_project_asks_for():
    """Dependabot's uv was 0.12.18 on 2026-10-01; an exact pin above it made every uv.lock update fail."""
    from packaging.specifiers import SpecifierSet

    assert "0.12.18" in SpecifierSet(UV_RANGE)


def test_packages_are_installed_before_any_cloud_credentials():
    for wf, job, steps, _ in _steps():
        names = [str(st.get("uses", "")) + " " + st.get("run", "") for st in steps]
        creds = next((i for i, n in enumerate(names) if "configure-aws-credentials" in n), None)
        if creds is None:
            continue
        late = [n for n in names[creds:] if re.search(r"\buv sync\b|\bpip3? install\b", n)]
        assert not late, (wf, job, late)


def test_a_job_that_holds_credentials_restores_no_cache():
    """uv does not re-verify unpacked cache entries: a poisoned cache restored into a deploy job would install
    unchecked (fifth review E, 2026-10-01)."""
    for wf, job, steps, _ in _steps():
        if not any("configure-aws-credentials" in str(st.get("uses", "")) for st in steps):
            continue
        for st in steps:
            if str(st.get("uses", "")).startswith("astral-sh/setup-uv@"):
                assert st["with"].get("enable-cache") is False, (wf, job)


def test_the_deployed_requirements_are_audited_where_they_change():
    text = (ROOT / ".github" / "workflows" / "_apps-check.yml").read_text(encoding="utf-8")
    assert "pip-audit -r" in text and "--require-hashes" in text and "bandit" in text


def test_every_image_is_pinned_by_digest():
    images = [(wf, svc["image"]) for wf, _, _, job in _steps() for svc in (job.get("services") or {}).values()]
    for dockerfile in [ROOT / "Dockerfile", *ROOT.glob("scenarios/**/Dockerfile")]:
        images += [(dockerfile.name, m) for m in re.findall(r"^FROM\s+(\S+)", dockerfile.read_text(encoding="utf-8"),
                                                              re.MULTILINE)]
    # The workloads CI applies to its cluster; `warden:local` is built in the job and imported, never pulled.
    for manifest in (ROOT / "k8s" / "test").glob("*.yaml"):
        images += [(manifest.name, m) for m in re.findall(r"^\s*image:\s*(\S+)", manifest.read_text(encoding="utf-8"),
                                                           re.MULTILINE) if m != "warden:local"]
    # k3d's node and tools images, and the full stack's placeholder ECS image (fifth review E: by tag).
    tool = (ROOT / ".github" / "workflows" / "ci-tool.yml").read_text(encoding="utf-8")
    images += [("ci-tool.yml", m) for m in re.findall(r"^\s*(?:K3S_IMAGE|K3D_IMAGE_TOOLS):\s*(\S+)", tool, re.MULTILINE)]
    assert '--image "$K3S_IMAGE"' in tool
    images += [("ecs.tf", m) for m in re.findall(r'^\s*image\s*=\s*"([^"$]+)"',
                                                 (ROOT / "terraform" / "fullstack" / "ecs.tf").read_text(encoding="utf-8"),
                                                 re.MULTILINE)]
    assert len(images) >= 13, images
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
    # uv builds with its bundled backend only when its own version satisfies this - CI's pinned uv must.
    from packaging.specifiers import SpecifierSet

    ci = {st["with"]["version"] for _, _, steps, _ in _steps() for st in steps
          if str(st.get("uses", "")).startswith("astral-sh/setup-uv@")}
    backend = re.search(r'requires = \["uv_build([^"]+)"\]', text).group(1)
    assert ci and all(v in SpecifierSet(backend) for v in ci), (ci, backend)
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


def test_the_groups_that_build_the_lambdas_carry_pip():
    """The deploy script builds the Lambda zips with `pip install --platform`; a uv environment has no pip,
    so CI · apps failed on 83f65e6. Both apps groups must lock it."""
    import tomllib

    script = (ROOT / "scripts" / "deploy_fullstack_apps.py").read_text(encoding="utf-8")
    assert '"-m", "pip"' in script
    groups = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["dependency-groups"]
    for name in ("apps-check", "apps-deploy"):
        assert any(_requirement(r)[0] == "pip" for r in groups[name]), name


def test_secret_bearing_files_are_kept_out_of_the_package_and_the_image():
    """Sixth review (2026-10-01): five patterns - a git-ignored tfstate (the database master password in plaintext)
    or tfvars under src/ would still ship from a local build."""
    import fnmatch
    import tomllib

    backend = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["uv"]["build-backend"]
    docker = [ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
              if ln.strip().startswith("**/")]
    # One list in three places, kept equal.
    assert backend["source-exclude"] == backend["wheel-exclude"] and set(backend["wheel-exclude"]) <= set(docker)
    # Seventh review: a fixed list of strings could not see a missing pattern - plan.out and trust.local.json, which
    # .gitignore names, and these all shipped from a local build. Each name must be excluded where it lies.
    planted = [".env", ".env.prod", ".envrc", ".env~", "x.log", "crash.log", "server.pem", "x.pem.bak", "tls.key",
               "a.p12", "a.pfx", "a.jks", "x.tfstate", "x.tfstate.backup", "prod.tfvars", "terraform.tfvars.json",
               "prod.auto.tfvars.json", "tfplan", "x.tfplan", "plan.out", "trust.local.json", "audit.db",
               "audit.db-wal", "audit.db-journal", "audit.db-shm", "x.sqlite3", "aws_credentials", ".netrc",
               ".pypirc", ".npmrc", "kubeconfig", "prod.kubeconfig", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
               "putty.ppk", "service-account.json", "x.keystore", "vault.kdbx",
               # eighth review: 27 more shipped
               "plan.json", "terraform.tfstate~", "prod.tfvars~", ".prod.tfvars.swp", ".terraformrc", "terraform.rc",
               "prod.env", "secrets.env", "#.env#", ".pgpass", ".my.cnf", ".vault-token", ".htpasswd", "client.ovpn",
               "token.txt", "secrets.yaml", "secrets.json", "key.p8", "x.pkcs12", "x.jceks", "secring.gpg",
               "private.asc", "x.key.enc", "audit.db~"]
    for patterns, where in ((backend["wheel-exclude"], "the wheel and sdist"), (docker, ".dockerignore")):
        shipped = [n for n in planted if not any(fnmatch.fnmatchcase(n, p.removeprefix("**/")) for p in patterns)]
        assert not shipped, (where, shipped)
    # Files inside a client's config directory, by directory.
    for path in (".docker/config.json", ".kube/config", ".azure/accessTokens.json"):
        assert any(fnmatch.fnmatchcase(path, p.removeprefix("**/")) for p in backend["wheel-exclude"]), path
    # Nothing re-includes what the excludes keep out: the last matching line wins, and `!src/**` after them would
    # bring everything back (eighth review).
    lines = [ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.startswith("#")]
    first_exclude = next(i for i, ln in enumerate(lines) if ln.startswith("**/"))
    assert not any(ln.startswith("!") for ln in lines[first_exclude:]), lines[first_exclude:]
    # And the image keeps no copy of the source in any layer: it is built in two stages.
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    final = dockerfile.split("\nFROM ")[-1]
    assert " AS build" in dockerfile
    # The final stage copies the installed environment and nothing else (eighth review: a string check passed
    # `COPY --from=build /app /app`, the source back in the image).
    copies = [ln.split() for ln in final.splitlines() if ln.strip().upper().startswith(("COPY", "ADD"))]
    assert copies == [["COPY", "--from=build", "/opt/warden", "/opt/warden"]], copies


def test_the_deployed_requirements_are_audited_every_week():
    """Sixth review (2026-10-01): the apps pipeline ran only on a change, so a new CVE in a pinned dependency of
    what is deployed waited for the next change."""
    apps = yaml.safe_load((ROOT / ".github" / "workflows" / "ci-apps.yml").read_text(encoding="utf-8"))
    assert apps[True].get("schedule"), "CI · apps has no schedule"
    # And it fires every week: any day of the month and month, one fixed minute, hour and weekday - a cron that never
    # fires (`0 0 31 2 *`) passed the check above (seventh review, 2026-10-01).
    [cron] = [s["cron"] for s in apps[True]["schedule"]]
    minute, hour, dom, month, dow = cron.split()
    assert dom == "*" and month == "*" and minute.isdigit() and hour.isdigit() and dow in tuple("0123456"), cron
    assert 0 <= int(minute) <= 59 and 0 <= int(hour) <= 23, cron  # `99 25 * * 1` is rejected by GitHub: it never runs
    check = (ROOT / ".github" / "workflows" / "_apps-check.yml").read_text(encoding="utf-8")
    assert "pip-audit -r" in check


def test_dependabot_never_updates_the_root_package_with_pip():
    """Audit R5-E2: a `pip /` entry opened pull requests that changed pyproject.toml without uv.lock - merging one
    turned every pipeline red. The root package is uv's; pip covers only the demo apps' hashed requirements."""
    import yaml

    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    for entry in config["updates"]:
        dirs = [entry.get("directory")] + list(entry.get("directories") or [])
        if entry["package-ecosystem"] == "pip":
            assert all(d and d.startswith("/scenarios/") for d in dirs if d is not None), dirs
    assert any(e["package-ecosystem"] == "uv" and e.get("directory") == "/" for e in config["updates"])
