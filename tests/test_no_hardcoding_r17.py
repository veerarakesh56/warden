"""Owner requirements R17 and R32: the AWS region is configuration (environments.yaml `aws_region`), never a literal in
code - not in Python, not in Terraform, not in the IAM templates."""

from __future__ import annotations

import ast
import pathlib
import re
import subprocess

import pytest

from warden import environments

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Every AWS partition's regions: commercial (eu-west-1), China (cn-north-1), GovCloud (us-gov-west-1), the ISO
# partitions (us-iso-east-1, us-isob-east-1) and the European Sovereign Cloud (eusc-de-east-1) (CodeRabbit, PR 37).
REGION = re.compile(r"\b(?:[a-z]{2}|eusc-[a-z]{2})(?:-gov|-iso[a-z]?)?-"
                    r"(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d\b")
# AWS serves its global services (IAM, CloudFront, region discovery) from us-east-1: AWS's fixed choice, named once as
# scripts/account_sweep.py AWS_GLOBAL_REGION - never where WARDEN or an application runs.
AWS_GLOBAL = "us-east-1"


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _literals(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstrings(tree)
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip]


def test_no_python_string_in_the_tool_the_scripts_or_the_harness_names_a_region():
    offenders = [f"{p.relative_to(ROOT)}: {m}" for top in ("src/warden", "scripts", "scenarios")
                 for p in (ROOT / top).rglob("*.py") for text in _literals(p) for m in REGION.findall(text)
                 if not (m == AWS_GLOBAL and p.name == "account_sweep.py")]
    assert not offenders, offenders


def test_no_terraform_line_and_no_iam_template_names_a_region():
    offenders = []
    for p in (ROOT / "terraform").rglob("*.tf"):
        if ".terraform" in p.parts:
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            offenders += [f"{p.relative_to(ROOT)}:{i}" for _ in REGION.findall(code)]
    for p in (ROOT / "iam" / "templates").glob("*.json"):
        offenders += [str(p.relative_to(ROOT))] * len(REGION.findall(p.read_text(encoding="utf-8")))
    assert not offenders, offenders


def test_the_region_comes_from_the_config_and_aws_region_overrides_it(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    configured = environments.default_environment_policies().aws_region
    assert configured and environments.region() == configured == environments.names("dev").region
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert environments.region() == "eu-west-1"
    monkeypatch.setenv("AWS_REGION", "not a region; rm -rf /")
    with pytest.raises(environments.EnvironmentPolicyError):
        environments.region()


# ---------------------------------------------------------------- owner, 2026-10-12: nothing in the repository is
# hardcoded. An audit of every tracked code file found no secret and no account number, and these: environment names
# written into scripts and Terraform, the runtime's and the repository's names in the IAM templates, model ids as code
# defaults, the harness's resource names. Each now comes from environments.yaml or providers.yaml; these tests keep it so.

CFG = environments.EnvironmentPolicies.load()
ENV_NAMES = (*CFG.known_environments, CFG.runtime_environment)
ENV_RESOURCE = re.compile("warden-(?:" + "|".join(map(re.escape, ENV_NAMES)) + ")-[a-z0-9]")
MODEL_ID = re.compile(r"\b(?:claude-(?:opus|sonnet|haiku|fable|mythos)|gemini|gpt)-[0-9][\w.-]*")
CODE_DIRS = ("src/warden", "scripts", "scenarios")


def _python_files():
    return [p for top in CODE_DIRS for p in (ROOT / top).rglob("*.py")]


def _code_lines(path: pathlib.Path, comment: str = "#") -> list[str]:
    """A file's lines without their comments (Terraform, YAML, workflows)."""
    return [line.split(comment, 1)[0] for line in path.read_text(encoding="utf-8").splitlines()]


def test_no_code_names_a_resource_of_one_environment():
    """`warden-dev-orders`, `warden-ops-read`: a name with an environment in it is built from the environment."""
    offenders = [f"{p.relative_to(ROOT)}: {m}" for p in _python_files() for text in _literals(p)
                 for m in ENV_RESOURCE.findall(text)]
    # The workflows are held to the same rule where the tests that read them run (tests/test_runtime_pipeline_s9.py).
    for pattern in ("terraform/**/*.tf", "iam/templates/*.json", "scenarios/catalog/*.yaml", "k8s/**/*.yaml"):
        for p in ROOT.glob(pattern):
            if ".terraform" in p.parts:
                continue
            comment = "//" if p.suffix == ".json" else "#"
            offenders += [f"{p.relative_to(ROOT)}:{i}" for i, line in enumerate(_code_lines(p, comment), 1)
                          if ENV_RESOURCE.search(line)]
    assert not offenders, offenders


# A word that is also an environment's name, where it is not one: a tier (`nonprod`/`preprod`/`prod`), a vocabulary
# of common words the checks read, or the environment of a bundled sample incident. Named file by file with why - a
# new file that writes an environment's name is a decision, not a habit.
NOT_AN_ENVIRONMENT = {
    "src/warden/environments.py": ({"prod"}, "the prod TIER, which no fault environment may be"),
    "src/warden/cli.py": ({"prod"}, "the bundled demo incidents' own environment"),
    "src/warden/mcp_server.py": ({"prod"}, "a sample alert in a tool's description"),
    "src/warden/verifier.py": ({"prod", "ops"}, "the prod TIER (P2), and a vocabulary of plain words"),
    "src/warden/reporting.py": ({"prod"}, "the tier ranks"),
    "src/warden/routing.py": ({"prod"}, "the prod TIER, a routing signal that makes a case hard"),
    "src/warden/grounding.py": ({"prod", "dev"}, "a vocabulary of scope words"),
    "src/warden/redaction.py": ({"prod", "dev"}, "a vocabulary of common words never swept as secrets"),
    "scripts/probe_cluster.py": ({"prod"}, "a manual probe's sample alert"),
    "scenarios/runner.py": ({"prod"}, "the dry runs' sample alerts"),
    "scenarios/fullstack_cli.py": ({"prod"}, "the dry run's sample alert"),
    "scenarios/ops_fullstack.py": ({"ops"}, "a result key named `ops`"),
}


def test_no_code_writes_an_environments_name_outside_the_named_exceptions():
    found = {}
    for p in _python_files():
        words = {text for text in _literals(p) if text in ENV_NAMES}
        if words:
            found[str(p.relative_to(ROOT)).replace(chr(92), "/")] = words
    allowed = {path: words for path, (words, _why) in NOT_AN_ENVIRONMENT.items()}
    assert found == allowed, {path: sorted(found.get(path, set()) ^ allowed.get(path, set()))
                              for path in set(found) | set(allowed) if found.get(path) != allowed.get(path)}


def test_where_faults_may_be_injected_is_one_list_in_the_configuration(tmp_path):
    assert CFG.fault_environments and all(CFG.for_env(e).tier != "prod" for e in CFG.fault_environments)
    text = (ROOT / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8")
    for bad in ("fault_environments: [prod]", "fault_environments: [nowhere]", "fault_environments: dev"):
        doc = tmp_path / "e.yaml"
        doc.write_text(re.sub(r"(?m)^fault_environments: .*$", bad, text), encoding="utf-8")
        with pytest.raises(environments.EnvironmentPolicyError):
            environments.EnvironmentPolicies.load(doc)
    from scenarios import region as harness

    assert harness.fault_environment() == CFG.fault_environments[0]
    assert harness.EXAMPLE_ACCOUNT.isdigit() and len(harness.EXAMPLE_ACCOUNT) == 12  # AWS's documentation account


def test_the_repository_is_named_in_the_configuration_and_nowhere_in_code(tmp_path):
    repo, subject = CFG.github["repository"], CFG.github["subject"]
    owner = repo.split("/")[0]
    assert subject.split("@")[0] == owner and subject.split("/")[1].split("@")[0] == repo.split("/")[1]
    for p in [*(ROOT / "iam" / "templates").glob("*.json"), *_python_files()]:
        assert repo not in p.read_text(encoding="utf-8") and subject not in p.read_text(encoding="utf-8"), p.name
    trust = (ROOT / "iam" / "templates" / "trust.json").read_text(encoding="utf-8")
    assert "repo:${github_subject}:environment:${env}" in trust and "${github_repository}/.github/workflows/" in trust
    # Owner, 2026-10-16: each environment deploys from the branch of its own name, the runtime from
    # `github.runtime_branch` - no template names a branch of its own.
    assert trust.count("refs/heads/${env}") == 3
    runtime_trust = (ROOT / "iam" / "templates" / "runtime-trust.json").read_text(encoding="utf-8")
    assert runtime_trust.count("refs/heads/${runtime_branch}") == 2
    literal = [p.name for p in (ROOT / "iam" / "templates").glob("*.json")
               if re.search(r"refs/heads/(?!\$\{(?:env|runtime_branch)\})", p.read_text(encoding="utf-8"))]
    assert not literal, literal
    yaml_text = (ROOT / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8")
    for bad in ("  runtime_branch: main", "  runtime_branch: [dev]", "  runtime_branch: nowhere"):
        doc = tmp_path / "branch.yaml"
        doc.write_text(re.sub(r"(?m)^  runtime_branch: .*$", bad, yaml_text), encoding="utf-8")
        with pytest.raises(environments.EnvironmentPolicyError, match="runtime_branch"):
            environments.EnvironmentPolicies.load(doc)
    rendered = (ROOT / "iam" / CFG.fault_environments[0] / "trust.json").read_text(encoding="utf-8")
    assert f"repo:{subject}:environment:" in rendered and f"{repo}/.github/workflows/" in rendered
    text = (ROOT / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8")
    for bad in ("  repository: not a repository", "  repository: 42"):
        doc = tmp_path / "e.yaml"
        doc.write_text(re.sub(r"(?m)^  repository: .*$", bad, text), encoding="utf-8")
        with pytest.raises(environments.EnvironmentPolicyError):
            environments.EnvironmentPolicies.load(doc)


def test_no_code_names_a_model_and_every_default_is_configuration():
    offenders = [f"{p.relative_to(ROOT)}: {m}" for p in _python_files() for text in _literals(p)
                 for m in MODEL_ID.findall(text)]
    assert not offenders, offenders
    from warden import providers

    defaults = providers.load_qualified()["defaults"]
    assert set(defaults) >= {"anthropic", "claude_cli", "gemini", "openai"}
    assert all(providers.default_model(name) == model for name, model in defaults.items())
    with pytest.raises(providers.ProviderError):
        providers.default_model("no-such-provider")
    # Every provider takes WARDEN_MODEL first and the configured default after - none a default of its own.
    source = (ROOT / "src" / "warden" / "providers.py").read_text(encoding="utf-8")
    assert source.count('os.environ.get("WARDEN_MODEL") or default_model(self.name)') == 4
    assert 'os.environ.get("WARDEN_MODEL", ' not in source


# ---------------------------------------------------------------- audit 2026-10-16: legacy names and region literals in
# any tracked file. `warden-pg` is the Wave 1-3 proving ground's prefix (and `warden-pg-fs` the retired user-era operator
# policy's): a name with no environment in it. Every other name is built from environments.yaml, and a region is
# configuration (R17). The tests above hold Python, Terraform and the IAM templates; this holds everything else that is
# tracked - JSON policies, k8s and workflow YAML, shell, example files. History (docs/, *.md) and test data are out of
# scope. Each exception is named, file by file, with why; a stale one fails too, so retiring the proving ground
# (owner decision pending; it is kept for Wave 1-3 re-runs, R52/R53, 2026-10-02) shrinks this list to nothing.
LEGACY_NAME = re.compile(r"\bwarden-pg\b")
PROVING_GROUND = "the Wave 1-3 proving ground and what drives it, kept for re-runs (R52/R53, owner 2026-10-02)"
LEGACY_OR_REGION_ALLOWED = {
    "src/warden/data/environments.yaml": ({"region"}, "the one place the region is configured"),
    "iam/operator/policy.json": ({"region"}, "the operator's own policy, pasted by the owner, not rendered"),
    "iam/operator/trust.json": ({"region"}, "the operator's Roles Anywhere trust, pasted by the owner, not rendered"),
    "k8s/proving-ground/namespace.yaml": ({"legacy"}, PROVING_GROUND),
    "k8s/proving-ground/rbac.yaml": ({"legacy"}, PROVING_GROUND),
    "scenarios/runner.py": ({"legacy"}, PROVING_GROUND),
    "scripts/aws_proof_bundle.py": ({"legacy"}, PROVING_GROUND),
    "scripts/prove_boundary.py": ({"legacy"}, PROVING_GROUND),
    "scripts/teardown_sweep.py": ({"legacy"}, PROVING_GROUND),
    "terraform/proving-ground/operator-policy-boundary.json": ({"legacy", "region"}, PROVING_GROUND),
    "terraform/proving-ground/operator-policy-rds-eks.json": ({"region"}, PROVING_GROUND),
    "terraform/proving-ground/operator-policy.json": ({"legacy", "region"}, PROVING_GROUND),
    "terraform/proving-ground/terraform.tfvars.example": ({"region"}, PROVING_GROUND),
    "terraform/proving-ground/variables.tf": ({"legacy"}, PROVING_GROUND),
}


def _legacy_and_region(path: pathlib.Path) -> set[str]:
    """{"legacy", "region"} as far as the file names them: Python's string constants (not docstrings), a JSON
    document whole, any other file's lines without their `#` comments."""
    chunks = (_literals(path) if path.suffix == ".py" else [path.read_text(encoding="utf-8")]
              if path.suffix == ".json" else _code_lines(path))
    return ({"legacy"} if any(LEGACY_NAME.search(c) for c in chunks) else set()) | (
        {"region"} if any(REGION.search(c) for c in chunks) else set())


def _scanned_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    rendered = tuple(f"iam/{env}/" for env in ENV_NAMES)  # scripts/render_env_iam.py writes the region into these
    return [f for f in listed.splitlines() if not f.startswith(("docs/", "tests/", *rendered))
            and not f.endswith(".md") and (ROOT / f).is_file()]


def test_no_tracked_file_names_a_legacy_resource_or_a_region_outside_the_named_exceptions():
    found = {}
    for rel in _scanned_files():
        try:
            kinds = _legacy_and_region(ROOT / rel)
        except UnicodeDecodeError:
            continue  # a binary file (an image): nothing to read
        if kinds:
            found[rel] = kinds
    allowed = {path: kinds for path, (kinds, _why) in LEGACY_OR_REGION_ALLOWED.items()}
    assert found == allowed, {path: sorted(found.get(path, set()) ^ allowed.get(path, set()))
                              for path in set(found) | set(allowed) if found.get(path) != allowed.get(path)}


@pytest.mark.parametrize(("name", "plant", "kind"), [
    ("p.json", '{"Resource": "arn:aws:iam::*:role/warden-pg-sweep"}', "legacy"),
    ("p.json", '{"Resource": "arn:aws:ecs:eu-west-1:*:cluster/x"}', "region"),
    ("p.yaml", "roleArn: arn:aws:iam::*:role/warden-pg-fs-reader", "legacy"),
    ("p.sh", "aws ecs list-clusters --region eu-west-1", "region"),
    ("p.py", 'ROLE = "warden-pg-sweep"', "legacy"),
    ("p.json", '{"Resource": "arn:aws-us-gov:ecs:us-gov-west-1:*:cluster/x"}', "region"),
    ("p.sh", "aws ecs list-clusters --region us-iso-east-1", "region"),
    ("p.yaml", "region: eusc-de-east-1", "region"),
    ("p.yaml", "region: cn-north-1", "region"),
])
def test_the_legacy_and_region_scan_catches_a_plant_and_passes_a_comment(tmp_path, name, plant, kind):
    planted = tmp_path / name
    planted.write_text(plant + "\n", encoding="utf-8")
    assert _legacy_and_region(planted) == {kind}, plant
    commented = tmp_path / "c.yaml"
    commented.write_text("# warden-pg-sweep in eu-west-1, a comment\nkey: value\n", encoding="utf-8")
    assert not _legacy_and_region(commented)
