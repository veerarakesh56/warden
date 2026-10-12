"""Owner requirements R17 and R32: the AWS region is configuration (environments.yaml `aws_region`), never a literal in
code - not in Python, not in Terraform, not in the IAM templates."""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from warden import environments

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGION = re.compile(r"\b[a-z]{2}-(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d\b")
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
    "src/warden/grounding.py": ({"prod", "staging", "dev"}, "a vocabulary of scope words"),
    "src/warden/redaction.py": ({"prod", "staging", "dev"}, "a vocabulary of common words never swept as secrets"),
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
