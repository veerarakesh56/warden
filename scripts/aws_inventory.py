"""Make src/warden/data/aws_inventory.json - what WARDEN itself uses on AWS - from its own Terraform (owner item B6).

    python scripts/aws_inventory.py           # write it
    python scripts/aws_inventory.py --check   # exit 1 when the file is not what the Terraform says now

The AWS updates watch (src/warden/awswatch.py) checks every AWS announcement against this file, and the worker's
image carries no Terraform, so the file is made here and a test (tests/test_awswatch.py) fails when it differs from
the Terraform. Nothing in it is typed by hand:

- services: every `resource "aws_..."` type in terraform/, mapped to awswatch.SERVICES by its prefixes;
- versions: the Lambda runtimes (`runtime = "..."`), the database engines' majors (`engine` with `engine_version`,
  a literal or a variable's default) and the EKS version (`version` of an aws_eks_cluster). A resource whose version
  cannot be read - a variable with no default, a reference, a cluster made by a script with AWS's default version -
  makes its family `unknown`, so the watch never says "not affected" about it;
- regions: AWS's own names (the words its announcements use: "Asia Pacific (Hyderabad)") of environments.yaml's
  `aws_region` and `aws_global_region`, from botocore's endpoint data. Names only: the code of a Region stays in
  environments.yaml, the one place it is configured (tests/test_no_hardcoding_r17.py).
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "warden" / "data" / "aws_inventory.json"
ENGINES = {"postgres": "postgresql", "aurora-postgresql": "postgresql", "redis": "redis", "valkey": "redis"}

_BLOCK = re.compile(r'^\s*(resource|variable)\s+"([\w-]+)"(?:\s+"([\w-]+)")?\s*\{', re.MULTILINE)
_ATTR = r'^\s*{}\s*=\s*(.+?)\s*(?:#.*)?$'
_STRING = re.compile(r'"([^"$]+)"')
_VAR = re.compile(r"\bvar\.(\w+)")
_SCRIPT_ENGINE = re.compile(r'\bEngine="([a-z-]+)"')


def _blocks(text: str) -> list[tuple[str, str, str, str]]:
    """(kind, type, name, body) of each top-level resource and variable block, by brace counting."""
    out = []
    for m in _BLOCK.finditer(text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append((m.group(1), m.group(2), m.group(3) or "", text[m.end():i - 1]))
    return out


def _attr(body: str, name: str) -> str:
    m = re.search(_ATTR.format(re.escape(name)), body, re.MULTILINE)
    return m.group(1) if m else ""


def _value(expr: str, defaults: dict[str, str]) -> str | None:
    """A literal string, or a variable's default (also inside split(...)); None when it cannot be read."""
    if m := _STRING.fullmatch(expr):
        return m.group(1)
    if m := _VAR.search(expr):
        return defaults.get(m.group(1))
    return None


def _major(family: str, version: str) -> str:
    """A database engine's major (`17.10` -> `17`); a runtime or a Kubernetes version as it is."""
    return version.split(".")[0] if family in ("postgresql", "redis") else version


def _add(versions: dict[str, dict], family: str, version: str | None) -> None:
    entry = versions.setdefault(family, {"known": set(), "unknown": False})
    if version:
        entry["known"].add(_major(family, version))
    else:
        entry["unknown"] = True


def _module(directory: pathlib.Path) -> tuple[list[tuple[str, str, str, str]], dict[str, str]]:
    blocks = [b for f in sorted(directory.glob("*.tf")) for b in _blocks(f.read_text(encoding="utf-8"))]
    defaults = {}
    for kind, name, _, body in blocks:
        if kind == "variable" and (m := _STRING.fullmatch(_attr(body, "default"))):
            defaults[name] = m.group(1)
    return blocks, defaults


def _resource_versions(rtype: str, body: str, defaults: dict[str, str], versions: dict[str, dict]) -> None:
    from warden.awswatch import RUNTIME_ID

    if rtype == "aws_lambda_function" and (expr := _attr(body, "runtime")):  # none: an image Lambda, no runtime
        runtime = _value(expr, defaults)
        _add(versions, "runtime", runtime if runtime and RUNTIME_ID.fullmatch(runtime) else None)
    engine = _value(_attr(body, "engine"), defaults)
    if engine in ENGINES and rtype in ("aws_db_instance", "aws_rds_cluster", "aws_elasticache_replication_group",
                                       "aws_elasticache_cluster"):
        _add(versions, ENGINES[engine], _value(_attr(body, "engine_version"), defaults))
    if rtype == "aws_eks_cluster":
        _add(versions, "kubernetes", _value(_attr(body, "version"), defaults))


def _region_names(codes: list[str]) -> list[str]:
    import botocore.session

    data = botocore.session.get_session().get_data("endpoints")
    names = {code: r["description"] for p in data["partitions"] for code, r in p["regions"].items()}
    return [names[c] for c in codes]


def build(root: pathlib.Path = ROOT) -> dict:
    """The inventory, from `root`'s terraform/ and environments.yaml."""
    import yaml

    from warden.awswatch import SERVICES

    types: set[str] = set()
    versions: dict[str, dict] = {}
    tf = root / "terraform"
    for directory in sorted({p.parent for p in tf.rglob("*.tf") if ".terraform" not in p.parts}):
        blocks, defaults = _module(directory)
        for kind, rtype, _, body in blocks:
            if kind == "resource" and rtype.startswith("aws_"):
                types.add(rtype)
                _resource_versions(rtype, body, defaults, versions)
    for script in sorted(tf.rglob("*.py")):  # a cluster a script makes, with AWS's default engine version
        text = script.read_text(encoding="utf-8")
        for engine in _SCRIPT_ENGINE.findall(text):
            if engine in ENGINES and "EngineVersion" not in text:
                _add(versions, ENGINES[engine], None)
    services = sorted(k for k, s in SERVICES.items() if any(t.startswith(s.prefixes) for t in types))
    env = yaml.safe_load((root / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8"))
    return {"made_by": "scripts/aws_inventory.py", "services": services, "resource_types": sorted(types),
            "versions": {f: {"known": sorted(v["known"]), "unknown": v["unknown"]} for f, v in sorted(versions.items())},
            "regions": _region_names([env["aws_region"], env["aws_global_region"]])}


def render(inv: dict) -> str:
    return json.dumps(inv, indent=1, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    text = render(build())
    if "--check" in args:
        same = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("aws_inventory.json is up to date" if same else "aws_inventory.json differs: run scripts/aws_inventory.py")
        return 0 if same else 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
