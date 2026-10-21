"""WARDEN's software and model bill of materials, as CycloneDX 1.6 JSON (registers S9, A-P-7).

    python scripts/sbom.py            # writes docs/sbom/warden.cdx.json

Software: every package uv.lock pins, with its version, purl and the sha256 of its source distribution - the hashes
`uv sync --locked` installs against. Models (the ML-BOM): the Prompt Guard 2 revision the tripwire loads, and every
model data/providers.yaml qualified, with its measured result. Deterministic - no timestamp, a serial number derived
from the lock - so tests/test_sbom.py can require the committed file to be exactly a fresh render.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tomllib
import uuid

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "sbom" / "warden.cdx.json"


def _model_status(row: dict, pinned: str | None, bar: dict) -> str:
    """What providers.qualified() would say of the row: qualified only on the pinned prompt and at the bar; a row on an
    earlier prompt, or below the bar, is listed as what it is, never as qualified today."""
    if not pinned or row.get("prompt") != pinned:
        return f"measured on an earlier prompt ({str(row.get('prompt'))[:8]}), NOT qualified on the pinned one"
    if (int(row.get("wrong_and_allowed", 1 << 30)) > int(bar["wrong_and_allowed"])
            or int(row.get("correct", -1)) < int(bar["min_correct"])):
        return "measured on the pinned prompt below the bar, NOT qualified"
    return "qualified on WARDEN's replay set"


def render() -> dict:
    sys.path.insert(0, str(ROOT / "src"))
    from warden import tripwire

    lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    lock = tomllib.loads(lock_text)
    project = next(p for p in lock["package"] if (p.get("source") or {}).get("editable") or
                   (p.get("source") or {}).get("virtual"))
    software = []
    for p in sorted(lock["package"], key=lambda p: p["name"]):
        if p is project:
            continue
        c = {"type": "library", "bom-ref": f"pkg:pypi/{p['name']}@{p['version']}", "name": p["name"],
             "version": p["version"], "purl": f"pkg:pypi/{p['name']}@{p['version']}"}
        # The source distribution's hash; a wheel-only package lists each wheel's.
        files = [p["sdist"]] if p.get("sdist") else p.get("wheels") or []
        digests = sorted({(f.get("hash") or "").removeprefix("sha256:") for f in files} - {""})
        if digests:
            c["hashes"] = [{"alg": "SHA-256", "content": d} for d in digests]
        software.append(c)

    org, name = tripwire.MODEL.split("/", 1)
    models = [{"type": "machine-learning-model", "bom-ref": f"pkg:huggingface/{org}/{name}@{tripwire.REVISION}",
               "name": tripwire.MODEL, "version": tripwire.REVISION,
               "purl": f"pkg:huggingface/{org}/{name}@{tripwire.REVISION}",
               "description": "the injection tripwire (P16): a signal that escalates, never a gate that allows"}]
    providers = yaml.safe_load((ROOT / "src" / "warden" / "data" / "providers.yaml").read_text(encoding="utf-8"))
    pinned = (providers.get("prompt") or {}).get("sha")
    for q in sorted(providers["qualified"], key=lambda q: (q["provider"], q["model"])):
        status = _model_status(q, pinned, providers["bar"])
        models.append({
            "type": "machine-learning-model", "bom-ref": f"model:{q['provider']}/{q['model']}", "name": q["model"],
            "version": q["model"], "supplier": {"name": "Anthropic"},
            "description": f"{status}: {q['correct']} of {q['runs']} correct, "
                           f"{q['wrong_and_allowed']} wrong and allowed (measured {q['measured']})",
            "properties": [{"name": "warden:provider", "value": q["provider"]},
                           {"name": "warden:client", "value": str(q.get("version", ""))}]})
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "warden:" + hashlib.sha256(lock_text.encode()).hexdigest())
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{serial}", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "warden", "name": "warden",
                                   "version": project["version"]}},
        "components": software + models,
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(render(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
