"""Owner B28: the proving ground's RDS master password never goes on a command line.

`terraform apply -var "db_password=..."` put the password in the terraform process's argv, which any user of the
machine reads (`ps`, /proc/<pid>/cmdline), and a typed `-var` lands in shell history. Terraform reads the value from
TF_VAR_db_password instead, set for the terraform process alone, not exported to everything else the run starts."""

from __future__ import annotations

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROOF = ROOT / "scripts" / "aws_proof.sh"
ON_ARGV = re.compile(r"""-var[ =]+["']?db_password""")


def _tracked() -> list[pathlib.Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / p for p in out.splitlines() if p.endswith((".sh", ".md", ".yml", ".yaml", ".py", ".example", ".tf"))]


def test_no_script_or_doc_puts_the_password_on_a_command_line():
    found = [f"{p.relative_to(ROOT)}:{n}" for p in _tracked() if p.is_file() and p != pathlib.Path(__file__)
             for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), start=1)
             if ON_ARGV.search(line) and not line.lstrip().startswith("#")]
    assert found == [], found


def test_the_harness_hands_the_password_to_terraform_alone():
    text = PROOF.read_text(encoding="utf-8")
    runs = [ln for ln in text.splitlines() if re.search(r"\bterraform -chdir=\S+ (apply|destroy)\b", ln)
            and not ln.lstrip().startswith(("#", "printf"))]
    assert len(runs) == 2, runs  # one apply, one destroy (the teardown)
    for line in runs:
        assert 'TF_VAR_db_password="$DB_PASSWORD" terraform -chdir=' in line, line
    assert not re.search(r"^\s*export\s+TF_VAR_db_password", text, re.MULTILINE)  # not for the whole run
