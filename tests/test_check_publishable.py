"""The publishability checker, tested against things it MUST refuse.

A secret scanner that has only ever been shown clean input has not been tested — it has been
admired. Every test here hands it something that must fail, because the day this matters is the day
a real credential is sitting in a file, and "it printed clean" is exactly what a broken scanner does.

The second half tests the *other* failure mode, which is the one that actually kills these tools in
practice: **crying wolf.** A checker that flags ordinary text gets bypassed within a week, and a
bypassed checker is worse than none because it also provides false comfort.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_publishable.py"


def _synth(*parts: str) -> str:
    """Assemble a credential-shaped string at runtime.

    ⛔ These fixtures must look exactly like real credentials, or the scanner they exercise is being
    tested against text that could never fool it. But a literal that looks like a real credential in
    a committed file is itself a finding - GitHub's push protection blocked this very file on a
    fabricated Slack token, which is precisely the behaviour you want from it.

    So the literal never appears in the source. It exists only in memory, and only inside a
    temporary file the checker is pointed at. Both properties are needed and they are not in
    conflict; they just cannot be satisfied by a string literal.
    """
    return "".join(parts)


def _scan(tmp_path: pathlib.Path, name: str, content: str) -> tuple[int, str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dir", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stdout + result.stderr


# --------------------------------------------------------------------------- must REFUSE


@pytest.mark.parametrize(
    "name,content,expect",
    [
        ("keys.txt", "AWS_ACCESS_KEY_ID=" + _synth("AKIA", "2E0RXAMPLE", "Q7WXYZ") + "\n", "access key"),
        ("keys.txt", _synth("ASIA", "2E0RXAMPLE", "Q7WXYZ") + "\n", "access key"),
        ("cfg.yaml", "aws_secret_access_key: " + _synth("aB3dE5gH7jK9lM1nO3pQ", "5rS7tU9vW1xY3zA5bC7d") + "\n", "secret access key"),
        ("run.log", "arn:aws:ecs:ap-south-1:" + _synth("847263", "519048") + ":cluster/prod\n",
         "account id"),
        # ⚠ Deliberately NOT named .pem: that filename is refused by the name rule before the
        # content rule is reached, so a .pem here would assert the wrong half of the scanner.
        ("notes.md", _synth("-----BEGIN ", "RSA PRIVATE KEY", "-----")
         + "\nMIIEpAIBAAKCAQEA\n", "private key"),
        ("hook.txt", _synth("https://hooks.", "slack.com/services/")
         + "T00000000/B00000000/abcdefghijklmnop\n", "Slack"),
        ("tok.txt", _synth("xo", "xb", "-2846013925-3947261508-QwErTyUiOpAsDfGh") + "\n", "Slack token"),
        ("k.txt", _synth("sk-", "ant-", "api03-QwErTyUiOpAsDfGhJkLzXcVbNm1234567890") + "\n", "Anthropic"),
        ("k.txt", _synth("AI", "za", "SyD9fK2mQ7xR4tV6wY8zB1cE3gH5jL7nP9r") + "\n", "Google"),
        ("k.txt", _synth("gs", "k_", "QwErTyUiOpAsDfGhJkLzXcVbNm1234567890QwErTyUi") + "\n", "Groq"),
        ("k.txt", _synth("gh", "p_", "QwErTyUiOpAsDfGhJkLzXcVbNm1234567890") + "\n", "GitHub"),
        ("dsn.txt", "postgresql://warden:" + _synth("Tr0ub4", "dor3xK9") + "@db.internal:5432/orders\n", "connection string"),
        ("h.txt", "Authorization: Bearer " + _synth("eyJhbGciOiJIUzI1NiIs", "InR5cCI6IkpXVCJ9") + "\n", "bearer"),
    ],
)
def test_a_real_secret_is_refused(tmp_path, name, content, expect):
    code, out = _scan(tmp_path, name, content)
    assert code != 0, f"scanner passed something it must refuse:\n{out}"
    assert expect.lower() in out.lower(), out


@pytest.mark.parametrize(
    "name",
    [".env", ".env.production", "terraform.tfvars", "prod.tfvars",
     "terraform.tfstate", "terraform.tfstate.backup", "id_rsa", "server.pem", "kubeconfig"],
)
def test_a_forbidden_file_is_refused_even_when_empty(tmp_path, name):
    """⛔ Content-blind on purpose. A tfstate carries every `sensitive` value in PLAINTEXT, and an
    empty one today is a full one tomorrow. The filename alone is the finding."""
    code, out = _scan(tmp_path, name, "")
    assert code != 0, f"{name} was accepted:\n{out}"
    assert "must never be tracked" in out


def test_the_tfvars_example_is_the_one_permitted_exception(tmp_path):
    code, out = _scan(tmp_path, "terraform.tfvars.example", 'region = "ap-south-1"\n')
    assert code == 0, out


def test_an_allowlisted_path_cannot_excuse_a_forbidden_FILE(tmp_path):
    """The ordering guard. A path allowlist may excuse secret-shaped TEXT inside a file meant to
    contain it; it must never excuse a .env being tracked at all. If this ever inverts, the
    allowlist becomes a way to smuggle a credentials file into the repo."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("cp", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for allowed in module.ALLOWED_PATHS:
        assert not module.FORBIDDEN_NAMES.search(allowed), (
            f"{allowed} is both allowlisted and forbidden - the ordering must be checked by hand"
        )


# --------------------------------------------------------------------------- must ACCEPT


@pytest.mark.parametrize(
    "content",
    [
        "the deployment finished at 1757400000000 ms\n",          # a 13-digit epoch
        "checked 82 files tracked by git\n",
        "resources = [\"*\"]\n",
        "postgresql://warden:<REDACTED>@db:5432/warden\n",
        "arn:aws:ecs:ap-south-1:<ACCOUNT>:cluster/prod\n",         # already redacted
        "AKIAIOSFODNN7EXAMPLE\n",                                  # AWS's documented example
        "password = var.db_password\n",                            # a reference, not a value
        "postgresql://user:${DB_PASSWORD}@host:5432/db\n",         # interpolated
        "set the value to your-password-here\n",
    ],
)
def test_ordinary_text_is_not_flagged(tmp_path, content):
    """Crying wolf is the failure mode that actually kills these tools. A checker that flags
    ordinary lines gets bypassed within a week, and a bypassed checker also provides false comfort."""
    code, out = _scan(tmp_path, "notes.md", content)
    assert code == 0, f"false positive on {content!r}:\n{out}"


def test_a_binary_file_does_not_crash_it(tmp_path):
    (tmp_path / "blob.bin").write_bytes(bytes(range(256)) * 8)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dir", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_it_reports_what_it_allowlisted_rather_than_skipping_quietly(tmp_path):
    """A silent allowlist is how a real leak gets waved through. Every run prints what it skipped
    and why, so the list is argued with rather than forgotten."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert "allowlisted" in result.stdout
    assert "redaction module documenting" in result.stdout


def test_the_repository_as_it_stands_is_publishable():
    """The check that matters. Runs against what git actually tracks - not what anyone intended to
    track - so it answers 'what is really on GitHub' rather than 'what did I mean to put there'."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- the blinding bug
#
# ⛔ A placeholder used to suppress every finding on its LINE rather than just itself. Redaction
# writes `<ACCOUNT>` into exactly the lines that carry ARNs, so redacting an account id switched off
# scanning for any real credential sitting beside it - and a JSON report is usually a single line,
# so one `<ACCOUNT>` blinded the entire file.
#
# That defeated the only guarantee this script offers. "The redactor ran" and "the redactor worked"
# are different claims, and the second had quietly stopped being checked.


def test_a_redacted_placeholder_does_not_hide_a_real_secret_beside_it(tmp_path):
    key = _synth("AKIA", "IOSFODNN", "7NOTREAL")
    code, out = _scan(
        tmp_path, "report.json",
        '{"arn":"arn:aws:ecs:ap-south-2:<ACCOUNT>:cluster/x","key":"' + key + '"}\n',
    )
    assert code != 0, "a real AWS key was waved through because <ACCOUNT> was on the same line"
    assert "AKIA" in out


def test_a_placeholder_value_is_still_allowed(tmp_path):
    """The rule has to keep working for what it was written for: the VALUE being a placeholder."""
    code, _ = _scan(tmp_path, "conf.yaml", 'aws_access_key_id: <YOUR_KEY_HERE>\n')
    assert code == 0


def test_a_single_line_json_report_is_scanned_all_the_way_along(tmp_path):
    """The realistic shape. A benchmark report is one line with many fields, and only the first
    account id becomes a placeholder."""
    key = _synth("AKIA", "IOSFODNN", "7NOTREAL")
    dsn = "postgres://user:" + _synth("hun", "ter", "2") + "@db.example.com:5432/app"
    code, out = _scan(
        tmp_path, "one-line.json",
        '{"a":"arn:aws:iam::<ACCOUNT>:role/r","b":"111122223333","c":"' + key + '",'
        '"d":"' + dsn + '"}\n',
    )
    assert code != 0
    assert "AKIA" in out, "the key later in the line was not reached"
    assert "dsn-password" in out, "the DSN password even later in the line was not reached"
