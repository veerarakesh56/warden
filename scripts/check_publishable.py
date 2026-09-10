"""Refuse to publish anything that should not leave this machine.

Run it before a commit, after a commit, and after a push — it reads what git actually tracks, so it
tells you what is *really* on GitHub rather than what you meant to put there:

    python scripts/check_publishable.py            # every file git tracks
    python scripts/check_publishable.py --dir path # a proof bundle, before copying it in
    python scripts/check_publishable.py --staged   # only what is about to be committed

Exit code 0 means clean. Non-zero means do not push, and the output says which file and which line.

⛔ WHY THIS EXISTS RATHER THAN A CAREFUL HABIT. A benchmark run against a real AWS account produces
a transcript full of ARNs, and every ARN contains the 12-digit account id. The RDS DSN carries a
master password. A Slack webhook URL is a credential that needs no username. None of those are
catastrophic alone, and all of them are free reconnaissance for somebody else. The failure mode is
not dramatic — it is one aborted run leaving one unredacted log file in a directory that later gets
`git add -A`-ed.

⚠ **What this cannot do.** It scans the working tree, not history. If a secret was committed and
later removed, this passes while the secret is still in the repository forever — for that, the only
real answer is to rotate the credential and rewrite history. It also cannot recognise a secret that
looks like ordinary text. It is a net with a known mesh size, not a guarantee.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Values that LOOK like findings and are not. Every entry needs a reason, because an allowlist is
# how a real leak eventually gets waved through.
ALLOWED = {
    # AWS's own documented example credentials, used in tests/test_redaction.py to prove the
    # redactor catches the shape. Published by AWS in their public documentation.
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # Reserved documentation account ids (RFC-style placeholders used throughout AWS docs).
    "111122223333",
    "123456789012",
    "999988887777",
    # The placeholder in the redaction output itself.
    "<ACCOUNT>",
}

# Files whose PURPOSE is to contain secret-shaped text. Allowlisted by path, each with a reason,
# and the reasons are printed on every run.
#
# ⛔ This is the dangerous part of the file. A path allowlist is how a real secret eventually gets
# waved through, so it is deliberately tiny, it is never widened to a directory, and every entry
# below was verified by opening the file rather than by trusting the filename.
ALLOWED_PATHS: dict[str, str] = {
    ".github/workflows/ci.yml":
        "service-container DSNs bound to 127.0.0.1 inside an ephemeral runner that is destroyed "
        "with the job. `sa:Warden!Passw0rd1` is MSSQL's complexity requirement, not a secret.",
    "src/warden/redaction.py":
        "the redaction module documenting the credential shapes it masks.",
    "tests/test_redaction.py":
        "fixtures that MUST look like real credentials - a redactor tested against text that does "
        "not resemble a secret proves nothing.",
    "tests/integration/test_live_database.py":
        "a docstring listing localhost dev DSNs for the optional live-database run.",
    "tests/test_aws_proof_bundle.py":
        "a fabricated DSN password used to prove the evidence bundle masks one. Same reason as "
        "test_redaction.py: the fixture has to look real or the assertion is vacuous.",
}

# Files whose mere presence in git is a failure, whatever they contain.
FORBIDDEN_NAMES = re.compile(
    r"(^|/)("
    r"\.env(\..*)?"
    r"|.*\.tfvars"            # real values: an IP, an email, sometimes a password
    r"|.*\.tfstate(\..*)?"    # ⛔ terraform stores every `sensitive` value in PLAINTEXT here
    r"|credentials"
    r"|client_secret.*\.json"
    r"|.*\.pem|.*\.p12|.*\.pfx|id_rsa|id_ed25519"
    r"|kubeconfig"
    r")$"
)
# The one deliberate exception: the example file exists to be read.
ALLOWED_NAMES = re.compile(r"\.tfvars\.example$")

PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "an AWS access key id"),
    ("aws-secret-key", re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     "an AWS secret access key"),
    # Boundaries are \w, not \d: a SHA256 in a .terraform.lock.hcl contains runs of 12 digits
    # surrounded by hex letters, and a digit-only boundary flagged every provider hash. A real
    # account id is always delimited by non-word characters - the ':' in an ARN, or whitespace.
    ("account-id", re.compile(r"(?<![\w.])\d{12}(?![\w.])"),
     "a 12-digit AWS account id"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "a private key"),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/\S+"),
     "a Slack incoming-webhook URL, which is a credential on its own"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
     "a Slack token"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
     "an Anthropic API key"),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}"),
     "an OpenAI API key"),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "a Google API key"),
    ("groq-key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}"),
     "a Groq API key"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
     "a GitHub token"),
    ("dsn-password", re.compile(r"://[^\s:/@]+:([^\s:/@]{6,})@"),
     "a password inside a connection string"),
    ("bearer", re.compile(r"[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}"),
     "a bearer token"),
]

# Anything that is obviously a placeholder is not a finding. Keeping this narrow on purpose: a
# generous placeholder rule is how a real value gets excused.
PLACEHOLDER = re.compile(
    r"(?i)\b(example|placeholder|redacted|dummy|fake|your[-_]?|xxx+|\*{4,}|"
    r"changeme|no-such|does-not-exist|test-only)\b|\$\{|\{\{|<[A-Z_]+>"
)

TEXT_SUFFIXES = {
    ".py", ".md", ".yaml", ".yml", ".json", ".tf", ".tfvars", ".sh", ".toml", ".cfg", ".ini",
    ".txt", ".log", ".env", ".hcl", ".lock", ".example", ".dockerfile", ".gitignore", "",
}


def _tracked_files(staged: bool) -> list[pathlib.Path]:
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if staged else \
          ["git", "ls-files"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / line for line in out.splitlines() if line.strip()]


def _walk(directory: pathlib.Path) -> list[pathlib.Path]:
    return [
        p for p in directory.rglob("*")
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
    ]


def _is_text(path: pathlib.Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        chunk = path.read_bytes()[:2048]
    except OSError:
        return False
    return b"\0" not in chunk


def scan(paths: list[pathlib.Path], *, root: pathlib.Path,
         skipped: list[str] | None = None) -> list[str]:
    findings: list[str] = []
    skipped = [] if skipped is None else skipped

    for path in paths:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = str(path)

        if FORBIDDEN_NAMES.search(rel) and not ALLOWED_NAMES.search(rel):
            findings.append(f"{rel}: this file must never be tracked by git")
            continue

        # ⛔ Note the ORDER: the forbidden-name check runs FIRST and is not allowlistable. A path
        # allowlist may excuse secret-SHAPED text inside a file that is meant to contain it; it may
        # never excuse a .env or a .tfstate being tracked at all.
        if rel in ALLOWED_PATHS:
            skipped.append(rel)
            continue

        if not path.exists() or not _is_text(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for number, line in enumerate(text.splitlines(), start=1):
            for name, pattern, human in PATTERNS:
                for match in pattern.finditer(line):
                    value = match.group(1) if match.groups() else match.group(0)
                    if value in ALLOWED:
                        continue
                    # ⛔ THE VALUE, NOT THE LINE. This used to test the whole line, which meant one
                    # placeholder anywhere on a line suppressed EVERY finding on it - and redaction
                    # writes `<ACCOUNT>` into exactly those lines. So redacting an account id turned
                    # off scanning for the real credential sitting beside it, and a JSON report is
                    # usually one line, so a single `<ACCOUNT>` blinded the whole file.
                    #
                    # That defeated the one guarantee this script exists to give: "the redactor ran"
                    # and "the redactor worked" are different claims, and the second was no longer
                    # being checked. Found by planting an AWS key next to an ARN and watching the
                    # publish step wave it through.
                    if PLACEHOLDER.search(value):
                        continue
                    shown = value if len(value) <= 8 else f"{value[:4]}...{value[-2:]}"
                    findings.append(f"{rel}:{number}: {human} ({name}: {shown})")
    return findings


def main() -> int:
    # ⛔ Windows consoles default to cp1252 and CANNOT encode the characters below. Without
    # this, the checker crashes *while printing its findings* - it would die precisely when it
    # had something to report, and anyone reading the tail of the output would see a traceback
    # rather than a leak. Found by running it, not by reading it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--dir", help="scan a directory instead of the git index")
    group.add_argument("--staged", action="store_true", help="scan only what is staged for commit")
    args = ap.parse_args()

    if args.dir:
        root = pathlib.Path(args.dir).resolve()
        paths, what = _walk(root), f"directory {root}"
    else:
        root = ROOT
        paths = _tracked_files(args.staged)
        what = "files staged for commit" if args.staged else "files tracked by git"

    skipped: list[str] = []
    findings = scan(paths, root=root, skipped=skipped)
    print(f"checked {len(paths)} {what}")

    if skipped:
        print(f"\n{len(skipped)} file(s) allowlisted - these are NOT scanned, and why:")
        for rel in sorted(skipped):
            print(f"  {rel}\n      {ALLOWED_PATHS[rel]}")
        print()

    if not findings:
        print("clean - nothing that must not be published was found")
        print("NOTE: this scans the WORKING TREE, not git history. A secret committed and later")
        print("      removed is still in the repo; rotate the credential and rewrite history.")
        return 0

    print(f"\n⛔ {len(findings)} problem(s) - DO NOT PUSH:\n")
    for finding in findings:
        print(f"  {finding}")
    print("\nIf one of these is genuinely safe, add it to ALLOWED in this file WITH A REASON.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
