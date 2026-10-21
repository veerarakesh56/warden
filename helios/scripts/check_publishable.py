"""Refuse to publish anything that should not leave this machine.

Adapted from WARDEN's scripts/check_publishable.py. It reads what git tracks PLUS new files not yet
`git add`-ed (but not ignored ones), so a run before `git add` sees what the commit will carry:

    python scripts/check_publishable.py            # tracked + untracked, non-ignored files
    python scripts/check_publishable.py --dir path # a directory, e.g. a scrubbed fixture

Exit code 0 means clean. Non-zero means do not push; the output names the file and line.

Why it exists: Helios reads `terraform show -json`. A real plan or state carries the account id in
every ARN, public IPs, and every `sensitive` value (database passwords, `random_password.result`)
in plaintext. The failure mode is one unscrubbed `plan.json` dropped into `fixtures/` and
`git add -A`-ed.
Real Terraform output must go through scripts/scrub_tfjson.py first.

What this cannot do: it scans the working tree, not history, and it cannot recognise a secret that
looks like ordinary text. It is a net with a known mesh size, not a guarantee.
"""

from __future__ import annotations

import argparse
import ipaddress
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Values that LOOK like findings and are not. Every entry needs a reason, because an allowlist is
# how a real leak eventually gets waved through.
ALLOWED = {
    # AWS's documented placeholder account id; every fixture and golden uses it.
    "123456789012",
}

# Files whose PURPOSE is to contain secret-shaped text, each with a reason printed on every run.
# Deliberately tiny and never widened to a directory.
ALLOWED_PATHS: dict[str, str] = {
    "scripts/test_publishable_guards.py":
        "fabricated secrets (a password, random_password.result, a real-shaped account id, a "
        "public IP, env vars) that the tests assert the scrubber REMOVES and this checker "
        "CATCHES. A fixture that did not look real would make both assertions vacuous.",
}

# Files whose mere presence is a failure, whatever they contain. Not allowlistable.
FORBIDDEN_NAMES = re.compile(
    r"(^|/)("
    r"\.env(\..*)?"
    r"|.*\.tfvars"            # real values: an IP, an email, sometimes a password
    r"|.*\.tfstate(\..*)?"    # terraform stores every `sensitive` value in PLAINTEXT here
    r"|tfplan[^/]*|.*\.tfplan|plan\.out"  # a binary plan embeds the same values
    r"|credentials"
    r"|client_secret.*\.json"
    r"|.*\.pem|.*\.p12|.*\.pfx|id_rsa|id_ed25519"
    r"|kubeconfig"
    r")$"
)
# The one deliberate exception: the example file exists to be read.
ALLOWED_NAMES = re.compile(r"\.tfvars\.example$")

# Addresses that are not a finding: private, loopback, unspecified, link-local, and the three
# RFC 5737 documentation ranges.
NON_PUBLIC_V4 = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "127.0.0.0/8", "0.0.0.0/32", "169.254.0.0/16",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
)]

PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "an AWS access key id"),
    ("aws-secret-key", re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     "an AWS secret access key"),
    # \w boundaries, not \d: a hash contains runs of 12 digits between hex letters. A real account
    # id is delimited by non-word characters - the ':' in an ARN, a quote, whitespace.
    ("account-id", re.compile(r"(?<![\w.])\d{12}(?![\w.])"),
     "a 12-digit AWS account id"),
    ("public-ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
     "a public IPv4 address"),
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
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
     "a GitHub token"),
    ("dsn-password", re.compile(r"://[^\s:/@]+:([^\s:/@]{6,})@"),
     "a password inside a connection string"),
    ("bearer", re.compile(r"[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}"),
     "a bearer token"),
]

# Obvious placeholders are not findings. Narrow on purpose, and tested against the VALUE, never the
# whole line - one placeholder on a line must not blind the scan to a real secret beside it.
PLACEHOLDER = re.compile(
    r"(?i)\b(example|placeholder|redacted|dummy|fake|your[-_]?|xxx+|\*{4,}|"
    r"changeme|no-such|does-not-exist|test-only)\b|\$\{|\{\{|<[A-Z_]+>"
)


def _is_public_ipv4(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:  # an octet > 255: a version string, not an address
        return False
    return not any(ip in net for net in NON_PUBLIC_V4)


def _git_files() -> list[pathlib.Path]:
    # `--others --exclude-standard`: new files not yet `git add`-ed are scanned too, so a run BEFORE
    # `git add` - the documented order - does not skip them. `-z`: paths with spaces or non-ASCII.
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout
    return [ROOT / p for p in out.split("\0") if p]


def _walk(directory: pathlib.Path) -> list[pathlib.Path]:
    return [
        p for p in directory.rglob("*")
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
    ]


def _is_text(path: pathlib.Path) -> bool:
    try:
        return b"\0" not in path.read_bytes()[:4096]
    except OSError:
        return False


def scan(paths: list[pathlib.Path], *, root: pathlib.Path,
         skipped: list[str] | None = None) -> list[str]:
    findings: list[str] = []
    skipped = [] if skipped is None else skipped

    for path in paths:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()

        # The ORDER matters: a forbidden name is not allowlistable. ALLOWED_PATHS may excuse
        # secret-SHAPED text in a file meant to hold it; never a .tfstate or a tfplan being there.
        if FORBIDDEN_NAMES.search(rel) and not ALLOWED_NAMES.search(rel):
            findings.append(f"{rel}: this file must never be tracked by git")
            continue
        if rel in ALLOWED_PATHS:
            skipped.append(rel)
            continue
        if not path.exists() or not _is_text(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")

        for number, line in enumerate(text.splitlines(), start=1):
            for name, pattern, human in PATTERNS:
                for match in pattern.finditer(line):
                    value = match.group(1) if match.groups() else match.group(0)
                    if value in ALLOWED or PLACEHOLDER.search(value):
                        continue
                    if name == "public-ipv4" and not _is_public_ipv4(value):
                        continue
                    shown = value if len(value) <= 8 else f"{value[:4]}...{value[-2:]}"
                    findings.append(f"{rel}:{number}: {human} ({name}: {shown})")
    return findings


def main() -> int:
    # Windows consoles default to cp1252 and cannot encode the output; without this the checker
    # would crash precisely when it had findings to print.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", help="scan a directory instead of the git file list")
    args = ap.parse_args()

    if args.dir:
        root = pathlib.Path(args.dir).resolve()
        paths, what = _walk(root), f"files in {root}"
    else:
        root, paths, what = ROOT, _git_files(), "tracked + untracked (non-ignored) files"

    skipped: list[str] = []
    findings = scan(paths, root=root, skipped=skipped)
    print(f"checked {len(paths)} {what}")

    if skipped:
        print(f"\n{len(skipped)} file(s) allowlisted - NOT scanned, and why:")
        for rel in sorted(skipped):
            print(f"  {rel}\n      {ALLOWED_PATHS[rel]}")
        print()

    if not findings:
        print("clean - nothing that must not be published was found")
        print("NOTE: this scans the WORKING TREE, not git history.")
        return 0

    print(f"\n{len(findings)} problem(s) - DO NOT PUSH:\n")
    for finding in findings:
        print(f"  {finding}")
    print("\nIf one is genuinely safe, add it to ALLOWED or ALLOWED_PATHS WITH A REASON.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
