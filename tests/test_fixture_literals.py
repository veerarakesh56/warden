"""No file holds a credential-shaped literal: the tests build theirs from parts, in tests/fakes.py.

Naming audit items 5 and 16 (2026-10-16). scripts/check_publishable.py catches the shapes that are real secrets.
This catches the fixture shapes that are not, but that gitleaks, trufflehog and GitHub push protection flag as if
they were: AWS's documented example key, a JWT, an armoured private key, a vendor token prefix with a body, the
stock fake password, and a quoted literal given to a password. Each pattern is written so that it cannot match its
own source, and the finding names the file, the line and the shape - never the value.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

import fakes

ROOT = pathlib.Path(__file__).resolve().parents[1]

SHAPES = {
    "an AWS access key id": r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}",
    "AWS's documented example secret key": "wJalr" + "XUtnFEMI",
    "a JWT": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ",
    "an armoured private key": r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY",
    "a GitHub token": r"\b(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,})",
    "a Slack token": r"\bx(?:ox[abprs]|app)-[A-Za-z0-9-]{6,}",
    "an Anthropic or OpenAI key": r"\bsk-(?:ant|proj)-[A-Za-z0-9_-]{4,}",
    "a Stripe key or webhook secret": r"\b(?:(?:sk|rk|pk)_(?:live|test)|whsec)_[A-Za-z0-9+/=]{6,}",
    "a GitLab token": r"\bgl(?:pat|rt)-[A-Za-z0-9_-]{6,}",
    "an npm, Hugging Face or Google key": r"\b(?:npm_[A-Za-z0-9]{16,}|hf_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,})",
    # Its two spellings, not any case: the constant's own name, HUNTER2, is how the tests say it.
    "the stock fake password string": "[Hh]" + fakes.HUNTER2[1:],
    "a literal password value": r"""(?i)password['"]?\s*[:=]\s*['"][^'"\s<>${}]{3,}['"]""",
    "a literal password in a Kubernetes env entry": r"""(?i)name=['"]\w*password['"],\s*value=['"]""",
    # Owner B28: a made-up secret's value written out (tests/fakes.secret_value builds it).
    "a literal fake secret value": r"""['"][\w-]*secret""" + r"""-value['"]""",
}
PATTERNS = {shape: re.compile(pattern) for shape, pattern in SHAPES.items()}


def _publish_check():
    spec = importlib.util.spec_from_file_location("check_publishable_for_literals", ROOT / "scripts" / "check_publishable.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_file_holds_a_credential_shaped_literal():
    """Every file git tracks, and every new one not yet added - the set the publish check scans, with no exemption."""
    check = _publish_check()
    found = []
    for path in check._tracked_files(staged=False):
        if not path.is_file() or not check._is_text(path):
            continue
        rel = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            found += [f"{rel}:{number}: {shape}" for shape, pattern in PATTERNS.items() if pattern.search(line)]
    assert not found, "build these from parts with tests/fakes.py:\n" + "\n".join(found)


@pytest.mark.parametrize("shape, sample", [
    ("an AWS access key id", fakes.AWS_ACCESS_KEY_ID),
    ("an AWS access key id", fakes.OPERATOR_ACCESS_KEY_ID),
    ("AWS's documented example secret key", fakes.AWS_SECRET_ACCESS_KEY),
    ("a JWT", fakes.JWT),
    ("an armoured private key", fakes.private_key_block("RSA", "body")),
    ("an armoured private key", fakes.private_key_block("PGP", "body")),
    ("a GitHub token", "ghp_" + "A1b2C3d4E5f6G7h8"),
    ("a Slack token", "xoxb-" + "123456789-abc"),
    ("an Anthropic or OpenAI key", fakes.ANTHROPIC_KEY_PREFIX + "api03-x"),
    ("a Stripe key or webhook secret", "whsec_" + "abcdefghij"),
    ("a GitLab token", "glpat-" + "abcDEF123456"),
    ("an npm, Hugging Face or Google key", "npm_" + "a" * 20),
    ("the stock fake password string", fakes.HUNTER2.capitalize() + "Secret"),
    ("a literal password value", 'DB_PASSWORD = "' + "s3cr3t" + '"'),
    ("a literal password in a Kubernetes env entry", 'NS(name="DB_' + 'PASSWORD", value="' + "x" + '")'),
    ("a literal fake secret value", repr(fakes.secret_value("super"))),
])
def test_each_shape_catches_what_it_names_and_the_helper_builds_the_real_shape(shape, sample):
    """A pattern that stopped matching would pass every file; a helper that built the wrong string would make every
    masking test vacuous. Each fixture still has the shape it stands for."""
    assert PATTERNS[shape].search(sample), (shape, sample)


def test_the_helper_builds_what_the_publish_check_calls_a_secret():
    """The redaction and publish tests prove a REAL-looking credential is caught, so the helper's values must be ones
    the publish check would refuse - all but AWS's documented pair, which it deliberately allows by value."""
    check = _publish_check()
    caught = lambda text, name: any(n == name and p.search(text) for n, p, _ in check.PATTERNS)
    assert caught(fakes.private_key_block("RSA", "body"), "private-key")
    assert caught(fakes.dsn("postgresql", "warden", fakes.HUNTER2 + "-x", "db:5432/warden"), "dsn-password")
    assert caught("aws_secret_access_key=" + fakes.AWS_SECRET_ACCESS_KEY, "aws-secret-key")
    assert {fakes.AWS_ACCESS_KEY_ID, fakes.AWS_SECRET_ACCESS_KEY} <= check.ALLOWED
