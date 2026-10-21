"""Credential-shaped test fixtures, each built from parts at run time.

2026-10-16: a test that proves a secret is masked needs a value with the secret's
shape, and a literal of that shape in a tracked file is exactly what gitleaks, trufflehog, GitHub push protection
and scripts/check_publishable.py exist to stop. The publish check used to skip seven whole files to make room for
such literals, so a real secret pasted into any of those files would have been published unscanned. Joining the
parts gives the same string at run time, so every assertion keeps its meaning, and no file holds the literal.
tests/test_fixture_literals.py fails the day one comes back.
"""

from __future__ import annotations

# AWS's own documented example key pair (the IAM user guide's "Manage access keys" page): the shape, never a key.
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# An operator's long-lived key id, the one the scenario harness must never pass on to WARDEN.
OPERATOR_ACCESS_KEY_ID = "AKIA" + "OPERATORKEYDONOTUSE"
# An HS256 JWT: header {"alg":"HS256"}, payload {"sub":"1234"}, and a made-up signature segment.
JWT = ".".join(("eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0In0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))
# The stock fake password. Tests add to it, so each fixture stays a distinct value.
HUNTER2 = "hun" + "ter2"
# The prefix every Anthropic API key starts with.
ANTHROPIC_KEY_PREFIX = "sk-" + "ant-"


def private_key_block(kind: str, body: str) -> str:
    """An armoured private key around `body`: "RSA" gives the PEM form, "PGP" the PGP `PRIVATE KEY BLOCK` form."""
    label = f"{kind} PRIVATE KEY" + (" BLOCK" if kind == "PGP" else "")
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def dsn(scheme: str, user: str, password: str, rest: str) -> str:
    """A connection string with its password inline: `scheme://user:<password>@rest`."""
    return f"{scheme}://{user}:" + f"{password}@{rest}"
