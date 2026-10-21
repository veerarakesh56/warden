"""Refuse a WARDEN package that holds any file outside an allowlist: the shipped kinds, compared without letter case.

    python scripts/check_package.py <the installed warden package directory, or a .whl>

The build backend has only an exclude list, matched with letter case: a local `SECRET.ENV` or `Prod.TFVARS` under
src/ shipped (registers R8-O4, R9-O1). The image build runs this on what it installed, so such a file fails the build
instead of shipping. Exit 0: clean; 1: files outside the allowlist, listed.
"""

from __future__ import annotations

import pathlib
import re
import sys
import zipfile

ALLOWED = (".py", ".pyc", ".yaml", ".json", ".sha256")
# One file by its exact path, not a kind (review, PR 48): Amazon RDS's public CA bundle, which every database login's
# TLS (reads and the terminate login) is verified against. It must hold certificates and nothing else (a key in it fails the build).
CERTIFICATES = ("data/rds-ca-bundle.crt", "warden/data/rds-ca-bundle.crt")
# The package's own metadata in a wheel.
DIST_INFO = ("METADATA", "RECORD", "WHEEL", "entry_points.txt", "licenses/LICENSE")


def outside(names: list[str]) -> list[str]:
    bad = []
    for name in names:
        parts = name.replace("\\", "/").split("/")
        if parts[0].endswith(".dist-info") and "/".join(parts[1:]) in DIST_INFO:
            continue
        if "/".join(parts) in CERTIFICATES:
            continue
        if not name.lower().endswith(ALLOWED) or any(p.startswith(".") for p in parts):
            bad.append(name)
    return bad


_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]++)-----END CERTIFICATE-----\s*+")


def _x509(body: str) -> bool:
    """`body` (a PEM block's base64) decodes to one X.509 certificate OpenSSL parses (review, PR 48: `AA==` is base64,
    not a certificate). Loaded into a throwaway trust store - the same parser verify-full's trust store uses."""
    import base64
    import binascii
    import ssl

    try:
        der = base64.b64decode("".join(body.split()), validate=True)
        ssl.create_default_context(cadata=der)  # a DER certificate, parsed; ValueError/SSLError when it is not one
    except (binascii.Error, ValueError, ssl.SSLError):
        return False
    return True


def only_certificates(text: str) -> bool:
    """`text` is one or more complete CERTIFICATE blocks - each with its END line and a body that parses as an X.509
    certificate - and nothing after them but whitespace (review, PR 48: a lone BEGIN line or text after a block
    passed). Plain text before the first block, which RFC 7468 allows and PEM readers skip, is the bundle's
    provenance; it holds no `-----`."""
    start = text.find("-----")
    if start < 0:
        return False
    at = start
    while at < len(text):
        block = _CERTIFICATE.match(text, at)
        if not block or not _x509(block.group(1)):
            return False
        at = block.end()
    return True


def main(argv: list[str] | None = None) -> int:
    target = pathlib.Path((argv or sys.argv[1:])[0])
    if target.suffix == ".whl":
        with zipfile.ZipFile(target) as whl:
            names = [n for n in whl.namelist() if not n.endswith("/")]
    else:
        names = [p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()]
    bad = outside(names)
    for name in names:
        if name.replace("\\", "/") in CERTIFICATES:
            text = (zipfile.ZipFile(target).read(name).decode("ascii", "replace") if target.suffix == ".whl"
                    else (target / name).read_text(encoding="ascii", errors="replace"))
            if not only_certificates(text):
                bad.append(name)
    for name in bad:
        print(f"not a shipped kind of file: {name}")
    print("clean" if not bad else f"{len(bad)} file(s) outside the allowlist {', '.join(ALLOWED)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
