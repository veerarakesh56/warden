"""Refuse a WARDEN package that holds any file outside an allowlist: the shipped kinds, compared without letter case.

    python scripts/check_package.py <the installed warden package directory, or a .whl>

The build backend has only an exclude list, matched with letter case: a local `SECRET.ENV` or `Prod.TFVARS` under
src/ shipped (registers R8-O4, R9-O1). The image build runs this on what it installed, so such a file fails the build
instead of shipping. Exit 0: clean; 1: files outside the allowlist, listed.
"""

from __future__ import annotations

import pathlib
import sys
import zipfile

ALLOWED = (".py", ".pyc", ".yaml", ".json", ".sha256")
# One file by its exact path, not a kind (review, PR 48): Amazon RDS's public CA bundle, which the terminate login's
# TLS is verified against. It must hold certificates and nothing else (a key in it fails the build).
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


def only_certificates(text: str) -> bool:
    """Every PEM block in `text` is a certificate, and there is at least one."""
    import re

    kinds = re.findall(r"-----BEGIN ([A-Z0-9 ]+)-----", text)
    return bool(kinds) and set(kinds) == {"CERTIFICATE"}


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
