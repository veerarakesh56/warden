"""Fetch the pinned Z3 release, check its sha256, and unpack the library z3-sys links.

z3-sys's `gh-release` feature downloads Z3 from GitHub at build time with no hash check. Helios
builds without it instead: this script downloads the official release zip, refuses it unless its
sha256 is the one pinned below, and unpacks only the link library into `target/z3/bin`, which
`.cargo/config.toml` hands to z3-sys as `Z3_LIBRARY_PATH_OVERRIDE`. Run it once before `cargo
build` (CI, the Action and the Makefile do):

    python scripts/fetch_z3.py [--dest DIR]

On Linux and macOS only the static `libz3.a` is unpacked, so the binary carries Z3 and needs no
shared library. On Windows it is `libz3.lib` + `libz3.dll`; the DLL is needed at run time, so it is
also copied into `target/debug` and `target/release`, next to `helios.exe` and the test binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import platform
import sys
import urllib.request
import zipfile

VERSION = "4.16.0"
BASE = f"https://github.com/Z3Prover/z3/releases/download/z3-{VERSION}/"
# sha256 of each official release asset, read 2026-10-16 from the GitHub release API's `digest`
# field for tag z3-4.16.0 (published 2026-02-19) and re-computed locally for the x64 Linux and
# Windows zips. Version 4.16.0 is what z3-sys 0.11's bindings are generated for.
PINNED = {
    ("Linux", "x86_64"): (
        "z3-4.16.0-x64-glibc-2.39.zip",
        "7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e",
    ),
    ("Linux", "aarch64"): (
        "z3-4.16.0-arm64-glibc-2.38.zip",
        "87fcd963d3eecb0f12cf1c3ef0ad74e84a3a7bd3caed5d94445645ef94ae6274",
    ),
    ("Darwin", "x86_64"): (
        "z3-4.16.0-x64-osx-15.7.3.zip",
        "d95519c4f3ed9393bb5f996e514c8f177bb148989bdfc32e95587f0307c4e7b0",
    ),
    ("Darwin", "arm64"): (
        "z3-4.16.0-arm64-osx-15.7.3.zip",
        "41828fa07d5cb77bfaee326e8e6dac074f26329c09c633f9e66012bb917cf8ae",
    ),
    ("Windows", "AMD64"): (
        "z3-4.16.0-x64-win.zip",
        "de4d813e47202394a093547dbdb5699ee076529aa853463e007539775cd7e836",
    ),
    ("Windows", "ARM64"): (
        "z3-4.16.0-arm64-win.zip",
        "f98dd099a69ae9784a13eec76eeced12aa733f4f30389b5ddc724c4c21747e94",
    ),
}
# What z3-sys links, per OS. Shared objects are left out on Linux/macOS so the link is static.
WANTED = {"libz3.a", "libz3.lib", "libz3.dll"}
DEFAULT_DEST = pathlib.Path(__file__).resolve().parent.parent / "target" / "z3"


class HashMismatch(Exception):
    pass


def check_sha256(data: bytes, expected: str, name: str) -> None:
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise HashMismatch(f"{name}: sha256 {got}, pinned {expected} -- refusing to use it")


def unpack(data: bytes, dest: pathlib.Path) -> list[str]:
    """Write the archive's `<root>/bin/<wanted>` files to `dest/bin`. Nothing else is written."""
    out = dest / "bin"
    out.mkdir(parents=True, exist_ok=True)
    written = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[1] == "bin" and parts[2] in WANTED:
                (out / parts[2]).write_bytes(z.read(info))
                written.append(parts[2])
    if not written:
        raise SystemExit("no Z3 library found in the archive")
    return sorted(written)


def copy_dll(dest: pathlib.Path) -> None:
    """Windows: put the unpacked libz3.dll next to the debug and release binaries."""
    dll = dest / "bin" / "libz3.dll"
    if not dll.is_file():
        return
    for profile in ("debug", "release"):
        (dest.parent / profile).mkdir(parents=True, exist_ok=True)
        (dest.parent / profile / "libz3.dll").write_bytes(dll.read_bytes())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", type=pathlib.Path, default=DEFAULT_DEST)
    args = ap.parse_args(argv)

    key = (platform.system(), platform.machine())
    if key not in PINNED:
        print(f"no pinned Z3 {VERSION} build for {key}", file=sys.stderr)
        return 1
    asset, sha = PINNED[key]
    stamp = args.dest / "PINNED"
    if stamp.is_file() and stamp.read_text().strip() == sha:
        # A profile dir may have been cleaned on its own: put the DLL back.
        copy_dll(args.dest)
        print(f"Z3 {VERSION} ({asset}, sha256 {sha}) already in {args.dest}")
        return 0
    with urllib.request.urlopen(BASE + asset, timeout=300) as r:  # noqa: S310 (constant https URL)
        data = r.read()
    check_sha256(data, sha, asset)
    files = unpack(data, args.dest)
    copy_dll(args.dest)
    stamp.write_text(sha + "\n")
    print(f"Z3 {VERSION}: {asset} sha256 OK, unpacked {', '.join(files)} to {args.dest / 'bin'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
