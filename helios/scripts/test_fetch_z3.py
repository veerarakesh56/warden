"""fetch_z3.py refuses an archive whose sha256 is not the pinned one, and unpacks only the library.

    python -m unittest discover -s scripts
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import platform
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import fetch_z3  # noqa: E402


def archive(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class FetchZ3(unittest.TestCase):
    def test_a_tampered_archive_is_refused(self):
        data = archive({"z3/bin/libz3.a": b"genuine"})
        pinned = hashlib.sha256(data).hexdigest()
        fetch_z3.check_sha256(data, pinned, "z3.zip")
        tampered = archive({"z3/bin/libz3.a": b"tampered"})
        with self.assertRaises(fetch_z3.HashMismatch):
            fetch_z3.check_sha256(tampered, pinned, "z3.zip")

    def test_only_the_link_library_is_unpacked(self):
        data = archive({
            "z3/bin/libz3.a": b"a",
            "z3/bin/libz3.so": b"so",
            "z3/include/z3.h": b"h",
            "z3/bin/../../evil/libz3.a": b"x",
        })
        with tempfile.TemporaryDirectory() as d:
            written = fetch_z3.unpack(data, pathlib.Path(d))
            self.assertEqual(written, ["libz3.a"])
            files = sorted(p.relative_to(d).as_posix() for p in pathlib.Path(d).rglob("*"))
            self.assertEqual(files, ["bin", "bin/libz3.a"])

    def test_an_already_fetched_z3_still_puts_the_dll_back_in_cleaned_profiles(self):
        key = (platform.system(), platform.machine())
        if key not in fetch_z3.PINNED:
            self.skipTest(f"no pin for {key}")
        with tempfile.TemporaryDirectory() as d:
            dest = pathlib.Path(d) / "target" / "z3"
            (dest / "bin").mkdir(parents=True)
            (dest / "bin" / "libz3.dll").write_bytes(b"dll")
            (dest / "PINNED").write_text(fetch_z3.PINNED[key][1] + "\n")
            self.assertEqual(fetch_z3.main(["--dest", str(dest)]), 0)  # no download: stamp matches
            for profile in ("debug", "release"):
                self.assertEqual((dest.parent / profile / "libz3.dll").read_bytes(), b"dll")

    def test_every_pin_is_a_4_16_0_zip_with_a_sha256(self):
        for key in [("Linux", "x86_64"), ("Windows", "AMD64")]:
            self.assertIn(key, fetch_z3.PINNED)
        for asset, sha in fetch_z3.PINNED.values():
            self.assertTrue(asset.startswith(f"z3-{fetch_z3.VERSION}-") and asset.endswith(".zip"))
            self.assertRegex(sha, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
