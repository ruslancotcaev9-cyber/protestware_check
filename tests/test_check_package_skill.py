"""Exercise the published skill's local archive entry point without a network."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


STAGER = (Path(__file__).resolve().parents[1] / ".agents" / "skills" /
          "check-package" / "scripts" / "stage_package.py")


class LocalPackageReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "staged"
        self.output.mkdir()
        self.archive = self.root / "sample.zip"
        with zipfile.ZipFile(self.archive, "w") as package:
            package.writestr("sample/label.txt", "sample label\n")

    def stage(self, digest):
        result = subprocess.run(
            [sys.executable, "-I", str(STAGER), "local", str(self.archive),
             "--expect", f"sha256:{digest}", "--workdir", str(self.output)],
            cwd=self.root, capture_output=True, text=True, timeout=15,
        )
        return result.returncode, json.loads(result.stdout)

    def test_match_extracts_expected_content(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        code, receipt = self.stage(digest)
        self.assertEqual((code, receipt["status"], receipt["sha256"]), (0, "staged", digest))
        tree = Path(receipt["tree"])
        self.assertTrue(tree.is_relative_to(self.output))
        self.assertEqual((tree / "sample" / "label.txt").read_bytes(), b"sample label\n")

    def test_mismatch_leaves_output_empty(self):
        code, receipt = self.stage("0" * 64)
        self.assertEqual((code, receipt["status"]), (1, "integrity_mismatch"))
        self.assertEqual(list(self.output.iterdir()), [])
