"""Deterministic graph fixtures; no package installation, external requests, or code execution."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import dependency_analysis as dep
import protestware_check as scanner
import threat_intel


class LockGraphTests(unittest.TestCase):
    def inventory(self, entries, **kwargs):
        return dep.analyze_dependencies(entries, **kwargs)

    def test_npm_v3_transitive_ancestry_scopes_and_nested_version(self):
        doc = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"app": "1.0.0"}},
            "node_modules/app": {"version": "1.0.0", "dependencies": {"@s/mid": "^2", "leaf": "^1"}},
            "node_modules/@s/mid": {"version": "2.1.0", "dependencies": {"leaf": "^2"}},
            "node_modules/leaf": {"version": "1.9.0"},
            "node_modules/@s/mid/node_modules/leaf": {"version": "2.0.0", "resolved": "git+https://github.com/owner/leaf.git#123"}
        }}
        result = self.inventory({"package-lock.json": json.dumps(doc)}, mode="lock")
        found = result["packages"]
        self.assertEqual(len(found), 4)
        self.assertTrue(result["summary"]["complete"])
        levels = {(p["name"], p["version"]): p["depth"] for p in found}
        self.assertEqual(levels, {("app", "1.0.0"): 1, ("@s/mid", "2.1.0"): 2,
                                  ("leaf", "1.9.0"): 2, ("leaf", "2.0.0"): 3})
        self.assertIn(("owner/leaf", "package-lock.json", 0, "npm:leaf@2.0.0 -> owner/leaf"), result["references"])

    def test_npm_v1_recursive_dependency(self):
        doc = {"lockfileVersion": 1, "dependencies": {"parent": {
            "version": "1.1.0", "dependencies": {"child": {"version": "3.0.0"}}
        }}}
        files = {"package.json": '{"dependencies":{"parent":"1.1"}}', "package-lock.json": json.dumps(doc)}
        result = self.inventory(files, mode="lock")
        self.assertEqual({p["name"]: p["depth"] for p in result["packages"]}, {"parent": 1, "child": 2})

    def test_npm_lock_missing_node_marks_incomplete(self):
        doc = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"one": "1"}},
            "node_modules/one": {"version": "1.0.0", "dependencies": {"missing": "1"}}}}
        report = self.inventory({"package-lock.json": json.dumps(doc)}, mode="lock")
        self.assertFalse(report["summary"]["complete"])
        self.assertIn("missing", " ".join(report["summary"]["warnings"]))

    def test_npm_v2_does_not_duplicate_legacy_section(self):
        doc = {"lockfileVersion": 2, "packages": {"": {"dependencies": {"x": "1"}},
          "node_modules/x": {"version": "1.0.0"}}, "dependencies": {"x": {"version": "1.0.0"}}}
        self.assertEqual(self.inventory({"package-lock.json": json.dumps(doc)}, mode="lock")["summary"]["count"], 1)

    def test_poetry_and_uv_lock(self):
        uv = '''[[package]]
name = "root"
version = "0.1"
source = { editable = "." }
[[package]]
name = "httpx"
version = "0.28.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "certifi"
version = "2025.1"
source = { git = "https://github.com/certifi/python-certifi" }
'''
        poetry = '''[[package]]
name = "other"
version = "3.0.0"
source = { type = "git", url = "https://github.com/sample/other.git", reference = "main" }
'''
        result = self.inventory({"a/uv.lock": uv, "b/poetry.lock": poetry,
                                  "a/pyproject.toml": '[project]\ndependencies = ["httpx>=0.27"]'}, mode="lock")
        self.assertEqual({p["name"] for p in result["packages"]}, {"httpx", "certifi", "other"})
        self.assertIn("sample/other", {r[0] for r in result["references"]})
        self.assertTrue(next(p for p in result["packages"] if p["name"] == "httpx")["direct"])

    def test_pep751_pylock(self):
        text = '''[[packages]]
name = "foo"
version = "1.0"
[packages.vcs]
url = "git+https://github.com/demo/foo"
'''
        result = self.inventory({"pylock.toml": text}, mode="lock")
        self.assertEqual(result["packages"][0]["repository"], "demo/foo")

    def test_go_cargo_composer(self):
        manifest = {
            "go.sum": "github.com/acme/mod v1.2.0 h1:" + "A" * 43 + "=\ngithub.com/acme/mod v1.2.0/go.mod h1:" + "A" * 43 + "=",
            "Cargo.lock": '[[package]]\nname="crate"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="gitcrate"\nversion="0.1"\nsource="git+https://github.com/a/crate#00"',
            "composer.lock": json.dumps({"packages": [{"name": "vendor/lib", "version": "v1.0", "source": {"type": "git", "url": "https://github.com/vendor/lib.git"}}]})
        }
        report = self.inventory(manifest, mode="lock")
        self.assertEqual(report["summary"]["count"], 4)
        self.assertNotIn("rust-lang/crates.io-index", {r[0] for r in report["references"]})
        self.assertEqual({r[0] for r in report["references"]}, {"acme/mod", "a/crate", "vendor/lib"})

    def test_pnpm_lock_v9_transitive(self):
        lock = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      parent:
        specifier: ^1.0
        version: 1.0.0
packages:
  parent@1.0.0:
    resolution: {integrity: sha512-test}
  child@2.0.0:
    resolution: {tarball: 'git+https://github.com/acme/child.git'}
snapshots:
  parent@1.0.0:
    dependencies:
      child: 2.0.0
  child@2.0.0: {}
"""
        data = self.inventory({"pnpm-lock.yaml": lock}, mode="lock")
        self.assertEqual({p["name"]: p["depth"] for p in data["packages"]}, {"parent": 1, "child": 2})
        self.assertTrue(data["summary"]["complete"])
        self.assertIn("acme/child", {r[0] for r in data["references"]})

    def test_missing_lockfile_reports_partial_without_network(self):
        with patch.object(dep, "official_json", side_effect=AssertionError("network forbidden")):
            report = self.inventory({"package.json": '{"dependencies": {"thing": "^1"}}'}, mode="lock")
        self.assertFalse(report["summary"]["complete"])
        self.assertIn("No npm lockfile", " ".join(report["summary"]["warnings"]))

    def test_package_limits_are_explicit(self):
        doc = {"lockfileVersion": 3, "packages": {"": {}, **{
            f"node_modules/pkg{i}": {"version": "1.0.0"} for i in range(20)}}}
        data = self.inventory({"package-lock.json": json.dumps(doc)}, max_packages=5, mode="lock")
        self.assertEqual(data["summary"]["count"], 5)
        self.assertFalse(data["summary"]["complete"])

    def test_watchlist_match_transitive_record_provenance(self):
        doc = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"a": "1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
            "node_modules/b": {"version": "1.0.0", "resolved": "git+https://github.com/owner/flagged.git"}
        }}
        toxic = {"black": set(), "toxic": {"owner/flagged": [{"id": 42, "type": "malware", "link": "https://github.com/owner/flagged"}]},
                 "metadata": {"mode": "offline"}}
        report = scanner.build_report("test", [("package-lock.json", json.dumps(doc))], [], [], [], watchlists=toxic)
        found = next(x for x in report["findings"] if x["rule"] == "TOXIC_REPO")
        self.assertEqual(found["matched_packages"][0]["name"], "b")
        self.assertIn("a@1.0.0", found["matched_packages"][0]["via"])
        self.assertEqual(found["matched_packages"][0]["direct"], False)

    def test_purl_registry_package_match(self):
        text = json.dumps([{"id": 2, "problem_type": "malware", "name": "some thing",
                            "PURL": "pkg:pypi/sample_pkg@1.0"},
                           {"id": 3, "PURL-link": "https://www.npmjs.com/package/@scope/a"}])
        matches = threat_intel.parse_toxic_packages(text)
        self.assertIn(("pypi", "sample-pkg"), matches)
        self.assertIn(("npm", "@scope/a"), matches)
        found = threat_intel.match_packages([{"ecosystem": "pypi", "name": "sample-pkg", "version": "2.0", "manifest": "x", "direct": False}], {"packages": matches})
        self.assertEqual(found, [])

    def test_off_mode_honors_default(self):
        result = self.inventory({"package.json": "bad"}, mode="off")
        self.assertEqual(result["summary"]["count"], 0)

    def test_strict_cli_incomplete_returns_error_code_two(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "package.json").write_text('{"dependencies":{"n":"^1"}}')
            with patch("sys.stdout"):
                status = scanner.main(["--path", directory, "--dependencies", "lock", "--dependency-strict"])
            self.assertEqual(status, 2)


class RegistryTests(unittest.TestCase):
    def fixture(self, url):
        if "registry.npmjs.org" in url:
            if url.endswith("/parent"):
                return {"versions": {"1.0.0": {}, "1.1.0": {}}}
            if url.endswith("/parent/1.1.0"):
                return {"repository": {"type": "git", "url": "https://github.com/test/parent"},
                        "dependencies": {"child": "^2.0.0"}}
            if url.endswith("/child"):
                return {"versions": {"1.0.0": {}, "2.1.0": {}}}
            if url.endswith("/child/2.1.0"):
                return {"repository": "git+https://github.com/test/child.git", "dependencies": {}}
        raise AssertionError(url)

    def test_registry_transitive_npm_without_installation(self):
        with patch.object(dep, "official_json", side_effect=self.fixture):
            report = dep.analyze_dependencies({"package.json": '{"dependencies":{"parent":"^1.0.0"}}'}, mode="registry")
        self.assertEqual({p["name"]: p["version"] for p in report["packages"]}, {"parent": "1.1.0", "child": "2.1.0"})
        self.assertFalse(report["summary"]["complete"], "Unlocked ranges should not claim reproducible resolution")
        self.assertEqual({r[0] for r in report["references"]}, {"test/parent", "test/child"})
        self.assertEqual(report["summary"]["registry_requests"], 4)

    def test_registry_exact_npm_lock_enrichment_does_not_expand(self):
        data = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1.0.0"}},
                "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}
        with patch.object(dep, "official_json", return_value={"repository": "https://github.com/o/a", "dependencies": {"b": "1"}}):
            report = dep.analyze_dependencies({"package-lock.json": json.dumps(data)}, mode="registry")
        self.assertEqual(report["summary"]["count"], 1)
        self.assertIn("o/a", {r[0] for r in report["references"]})

    def test_python_metadata_requires_dist_markers(self):
        def fake(url):
            if url.endswith("/pypi/parent/1.0/json"):
                return {"info": {"project_urls": {"Source": "https://github.com/owner/parent"},
                                 "requires_dist": ["child >=2", "windows-only; sys_platform == 'win32'", "extra-child; extra == 'dev'"]}}
            if url.endswith("/pypi/child/json"):
                return {"info": {}, "releases": {"1.0": [{"yanked": False}], "2.0": [{"yanked": False}]}}
            if url.endswith("/pypi/child/2.0/json"):
                return {"info": {"project_urls": {"Source": "https://github.com/owner/child"}, "requires_dist": []}}
            raise AssertionError(url)
        with patch.object(dep, "official_json", side_effect=fake):
            data = dep.analyze_dependencies({"requirements.txt": "--index-url https://pypi.org/simple\nparent==1.0"}, mode="registry")
        self.assertEqual({p["name"] for p in data["packages"]}, {"parent", "child"})
        self.assertEqual({r[0] for r in data["references"]}, {"owner/parent", "owner/child"})
        self.assertFalse(data["summary"]["complete"])

    def test_registry_failure_and_limit_fail_informatively(self):
        with patch.object(dep, "official_json", side_effect=dep.RegistryError("offline")):
            report = dep.analyze_dependencies({}, mode="registry", explicit_packages=["npm:example@1.0.0"])
        self.assertFalse(report["summary"]["complete"])
        self.assertIn("offline", " ".join(report["summary"]["warnings"]))

    def test_ssrf_denied_for_registry_metadata(self):
        with self.assertRaises(dep.RegistryError):
            dep.official_json("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(dep.RegistryError):
            dep.official_json("https://malicious.example/data.json")

    def test_no_install_or_exec_ever_called(self):
        with patch("subprocess.run", side_effect=AssertionError("must never run")):
            dep.analyze_dependencies({"go.sum": "github.com/one/two v1.0.0 h1:x"}, mode="lock")


if __name__ == "__main__":
    unittest.main()
