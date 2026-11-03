"""Regression tests using inert strings only; no suspicious code is executed."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import base64

import protestware_check as scanner


class DetectionTests(unittest.TestCase):
    def scan(self, code, suffix="sample.py", allow=()):
        return scanner.scan_text(suffix, code, list(scanner.POLITICAL_TERMS), list(allow))

    def rules(self, findings):
        return {item["rule"] for item in findings}

    def test_political_context_is_not_malware(self):
        report = scanner.build_report("test", [("README.md", "Stop Russian aggression.")],
                                      list(scanner.POLITICAL_TERMS), [], [])
        self.assertEqual(report["risk"], "none")
        self.assertEqual(report["summary"]["info"], 1)

    def test_geography_guard(self):
        findings = self.scan('if country_code == "RU":\n    print("unsupported")')
        self.assertIn("GEO_TARGET", self.rules(findings))
        self.assertNotIn("GEO_ACTION", self.rules(findings))

    def test_geo_with_delete_correlation(self):
        findings = self.scan('if country == "RU":\n    shutil.rmtree(home_dir)')
        self.assertTrue({"GEO_TARGET", "FS_DELETE", "GEO_ACTION"}.issubset(self.rules(findings)))

    def test_geography_action_not_near(self):
        code = 'if country == "RU":\n    print("hello")\n' + ('print(1)\n' * 20) + 'os.remove(x)'
        self.assertNotIn("GEO_ACTION", self.rules(self.scan(code)))

    def test_http_domain_and_allowlist(self):
        code = 'fetch("https://unknown.example/v1")'
        self.assertIn("NET_EXTERNAL", self.rules(self.scan(code, "index.js")))
        self.assertNotIn("NET_EXTERNAL", self.rules(self.scan(code, "index.js", ["unknown.example"])))

    def test_subdomain_boundary(self):
        self.assertTrue(scanner.domain_allowed("api.example.org", ["example.org"]))
        self.assertFalse(scanner.domain_allowed("evil-example.org", ["example.org"]))

    def test_dynamic_http(self):
        self.assertIn("NET_DYNAMIC", self.rules(self.scan("requests.get(api_url)")))

    def test_geo_api(self):
        code = 'requests.get("https://ipapi.co/json/")'
        self.assertIn("NET_GEO_API", self.rules(self.scan(code)))

    def test_obfuscated_exec(self):
        self.assertIn("OBF_DECODE_EXEC", self.rules(self.scan('eval(atob(payload))', "code.js")))

    def test_write_and_delete(self):
        findings = self.scan('Path("tmp").write_text(content)\nos.unlink(target)')
        self.assertTrue({"FS_WRITE", "FS_DELETE"}.issubset(self.rules(findings)))

    def test_python_string_literals_do_not_trigger_code_rules(self):
        findings = self.scan('example = "eval(atob(payload))"\n# shutil.rmtree(path)')
        self.assertEqual(findings, [])

    def test_geo_discovery_api(self):
        findings = self.scan('navigator.geolocation.getCurrentPosition(onSuccess)', "index.js")
        self.assertIn("GEO_DISCOVERY", self.rules(findings))

    def test_python_open_write_mode(self):
        findings = self.scan('with open(path, "w") as out:\n    out.write(value)')
        self.assertIn("FS_WRITE", self.rules(findings))

    def test_docs_do_not_trigger_technical_checks(self):
        findings = self.scan("Example: eval(atob(payload)) and shutil.rmtree(path)", "README.md")
        self.assertEqual(findings, [])

    def test_cli_json_output_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "bad.js").write_text('eval(atob(payload))', encoding="utf-8")
            with patch("sys.stdout") as out:
                code = scanner.main(["--path", directory, "--format", "json"])
            self.assertEqual(code, 1)
            data = json.loads("".join(call.args[0] for call in out.write.call_args_list))
            self.assertEqual(data["risk"], "high")

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            Path(outside, "evil.py").write_text('eval(atob(payload))', encoding="utf-8")
            os.symlink(outside, Path(directory, "alias"))
            report = scanner.build_report("test", scanner.iter_local(Path(directory), 100000, [], []),
                                          list(scanner.POLITICAL_TERMS), [], [])
            self.assertEqual(report["files_scanned"], 0)

    def test_git_coordinates(self):
        self.assertEqual(scanner.github_coordinates("https://github.com/owner/repo.git"), ("owner", "repo"))
        for bad in ("http://github.com/x/y", "https://evil.com/x/y", "a/b/c", "../repo", "a/b?ref=main"):
            with self.subTest(bad=bad), self.assertRaises(scanner.ScanError):
                scanner.github_coordinates(bad)

    def test_github_tree_and_blob_without_execution(self):
        digest = "a" * 40
        def fake_api(url, token):
            if url.endswith("/org/demo"):
                return {"default_branch": "main"}
            if "/git/trees/" in url:
                return {"truncated": False, "tree": [{"type": "blob", "mode": "100644", "size": 12,
                                                      "path": "src/hello.py", "sha": digest}]}
            if "/git/blobs/" in url:
                return {"encoding": "base64", "content": base64.b64encode(b"print('hi')").decode()}
            raise AssertionError(url)
        with patch.object(scanner, "api_json", side_effect=fake_api):
            files = list(scanner.iter_github("org/demo", None, 10000, [], []))
        self.assertEqual(files, [("src/hello.py", "print('hi')")])

    def test_truncated_remote_tree_fails_closed(self):
        with patch.object(scanner, "api_json", side_effect=[{"default_branch": "main"},
                                                        {"truncated": True, "tree": []}]):
            with self.assertRaises(scanner.ScanError):
                list(scanner.iter_github("org/demo", None, 10000, [], []))


if __name__ == "__main__":
    unittest.main()