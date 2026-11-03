"""Tests with inert code samples and synthetic watchlist records (never executed)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ast_analysis
import protestware_check as scanner
import threat_intel


class ASTTests(unittest.TestCase):
    def rules(self, code):
        return scanner.scan_text("pkg.py", code, [], [])

    def test_ast_reports_control_flow_and_aliases(self):
        code = 'import shutil as s\nif country_code in ("RU", "BY"):\n    s.rmtree(home)\n'
        findings = self.rules(code)
        self.assertTrue({"FS_DELETE", "GEO_TARGET", "GEO_ACTION"}.issubset({f["rule"] for f in findings}))
        self.assertEqual(next(f for f in findings if f["rule"] == "GEO_ACTION")["analysis"], "ast")

    def test_unrelated_operation_close_to_guard_is_not_correlated(self):
        code = 'if country == "RU":\n    print("ok")\nshutil.rmtree(home)\n'
        self.assertNotIn("GEO_ACTION", {f["rule"] for f in self.rules(code)})

    def test_nested_def_not_executed_in_geo_branch(self):
        code = 'if country == "RU":\n    def cleanup():\n        shutil.rmtree(home)\n'
        self.assertNotIn("GEO_ACTION", {f["rule"] for f in self.rules(code)})

    def test_nested_branch_acted_and_else_branch(self):
        code = 'if country == "RU":\n    if enabled:\n        os.unlink(path)\nelse:\n    Path("foo").write_text(data)\n'
        actions = [f for f in self.rules(code) if f["rule"] == "GEO_ACTION"]
        self.assertEqual({f["line"] for f in actions}, {3, 5})

    def test_conditional_alias_assignment(self):
        code = 'is_blocked = country_code == "RU"\nif is_blocked:\n    os.remove(path)'
        self.assertIn("GEO_ACTION", {f["rule"] for f in self.rules(code)})

    def test_ast_ignores_string_and_comment(self):
        self.assertEqual(self.rules('x = "os.unlink(path)"\n# if country == "RU":\nprint(1)'), [])

    def test_multiline_request_and_alias(self):
        code = 'import requests as web\nweb.get(\n    "https://other.example/path"\n)'
        findings = self.rules(code)
        self.assertIn("NET_EXTERNAL", {f["rule"] for f in findings})
        self.assertTrue(any(f.get("analysis") == "ast" for f in findings))

    def test_keyword_open_write(self):
        self.assertIn("FS_WRITE", {f["rule"] for f in self.rules('with open(path, mode="wb") as f:\n    pass')})

    def test_decode_execute_through_import_alias(self):
        code = 'from base64 import b64decode as decode\nfrom builtins import exec as run\nrun(decode(payload))'
        self.assertIn("OBF_DECODE_EXEC", {f["rule"] for f in self.rules(code)})

    def test_invalid_python_fallback(self):
        self.assertIsNone(ast_analysis.scan_python("x.py", 'if country == "RU"', []))

    def test_neither_geo_mention_nor_plain_country_is_enough(self):
        for code in ('if x == "RU":\n    os.unlink(path)',
                     'if country == "US":\n    os.unlink(path)'):
            with self.subTest(code=code):
                self.assertNotIn("GEO_ACTION", {f["rule"] for f in self.rules(code)})


SAMPLE_JSON = json.dumps([
    {"id": 1, "problem_type": "malware", "name": "a/evil", "commit_link": "https://github.com/a/evil/commit/abc"},
    {"id": 2, "problem_type": "political_slogans", "name": "b/words", "commit_link": "https://github.com/b/words"},
    {"id": 3, "problem_type": "ip_block", "name": "c/pkg", "commit_link": "https://github.com/c/pkg/blob/main/readme.md"},
    {"id": 4, "problem_type": "malware", "name": "some other name", "commit_link": "https://example.com"},
])
SAMPLE_BLACK = '# black-mark\n* https://github.com/a\n* https://github.com/BigOrg\nhttps://gitlab.com/excluded\n'


class ThreatIntelTests(unittest.TestCase):
    def data(self):
        return {"black": threat_intel.parse_black_mark(SAMPLE_BLACK),
                "toxic": threat_intel.parse_toxic_repos(SAMPLE_JSON),
                "metadata": {"mode": "offline"}}

    def test_parses_two_real_source_formats(self):
        data = self.data()
        self.assertIn("bigorg", data["black"])
        self.assertIn("a/evil", data["toxic"])
        self.assertEqual(data["toxic"]["a/evil"][0]["type"], "malware")
        self.assertNotIn("some other name", data["toxic"])

    def test_canonical_github_urls(self):
        text = ('git+https://github.com/a/evil.git#egg=evil\n'
                'git@github.com:BigOrg/Useful.git\n'
                'https://evilgithub.com/a/evil\n')
        self.assertEqual(threat_intel.github_refs(text), {"a/evil", "bigorg/useful"})
        self.assertEqual(threat_intel.github_refs('"dep": "github:BigOrg/Useful#main"'),
                         {"bigorg/useful"})
        self.assertEqual(threat_intel.github_refs('git+ssh://git@github.com/a/evil.git'),
                         {"a/evil"})

    def test_not_every_github_mention_is_dependency(self):
        self.assertEqual(threat_intel.scan_manifests("README.md", 'https://github.com/a/evil'), [])
        self.assertEqual(threat_intel.scan_manifests("requirements-dev.txt", "git+https://github.com/a/evil.git"),
                         [("a/evil", 1, "git+https://github.com/a/evil.git")])

    def test_repo_and_owner_matches_have_separate_severity(self):
        matches = threat_intel.match_repositories([("a/evil", "(repository)", 0, "a/evil"),
                                                   ("bigorg/good", "package.json", 3, "github:BigOrg/good")], self.data())
        by_rule = {(x["rule"], x["repository"]): x for x in matches}
        self.assertEqual(by_rule[("BLACK_MARK_OWNER", "bigorg/good")]["severity"], "info")
        self.assertEqual(by_rule[("TOXIC_REPO", "a/evil")]["severity"], "medium")
        self.assertEqual(by_rule[("TOXIC_REPO", "a/evil")]["record_ids"], ["1"])

    def test_political_slogans_are_context_only(self):
        entries = threat_intel.match_repositories([("b/words", "(package)", 0, "b/words")], self.data())
        self.assertEqual(entries[0]["severity"], "info")

    def test_manifests_collected_with_report(self):
        files = [("package.json", '{"dependencies": {"dep": "git+https://github.com/a/evil.git#main"}}')]
        report = scanner.build_report("example", files, [], [], [], watchlists=self.data())
        self.assertEqual(report["risk"], "medium")
        self.assertEqual(report["code_risk"], "none")
        self.assertIn("TOXIC_REPO", {f["rule"] for f in report["findings"]})

    def test_cli_offline_mode_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("git+https://github.com/a/evil.git\n", encoding="utf-8")
            (root / "black.md").write_text(SAMPLE_BLACK, encoding="utf-8")
            (root / "toxic.json").write_text(SAMPLE_JSON, encoding="utf-8")
            with patch("sys.stdout") as out:
                exit_status = scanner.main(["--path", directory, "--watchlists", "offline",
                                            "--black-mark-file", str(root / "black.md"),
                                            "--toxic-repos-file", str(root / "toxic.json"),
                                            "--format", "json", "--fail-on", "medium"])
            self.assertEqual(exit_status, 1)
            report = json.loads("".join(x.args[0] for x in out.write.call_args_list))
            self.assertIn("TOXIC_REPO", {item["rule"] for item in report["findings"]})
            self.assertEqual(report["watchlists"]["mode"], "offline")

    def test_no_live_fetch_when_off(self):
        with patch.object(threat_intel, "download_public_list", side_effect=AssertionError("network")):
            self.assertIsNone(threat_intel.load_watchlists("off"))

    def test_live_fetch_fixed_urls(self):
        with patch.object(threat_intel, "download_public_list", side_effect=[SAMPLE_BLACK, SAMPLE_JSON]) as fetch:
            out = threat_intel.load_watchlists("live")
        self.assertEqual(out["metadata"]["mode"], "live")
        self.assertEqual([a.args[0] for a in fetch.call_args_list],
                         [threat_intel.BLACK_MARK_URL, threat_intel.TOXIC_REPOS_URL])

    def test_fail_closed_on_invalid_lists(self):
        for black, toxic in [("", SAMPLE_JSON), (SAMPLE_BLACK, "{}"), (SAMPLE_BLACK, "[]")]:
            with self.subTest(black=black, toxic=toxic), patch.object(
                    threat_intel, "download_public_list", side_effect=[black, toxic]):
                with self.assertRaises(threat_intel.WatchlistError):
                    threat_intel.load_watchlists("live")

    def test_github_repos_from_cli_list(self):
        report = scanner.build_report("example", [], [], [], [], watchlists=self.data(),
                                      package_repos=["https://github.com/a/evil"])
        self.assertEqual(report["files_scanned"], 0)
        self.assertIn("TOXIC_REPO", {f["rule"] for f in report["findings"]})

    def test_repo_self_checked(self):
        report = scanner.build_report("example", [], [], [], [], watchlists=self.data(), repository="a/evil")
        self.assertIn("TOXIC_REPO", {f["rule"] for f in report["findings"]})


class ScopeRegressionTests(unittest.TestCase):
    def test_geo_flag_does_not_leak_across_functions(self):
        source = ('def foo():\n    special = country == "RU"\n    return special\n'
                  'def bar():\n    if special:\n        os.unlink(path)\n')
        findings = ast_analysis.scan_python("sample.py", source, [])
        self.assertNotIn("GEO_ACTION", {f["rule"] for f in findings})


if __name__ == "__main__":
    unittest.main()
