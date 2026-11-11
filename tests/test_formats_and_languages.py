"""Focused regression tests for non-Python languages and machine-readable exports."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_analysis
import language_analysis
import protestware_check as scanner
import report_formats
import threat_intel


class LanguageSmokeTests(unittest.TestCase):
    def scan(self, source, suffix):
        return scanner.scan_text("demo" + suffix, source, [], [])

    def rules(self, source, suffix):
        return {x["rule"] for x in self.scan(source, suffix)}

    def test_extensions_are_scannable(self):
        for suffix in (".go", ".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
                       ".sql", ".html", ".htm", ".css", ".scss", ".sass", ".less"):
            with self.subTest(suffix=suffix):
                self.assertTrue(scanner.is_scannable("src/main" + suffix, []))

    def test_go_file_and_network(self):
        results = self.rules('package p\nimport ("os"; "net/http")\n'
                             'func run(){ os.RemoveAll(home); resp, err := http.Get("https://evil.example/api") }', ".go")
        self.assertTrue({"GO_FS_DELETE", "GO_NETWORK", "NET_EXTERNAL"} <= results)

    def test_go_comment_does_not_execute(self):
        self.assertNotIn("GO_FS_DELETE", self.rules('// os.RemoveAll(home)\n/* os.Remove(x) */', ".go"))
        self.assertNotIn("FS_DELETE", self.rules('// os.RemoveAll(home)\n/* os.Remove(x) */', ".go"))

    def test_csharp_network_and_file_operations(self):
        rules = self.rules('File.Delete(target);\nHttpClient client = new HttpClient();\n'
                           'await client.GetAsync("https://evil.example/json");', ".cs")
        self.assertTrue({"CS_FS_DELETE", "CS_NETWORK", "NET_EXTERNAL"} <= rules)

    def test_csharp_comment_not_executed(self):
        self.assertNotIn("CS_FS_DELETE", self.rules('/* File.Delete(target); */', ".cs"))

    def test_ts_and_js(self):
        for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
            with self.subTest(suffix=suffix):
                rules = self.rules('const x = await globalThis.fetch("https://evil.example/x");', suffix)
                self.assertTrue({"JS_NETWORK", "NET_EXTERNAL"} <= rules)

    def test_js_comment_does_not_trigger_execution(self):
        for suffix in (".ts", ".js"):
            with self.subTest(suffix=suffix):
                self.assertNotIn("OBF_DYNAMIC_EXEC", self.rules('// eval(payload);', suffix))

    def test_sql_modifies_database(self):
        self.assertTrue({"SQL_DESTRUCTIVE", "SQL_MODIFY"} <=
                        self.rules('DROP TABLE customers;\nUPDATE invoices SET paid=1;', ".sql"))

    def test_sql_does_not_read_comments_as_commands(self):
        self.assertNotIn("SQL_DESTRUCTIVE", self.rules('-- DROP TABLE customers;\n/* TRUNCATE TABLE t; */', ".sql"))

    def test_sql_literals_and_quoted_identifiers_are_not_commands(self):
        for text in ("SELECT 'DROP TABLE records;' AS example;", 'SELECT "DROP TABLE records" FROM logs;',
                     "SELECT 'It''s an example: DROP TABLE records;' AS example;"):
            with self.subTest(text=text):
                self.assertNotIn('SQL_DESTRUCTIVE', self.rules(text, '.sql'))
        self.assertIn('SQL_MODIFY', self.rules('UPDATE "records" SET flag = 1;', '.sql'))
        self.assertIn('SQL_DYNAMIC', self.rules("EXECUTE IMMEDIATE 'DROP TABLE records';", '.sql'))

    def test_html_external_script(self):
        self.assertIn("HTML_REMOTE_SCRIPT", self.rules('<script src="https://cdn.evil.example/lib.js"></script>', ".html"))

    def test_html_comment_is_not_script(self):
        self.assertNotIn("HTML_REMOTE_SCRIPT", self.rules('<!-- <script src="https://evil.example/a.js"></script> -->', ".html"))

    def test_html_inline_js(self):
        self.assertIn("JS_NETWORK", self.rules('<script>\nfetch("https://evil.example/api")\n</script>', ".htm"))

    def test_html_multiline_script_tag(self):
        self.assertIn("HTML_REMOTE_SCRIPT", self.rules('<script\n src="https://evil.example/lib.js">\n</script>', ".html"))

    def test_html_inline_decoded_exec(self):
        self.assertIn("OBF_DECODE_EXEC", self.rules('<script>eval(atob(payload))</script>', ".html"))

    def test_go_multiline_http_url(self):
        self.assertIn("NET_EXTERNAL", self.rules('http.Get(\n  "https://evil.example/x",\n)', ".go"))

    def test_stylesheet_imports(self):
        for suffix in (".css", ".scss", ".sass", ".less"):
            with self.subTest(suffix=suffix):
                self.assertIn("STYLE_REMOTE_RESOURCE", self.rules('@import url("https://tracker.example/base.css");', suffix))

    def test_stylesheet_unquoted_url(self):
        self.assertIn("STYLE_REMOTE_RESOURCE", self.rules('body{background:url(https://evil.example/t.png)}', ".css"))

    def test_stylesheet_trusted_domain(self):
        findings = scanner.scan_text("demo.scss", '@import "https://static.example.com/base.css";', [], ["example.com"])
        self.assertNotIn("STYLE_REMOTE_RESOURCE", {x["rule"] for x in findings})

    def test_stylesheet_comment_ignored(self):
        self.assertNotIn("STYLE_REMOTE_RESOURCE", self.rules('/* @import "https://evil.example/hidden.css" */', ".less"))

    def test_plain_political_context_remains_info(self):
        report = scanner.build_report("test", [("README.md", "boycott russia")],
                                      list(scanner.POLITICAL_TERMS), [], [])
        self.assertEqual(report["risk"], "none")


class FormatTests(unittest.TestCase):
    def sample(self):
        return {"tool": "protestware-check", "version": "0.4.0", "source": "demo/repo", "risk": "medium",
                "findings": [
                    {"rule": "NET_EXTERNAL", "category": "network", "severity": "medium",
                     "file": "src/main.ts", "line": 5, "message": "External endpoint", "evidence": "fetch(url)"},
                    {"rule": "BLACK_MARK_OWNER", "category": "watchlist_context", "severity": "info",
                     "file": "(repository)", "line": 0, "message": "List-only match", "evidence": "owner/repo"}],
                "dependencies": {"mode": "lock", "summary": {"count": 3, "complete": True}, "packages": [
                    {"ecosystem": "npm", "name": "@scope/core", "version": "1.2.3", "manifest": "package-lock.json",
                     "source": "lockfile", "direct": True, "depth": 1, "via": [], "repository": "abc/core"},
                    {"ecosystem": "npm", "name": "helper", "version": "2.1.0", "manifest": "package-lock.json",
                     "source": "lockfile", "direct": False, "depth": 2, "via": ["@scope/core@1.2.3"], "repository": None},
                    {"ecosystem": "pypi", "name": "requests", "version": "2.32.3", "manifest": "uv.lock",
                     "source": "lockfile", "direct": True, "depth": 1, "via": [], "repository": None}]}}

    def test_empty_inventory_is_not_complete(self):
        report = scanner.build_report("no-manifests", [("file.go", "package demo")], [], [], [])
        self.assertFalse(report["dependencies"]["summary"]["complete"])
        sbom = report_formats.cyclonedx(report)
        props = sbom["metadata"]["component"]["properties"]
        self.assertIn({"name": "protestware-check:dependency-analysis-complete", "value": "false"}, props)

    def test_sarif_shape(self):
        data = report_formats.sarif(self.sample())
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 2)
        result = data["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 5)
        self.assertNotIn("locations", data["runs"][0]["results"][1])
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_deterministic(self):
        self.assertEqual(report_formats.sarif(self.sample()), report_formats.sarif(self.sample()))

    def test_cyclonedx_shape_and_edges(self):
        obj = report_formats.cyclonedx(self.sample())
        self.assertEqual(obj["bomFormat"], "CycloneDX")
        self.assertEqual(obj["specVersion"], "1.6")
        self.assertEqual(len(obj["components"]), 3)
        self.assertEqual(len({x["bom-ref"] for x in obj["components"]}), 3)
        self.assertIn("pkg:npm/%40scope/core@1.2.3", [c.get("purl") for c in obj["components"]])
        root = obj["metadata"]["component"]["bom-ref"]
        self.assertEqual(len(next(x for x in obj["dependencies"] if x["ref"] == root)["dependsOn"]), 2)
        parent = next(c for c in obj["components"] if c["name"] == "@scope/core")
        child = next(c for c in obj["components"] if c["name"] == "helper")
        self.assertIn(child["bom-ref"], next(x for x in obj["dependencies"] if x["ref"] == parent["bom-ref"])["dependsOn"])

    def test_sbom_not_disguised_vulnerability(self):
        self.assertNotIn("vulnerabilities", report_formats.cyclonedx(self.sample()))

    def test_cli_output_sarif(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "index.js").write_text('fetch("https://evil.example/x")', encoding="utf-8")
            result = root / "results.sarif"
            exit_code = scanner.main(["--path", td, "--dependencies", "off", "--format", "sarif", "--output", str(result)])
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(result.read_text())["version"], "2.1.0")

    def test_cli_output_sbom(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3,
                "packages": {"": {"dependencies": {"foo": "1.0.0"}},
                             "node_modules/foo": {"version": "1.0.0"}}}), encoding="utf-8")
            target = root / "bom.cdx.json"
            exit_code = scanner.main(["--path", td, "--format", "cyclonedx", "--output", str(target)])
            self.assertEqual(exit_code, 0)
            obj = json.loads(target.read_text())
            self.assertEqual(obj["components"][0]["name"], "foo")

    def test_purl_languages(self):
        for ecosystem, name, expected in [("go", "github.com/acme/pkg", "pkg:golang/github.com/acme/pkg@v1.0.0"),
                                           ("nuget", "Newtonsoft.Json", "pkg:nuget/Newtonsoft.Json@v1.0.0"),
                                           ("composer", "symfony/console", "pkg:composer/symfony/console@v1.0.0")]:
            self.assertEqual(report_formats.purl({"ecosystem": ecosystem, "name": name, "version": "v1.0.0"}), expected)


class NuGetTests(unittest.TestCase):
    def test_csharp_project_is_scannable(self):
        self.assertTrue(threat_intel.is_manifest("src/Project.csproj"))
        self.assertTrue(scanner.is_scannable("src/packages.lock.json", []))

    def test_nuget_lock_transitive(self):
        manifests = {
            "app/Project.csproj": '<Project><ItemGroup><PackageReference Include="A" Version="1.0.0" /></ItemGroup></Project>',
            "app/packages.lock.json": json.dumps({"version": 1, "dependencies": {"net8.0": {
                "A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"B": "2.0.0"}},
                "B": {"type": "Transitive", "resolved": "2.0.0"}}}}),
        }
        data = dependency_analysis.analyze_dependencies(manifests, mode="lock")
        self.assertTrue(data["summary"]["complete"])
        packages = {p["name"]: p for p in data["packages"]}
        self.assertTrue(packages["A"]["direct"])
        self.assertFalse(packages["B"]["direct"])
        self.assertIn("A@1.0.0", packages["B"]["via"])

    def test_csharp_project_without_lock_is_partial(self):
        data = dependency_analysis.analyze_dependencies({"app/P.csproj":
            '<Project><PackageReference Include="A" Version="1.2.3" /></Project>'}, mode="lock")
        self.assertFalse(data["summary"]["complete"])
        self.assertEqual(data["packages"][0]["ecosystem"], "nuget")

    def test_malformed_nuget_lock_is_partial(self):
        data = dependency_analysis.analyze_dependencies({"packages.lock.json": '{broken'}, mode="lock")
        self.assertFalse(data["summary"]["complete"])


if __name__ == "__main__":
    unittest.main()
