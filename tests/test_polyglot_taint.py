"""AST/dataflow tests: test inputs are parsed only and NEVER executed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import polyglot_ast
import protestware_check as scanner
import python_taint


class PythonFlows(unittest.TestCase):
    def rules(self, code):
        return {x['rule'] for x in scanner.scan_text('demo.py', code, [], [])}

    def test_user_input_via_alias_and_format(self):
        code = ('import os\nvalue = os.getenv("TARGET")\n'
                'endpoint = "https://example.test/" + value\n'
                'alias = endpoint\nimport requests as r\nr.get(alias)\n')
        self.assertIn('TAINT_URL', self.rules(code))

    def test_geo_response_into_fstring(self):
        code = ('import requests\nlocation = geoip.lookup(ip)\n'
                'u = f"https://collector.example/{location.country}"\nrequests.post(u)\n')
        self.assertIn('TAINT_URL', self.rules(code))

    def test_literal_alias_excludes_taint(self):
        code = 'import requests\nurl = "https://cdn.example/app"\nrequests.get(url)\n'
        self.assertNotIn('TAINT_URL', self.rules(code))
        self.assertIn('AST_NET_EXTERNAL', self.rules(code))

    def test_reassignment_overwrites_taint(self):
        code = ('import os, requests\nu = os.getenv("S")\n'
                'u = "https://cdn.example/lib"\nrequests.get(u)\n')
        self.assertNotIn('TAINT_URL', self.rules(code))

    def test_branch_merging_conservative(self):
        code = ('import os, requests\nu = "https://good.example"\n'
                'if enabled:\n    u = os.getenv("DEST")\nrequests.get(u)\n')
        self.assertIn('TAINT_URL', self.rules(code))

    def test_string_does_not_create_source(self):
        code = 'import requests\nu = "os.getenv(\\"URL\\")"\nrequests.get(u)\n'
        self.assertNotIn('TAINT_URL', self.rules(code))

    def test_scan_does_not_execute(self):
        with tempfile.TemporaryDirectory() as work:
            target = Path(work) / 'do-not-create'
            code = f'import os\nos.system("touch {target}")\nrequests.get(os.getenv("URL"))'
            self.rules(code)
            self.assertFalse(target.exists())


class MockNode:
    def __init__(self, source, kind, piece, children=(), occurrence=0):
        self.type = kind
        data = source.encode('utf-8')
        chunk = piece.encode('utf-8')
        offset = -1
        for _ in range(occurrence + 1):
            offset = data.find(chunk, offset + 1)
        if offset < 0:
            raise ValueError(f'missing source: {piece}')
        self.start_byte = offset
        self.end_byte = offset + len(chunk)
        self.start_point = (data[:offset].count(b'\n'), 0)
        self.end_point = (data[:self.end_byte].count(b'\n'), 0)
        self.named_children = list(children)
        self.has_error = False


class PolyglotTreeTests(unittest.TestCase):
    def test_js_alias_flow_over_real_node_boundaries(self):
        text = 'const endpoint = location.search;\nfetch(endpoint);'
        member = MockNode(text, 'member_expression', 'location.search')
        assign = MockNode(text, 'variable_declarator', 'endpoint = location.search',
                          [MockNode(text, 'identifier', 'endpoint'), member])
        call = MockNode(text, 'call_expression', 'fetch(endpoint)', [
            MockNode(text, 'identifier', 'fetch'),
            MockNode(text, 'arguments', '(endpoint)', [MockNode(text, 'identifier', 'endpoint', occurrence=1)])])
        root = MockNode(text, 'program', text, [assign, call])
        analyzer = polyglot_ast.TreeAnalyzer('demo.ts', text, [])
        analyzer.walk(root, {})
        self.assertIn('TAINT_URL', {x['rule'] for x in analyzer.findings})
        self.assertEqual(next(x for x in analyzer.findings if x['rule'] == 'TAINT_URL')['line'], 2)

    def test_go_env_flow(self):
        text = 'addr := os.Getenv("DEST")\nhttp.Get(addr)'
        expr = MockNode(text, 'call_expression', 'os.Getenv("DEST")')
        assignment = MockNode(text, 'short_var_declaration', 'addr := os.Getenv("DEST")', [
            MockNode(text, 'expression_list', 'addr', [MockNode(text, 'identifier', 'addr')]),
            MockNode(text, 'expression_list', 'os.Getenv("DEST")', [expr])])
        call = MockNode(text, 'call_expression', 'http.Get(addr)', [
            MockNode(text, 'selector_expression', 'http.Get'),
            MockNode(text, 'argument_list', '(addr)', [MockNode(text, 'identifier', 'addr', occurrence=1)])])
        root = MockNode(text, 'source_file', text, [assignment, call])
        analyzer = polyglot_ast.TreeAnalyzer('source.go', text, [])
        analyzer.walk(root, {})
        self.assertIn('TAINT_URL', {x['rule'] for x in analyzer.findings})

    def test_sql_nodes_only(self):
        text = '-- DELETE FROM old\nDELETE FROM sessions;'
        stmt = MockNode(text, 'delete_statement', 'DELETE FROM sessions;')
        root = MockNode(text, 'source_file', text, [stmt])
        analyzer = polyglot_ast.TreeAnalyzer('d.sql', text, [])
        analyzer.walk(root, {})
        rules = {x['rule'] for x in analyzer.findings}
        self.assertIn('AST_SQL_MODIFY', rules)
        self.assertEqual(analyzer.findings[0]['line'], 2)

    def test_html_structured_tag(self):
        text = '<script src="https://untrusted.example/p.js"></script>'
        tag = MockNode(text, 'start_tag', '<script src="https://untrusted.example/p.js">')
        root = MockNode(text, 'document', text, [tag])
        analyzer = polyglot_ast.TreeAnalyzer('page.html', text, [])
        analyzer.walk(root, {})
        self.assertIn('AST_HTML_EXTERNAL', {x['rule'] for x in analyzer.findings})

    def test_sass_structure_and_url(self):
        text = '// @import "https://comment.example"\nbody\n  background: url("https://host.example/x")'
        nodes = polyglot_ast.parse_sass(text)
        self.assertIs(nodes[1].parent, nodes[0])
        results = polyglot_ast.scan_sass('page.sass', text, [])
        self.assertEqual([x['rule'] for x in results], ['AST_STYLE_EXTERNAL'])

    def test_required_mode_cannot_silently_degrade(self):
        with patch.object(polyglot_ast, '_parser', side_effect=RuntimeError('not installed')):
            with self.assertRaises(scanner.ScanError):
                scanner.scan_text('demo.js', 'fetch(url)', [], [], ast_mode='required')

    def test_auto_degraded_warning(self):
        warnings = []
        with patch.object(polyglot_ast, '_parser', side_effect=RuntimeError('not installed')):
            findings = scanner.scan_text('demo.js', 'fetch(url)', [], [], ast_warnings=warnings)
        self.assertTrue(any('AST diagnostic' in w for w in warnings))
        self.assertIn('JS_NETWORK', {x['rule'] for x in findings})


class RealGrammarTests(unittest.TestCase):
    """Run against real Tree-sitter grammars when installed (required in CI)."""
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Tree-sitter language pack not installed locally')

    def test_actual_all_grammars(self):
        specimens = {
            'main.go': 'package main\nimport "os"\nfunc main(){ url := os.Getenv("DEST"); http.Get(url) }',
            'main.cs': 'class C { async void Run(){ var u = Environment.GetEnvironmentVariable("URL"); await client.GetAsync(u); } }',
            'main.ts': 'const u = location.search; fetch(u);',
            'main.js': 'const u = process.env.URL; fetch(u);',
            'main.sql': 'DROP TABLE users;',
            'main.html': '<script src="https://untrusted.example/x.js"></script>',
            'main.css': 'body{background:url("https://untrusted.example/x.png")}',
            'main.scss': '$u: "https://evil.example"; a{background:url($u)}',
            'main.less': '@u: "https://evil.example"; a{background:url(@u)}',
            'main.sass': 'body\n  background: url("https://untrusted.example/x.png")',
        }
        for path, source in specimens.items():
            with self.subTest(path=path):
                findings, diagnostic = polyglot_ast.scan_tree(path, source, [])
                self.assertIsNone(diagnostic, diagnostic)
                self.assertTrue(findings, f'No AST findings for {path}')

    def test_actual_taint_sinks(self):
        specimens = {
            'main.go': 'package main\nfunc main(){ u := os.Getenv("DEST"); http.Get(u) }',
            'main.cs': 'class C { void Run(){ var u = Environment.GetEnvironmentVariable("URL"); client.GetAsync(u); } }',
            'main.ts': 'const u = location.search; fetch(u);',
            'main.js': 'const u = process.env.URL; fetch(u);',
        }
        for path, content in specimens.items():
            with self.subTest(path=path):
                findings, diagnostic = polyglot_ast.scan_tree(path, content, [])
                self.assertIsNone(diagnostic)
                self.assertIn('TAINT_URL', {x['rule'] for x in findings}, path)

if __name__ == '__main__':
    unittest.main()
