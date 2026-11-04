"""Interprocedural provenance tests; sample source is parsed, never executed."""
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

import polyglot_ast
import python_taint
from report_formats import sarif


class PythonInterproceduralTests(unittest.TestCase):
    def scan(self, source):
        return python_taint.scan_python_taint('app.py', source, [])

    def taint(self, source):
        return [f for f in self.scan(source) if f['rule'] == 'TAINT_URL']

    def test_argument_through_helper_to_sink(self):
        code = ('import os, requests\n'
                'def send(url):\n    requests.get(url)\n'
                'dest = os.getenv("ENDPOINT")\nsend(dest)\n')
        result = self.taint(code)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['line'], 3)
        steps = result[0]['dataflow']
        self.assertEqual(steps[0]['kind'], 'source')
        self.assertEqual(steps[-1]['kind'], 'sink')
        self.assertIn('parameter', [x['kind'] for x in steps])
        self.assertEqual(steps[0]['line'], 4)

    def test_return_through_two_helpers(self):
        code = ('import os, requests\n'
                'def identity(u):\n    return u\n'
                'def wrapper(v):\n    return identity(v) + "/v2"\n'
                'target = wrapper(os.getenv("URL"))\nrequests.get(target)\n')
        result = self.taint(code)
        self.assertTrue(result)
        steps = result[0]['dataflow']
        self.assertIn('return', [s['kind'] for s in steps])
        self.assertEqual(steps[-1]['line'], 7)

    def test_geo_source_inside_function_return(self):
        source = ('import requests\n'
                  'def geo_target():\n    return geoip.lookup(ip).country\n'
                  'url = "https://example.test/" + geo_target()\nrequests.get(url)\n')
        result = self.taint(source)
        self.assertTrue(result)
        self.assertIn('geolocation', result[0]['message'])

    def test_safe_overwrite_not_tainted(self):
        source = ('import os, requests\n'
                  'def clean(value):\n    value = "https://safe.example"\n    return value\n'
                  'destination = clean(os.getenv("URL"))\nrequests.get(destination)\n')
        self.assertEqual(self.taint(source), [])

    def test_unrelated_function_no_false_positive(self):
        source = ('import requests\n'
                  'def build(value):\n    return "https://safe.example"\n'
                  'def unused():\n    return geoip.lookup(ip)\n'
                  'requests.get(build("hello"))\n')
        self.assertEqual(self.taint(source), [])

    def test_recursive_call_is_bounded(self):
        source = ('import os, requests\n'
                  'def loop(v):\n    return loop(v)\n'
                  'requests.get(loop(os.getenv("URL")))\n')
        self.assertTrue(self.taint(source))

    def test_unknown_transform_conservatively_propagates(self):
        source = ('import os, requests\n'
                  'def encode(value):\n    return unknown_encoder(value)\n'
                  'requests.get(encode(os.getenv("DEST")))\n')
        self.assertTrue(self.taint(source))

    def test_source_code_is_not_executed(self):
        with tempfile.TemporaryDirectory() as td:
            outfile = Path(td) / 'bad.txt'
            code = (f'import os, requests\n'
                    f'def helper(u):\n    os.system("touch {outfile}")\n    requests.get(u)\n'
                    f'helper(os.getenv("URL"))\n')
            self.assertTrue(self.taint(code))
            self.assertFalse(outfile.exists())


class SarifDataflowTests(unittest.TestCase):
    def report(self, findings):
        return sarif({'tool': 'protestware-check', 'version': '0.6.0',
                      'source': 'demo', 'findings': findings})

    def test_sarif_codeflow_trace(self):
        finding = PythonInterproceduralTests().taint(
            'import os, requests\ndef wrap(u):\n    return u\n'
            'endpoint = wrap(os.getenv("URL"))\nrequests.post(endpoint)\n')[0]
        result = self.report([finding])['runs'][0]['results'][0]
        steps = result['codeFlows'][0]['threadFlows'][0]['locations']
        self.assertEqual(steps[0]['location']['physicalLocation']['region']['startLine'], 4)
        self.assertEqual(steps[-1]['location']['physicalLocation']['region']['startLine'], 5)
        self.assertEqual([s['executionOrder'] for s in steps], list(range(len(steps))))

    def test_unsafe_hop_path_skipped(self):
        f = {'rule': 'TAINT_URL', 'category': 'dataflow', 'severity': 'medium',
             'file': 'app.py', 'line': 3, 'message': 'test',
             'dataflow': [{'file': '../../private.txt', 'line': 2, 'kind': 'source'},
                          {'file': 'app.py', 'line': 3, 'kind': 'sink'}]}
        result = self.report([f])['runs'][0]['results'][0]
        locations = result['codeFlows'][0]['threadFlows'][0]['locations']
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0]['location']['physicalLocation']['artifactLocation']['uri'], 'app.py')

    def test_no_trace_no_codeflows(self):
        f = {'rule': 'NET_DYNAMIC', 'category': 'network', 'severity': 'low',
             'file': 'a.js', 'line': 2, 'message': 'dynamic'}
        self.assertNotIn('codeFlows', self.report([f])['runs'][0]['results'][0])


class RealGrammarInterproceduralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Tree-sitter language pack required in GitHub Actions')

    def test_tainted_argument_to_helper_sink(self):
        cases = {
            'x.js': 'function send(u) { fetch(u); } const endpoint = process.env.DEST; send(endpoint);',
            'x.ts': 'function send(u: string) { fetch(u); } const endpoint = location.search; send(endpoint);',
            'x.go': 'package main\nfunc send(u string) { http.Get(u) }\nfunc main(){ send(os.Getenv("DEST")) }',
            'x.cs': 'class C { void Send(string u) { client.GetAsync(u); } void Main() { Send(Environment.GetEnvironmentVariable("DEST")); } }',
        }
        for path, code in cases.items():
            with self.subTest(path=path):
                findings, diagnostic = polyglot_ast.scan_tree(path, code, [])
                self.assertIsNone(diagnostic, diagnostic)
                tainted = [x for x in findings if x['rule'] == 'TAINT_URL']
                self.assertTrue(tainted, (path, findings))
                self.assertTrue(any('parameter' == hop['kind'] for f in tainted for hop in f.get('dataflow', [])))

    def test_tainted_return_to_network_sink(self):
        cases = {
            'x.js': 'function wrap(u) { return u + "/v2"; } fetch(wrap(process.env.DEST));',
            'x.ts': 'function wrap(u: string) { return u; } fetch(wrap(location.search));',
            'x.go': 'package main\nfunc wrap(u string) string { return u }\nfunc main(){ http.Get(wrap(os.Getenv("URL"))) }',
            'x.cs': 'class C { string Wrap(string u) { return u; } void Main(){ client.GetAsync(Wrap(Environment.GetEnvironmentVariable("URL"))); } }',
        }
        for path, code in cases.items():
            with self.subTest(path=path):
                findings, diagnostic = polyglot_ast.scan_tree(path, code, [])
                self.assertIsNone(diagnostic, diagnostic)
                tainted = [x for x in findings if x['rule'] == 'TAINT_URL']
                self.assertTrue(tainted, (path, findings))
                self.assertTrue(any('return' == hop['kind'] for f in tainted for hop in f.get('dataflow', [])), path)


if __name__ == '__main__':
    unittest.main()
