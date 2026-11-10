"""Regression fixtures are inspected as strings, never executed."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ast_analysis
import cpp_ast
import js_behavior
import polyglot_ast
import protestware_check as scanner
import python_taint
from report_formats import sarif


class PythonIntegrityTests(unittest.TestCase):
    def report(self, source, **kwargs):
        return scanner.build_report('test', [('sample.py', source)], [], [], [], dependency_mode='off', **kwargs)

    def exhausted(self):
        return ('import os, requests\ndef no_op():\n    return "fixed"\n'
                'def send():\n    requests.get(os.getenv("DEST"))\n' + 'no_op()\n' * 201 + 'send()\n')

    def test_exhaustion_is_partial_in_json_and_sarif(self):
        report = self.report(self.exhausted())
        self.assertFalse(report['ast']['complete'])
        self.assertEqual(report['ast']['partial'], 1)
        self.assertTrue(any('invocation budget' in item for item in report['warnings']))
        invocation = sarif(report)['runs'][0]['invocations'][0]
        self.assertFalse(invocation['executionSuccessful'])
        self.assertFalse(invocation['properties']['analysisCoverage']['ast'])

    def test_exhaustion_required_returns_two(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'sample.py').write_text(self.exhausted(), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors:
                status = scanner.main(['--path', folder, '--ast-mode', 'required', '--dependencies', 'off'])
        self.assertEqual(status, 2)
        self.assertIn('invocation budget', errors.getvalue())

    def test_normal_taint_remains_complete(self):
        report = self.report('import os, requests\nrequests.get(os.getenv("DEST"))\n')
        self.assertTrue(report['ast']['complete'])
        self.assertEqual([x['rule'] for x in report['findings']].count('TAINT_URL'), 1)

    def test_recursion_and_call_depth_are_reported(self):
        cases = [('def recurse(x):\n    return recurse(x)\nrecurse(input())', 'recursive call'),
                 ('def a(x):\n    return b(x)\ndef b(x):\n    return x\na(input())', 'call depth limit')]
        for source, expected in cases:
            with self.subTest(expected=expected), patch.object(python_taint, 'MAX_CALL_DEPTH', 1):
                report = self.report(source)
                self.assertFalse(report['ast']['complete'])
                self.assertTrue(any(expected in warning for warning in report['warnings']))

    def geo(self, source):
        return [x for x in ast_analysis.scan_python('sample.py', 'import shutil\n' + source, []) if x['rule'] == 'GEO_ACTION']

    def test_reassignment_kills_geo_flag(self):
        for assignment in ('flag = False', 'flag: bool = False', 'flag, other = False, 1',
                           '(flag := False)', 'del flag\nflag = False'):
            with self.subTest(assignment=assignment):
                source = 'flag = country == "RU"\n' + assignment + '\nif flag:\n    shutil.rmtree("demo")'
                self.assertFalse(self.geo(source))
                self.assertNotIn('GEO_ACTION', {x['rule'] for x in self.report('import shutil\n' + source)['findings']})

    def test_other_alias_keeps_original_geo_value(self):
        source = 'flag = country == "RU"\ncopy = flag\nflag = False\nif copy:\n    shutil.rmtree("demo")'
        self.assertEqual(len(self.geo(source)), 1)

    def test_branch_merge_preserves_possible_geo_value(self):
        source = 'flag = country == "RU"\nif enabled:\n    flag = False\nif flag:\n    shutil.rmtree("demo")'
        self.assertEqual(len(self.geo(source)), 1)
        source = source.replace('    flag = False\nif flag:', '    flag = False\nelse:\n    flag = False\nif flag:')
        self.assertFalse(self.geo(source))

    def test_unreachable_nested_action_is_not_geo_action(self):
        for source in ('if country == "RU":\n    if False:\n        shutil.rmtree("demo")',
                       'if False:\n    if country == "RU":\n        shutil.rmtree("demo")',
                       'if True or country == "RU":\n    shutil.rmtree("demo")'):
            with self.subTest(source=source):
                self.assertFalse(self.geo(source))

    def test_uncalled_function_does_not_inherit_outer_geo_condition(self):
        source = 'if country == "RU":\n    def helper():\n        shutil.rmtree("demo")'
        self.assertFalse(self.geo(source))

    def test_partial_tree_findings_are_retained_without_proximity_fallback(self):
        observation = {'rule': 'TAINT_URL', 'file': 'sample.js', 'line': 1, 'severity': 'medium'}
        with patch.object(polyglot_ast, 'scan_tree', return_value=([observation], 'AST partial analysis: sample.js: budget')):
            report = scanner.build_report('test', [('sample.js', 'const a = 1;')], [], [], [], dependency_mode='off')
        self.assertIn(observation, report['findings'])
        self.assertEqual(report['ast']['partial'], 1)


class TreeBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            polyglot_ast._parser('javascript')
            polyglot_ast._parser('cpp')
        except RuntimeError as error:
            raise unittest.SkipTest(str(error))

    def test_polyglot_invocation_budget(self):
        source = 'function noop() { return "fixed"; }\n' + 'noop();\n' * 201
        _, diagnostic = polyglot_ast.scan_tree('sample.js', source, [])
        self.assertIn('invocation budget', diagnostic)

    def test_cpp_helper_budget_is_partial_and_strict(self):
        source = 'void erase() { remove("demo"); } void f() { if (country == "RU") { erase(); } }'
        with patch.object(cpp_ast, 'MAX_HELPER_EXPANSIONS', 0):
            report = scanner.build_report('test', [('sample.cpp', source)], [], [], [], dependency_mode='off')
            self.assertFalse(report['ast']['complete'])
            self.assertTrue(any('helper expansion budget' in item for item in report['warnings']))
            with self.assertRaises(scanner.ScanError):
                scanner.scan_text('sample.cpp', source, [], [], ast_mode='required')

    def test_js_network_path_node_budget(self):
        source = 'fetch("https://example.test");'
        root = polyglot_ast._parser('javascript').parse(source.encode()).root_node
        analyzer = js_behavior.BehaviorAnalyzer('sample.js', source)
        self.assertIsNone(analyzer.network_path(root, budget=0))
        self.assertIn('JavaScript network path node budget reached', analyzer.diagnostics)

    def test_expression_budget_propagates(self):
        source = 'let a = value;'
        root = polyglot_ast._parser('javascript').parse(source.encode()).root_node
        analyzer = polyglot_ast.TreeAnalyzer('sample.js', source, [])
        analyzer.value(root, {}, level=41)
        self.assertIn('Tree-sitter taint expression depth limit reached', analyzer.diagnostics)


if __name__ == '__main__':
    unittest.main()
