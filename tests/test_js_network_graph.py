"""Finite local network reachability: cycles, witnesses and honest work limits."""
import unittest

import js_behavior
import polyglot_ast


class JavaScriptNetworkGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('JS grammar required')

    def analyze(self, code):
        tree = polyglot_ast._parser('javascript').parse(code.encode())
        analyzer = js_behavior.BehaviorAnalyzer('sample.js', code)
        analyzer.index(tree.root_node)
        analyzer.scan_flood(tree.root_node)
        return analyzer, tree.root_node

    def test_recursive_noop_is_not_a_flood_or_a_depth_error(self):
        analyzer, _ = self.analyze('function a(){b()} function b(){a()} while(true){a()}')
        self.assertFalse(analyzer.findings)
        self.assertFalse(analyzer.diagnostics)

    def test_network_sink_in_recursive_component_retains_a_witness(self):
        analyzer, _ = self.analyze('function a(){b()} function b(){a();fetch(url)} while(true){a()}')
        self.assertEqual(len(analyzer.findings), 1)
        self.assertEqual(analyzer.findings[0]['rule'], 'NETWORK_FLOOD')
        self.assertEqual(analyzer.findings[0]['dataflow'][-1]['kind'], 'sink')
        self.assertFalse(analyzer.diagnostics)

    def test_shared_helpers_and_uncalled_nested_functions_do_not_invent_requests(self):
        code = 'function a(){noop();noop();function unused(){fetch(url)}} function noop(){} while(true){a()}'
        analyzer, _ = self.analyze(code)
        self.assertFalse(analyzer.findings)
        self.assertFalse(analyzer.diagnostics)

    def test_global_node_budget_still_reports_incomplete_search(self):
        analyzer, root = self.analyze('function a(){b()} function b(){fetch(url)} while(true){a()}')
        analyzer.diagnostics.clear()
        self.assertIsNone(analyzer.network_path(root, budget=1))
        self.assertIn('node budget', ' '.join(analyzer.diagnostics))


if __name__ == '__main__':
    unittest.main()
