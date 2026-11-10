"""Static-only C/C++ bounded call graph regressions. Source strings are never run."""
import unittest

import cpp_ast
import polyglot_ast
from report_formats import sarif


class CppCallGraphUnitTests(unittest.TestCase):
    def test_budget_and_confidence_are_explicit(self):
        self.assertGreater(cpp_ast.MAX_CALL_DEPTH, 1)
        self.assertLessEqual(cpp_ast.MAX_CALL_DEPTH, 8)
        self.assertGreater(cpp_ast.MAX_HELPER_EXPANSIONS, 0)

    def test_stl_algorithm_not_filesystem_delete(self):
        self.assertFalse(cpp_ast.DELETE.fullmatch('std::remove'))
        self.assertTrue(cpp_ast.DELETE.fullmatch('std::filesystem::remove'))


class CppCallGraphParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from tree_sitter_language_pack import get_parser
            get_parser('c')
            get_parser('cpp')
        except (ImportError, OSError, ValueError) as err:
            raise unittest.SkipTest('real Tree-sitter grammars required: ' + str(err))

    def scan(self, code: str, path='demo.cpp'):
        results, diagnostic = polyglot_ast.scan_tree(path, code, [])
        self.assertIsNone(diagnostic, diagnostic)
        return results

    def geo(self, results):
        return [f for f in results if f['rule'] == 'CPP_GEO_ACTION']

    def test_simple_helper_reachability_cpp(self):
        code = '''#include <filesystem>
        void clean(const char* path) { std::filesystem::remove_all(path); }
        void process(const char* country_code, const char* target) {
          if (country_code == "RU") { clean(target); }
        }'''
        results = self.scan(code)
        self.assertEqual(len(self.geo(results)), 1)
        f = self.geo(results)[0]
        self.assertEqual(f['reachability']['call_depth'], 1)
        self.assertEqual([h['kind'] for h in f['dataflow']], ['condition', 'call', 'function', 'sink'])
        self.assertEqual(f['line'], 2)

    def test_two_hop_helper_reachability(self):
        code = '''#include <filesystem>
        void erase(const char* path) { std::filesystem::remove_all(path); }
        void delegate(const char* target) { erase(target); }
        void run(const char* country, const char* target) {
           if (country == "BY") delegate(target);
        }'''
        result = self.geo(self.scan(code))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['reachability']['call_depth'], 2)
        self.assertEqual([h['kind'] for h in result[0]['dataflow']],
                         ['condition', 'call', 'function', 'call', 'function', 'sink'])

    def test_c_helper_reachability(self):
        code = '''void wipe(const char* file) { unlink(file); }
        void work(const char* country, const char* file) {
           if (country == "RU") wipe(file);
        }'''
        result = self.geo(self.scan(code, 'code.c'))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['reachability']['call_depth'], 1)

    def test_network_through_helper(self):
        code = '''void dispatch(void* handle) { curl_easy_perform(handle); }
        void start(const char* locale, void* handle) {
           if (locale == "RU") dispatch(handle);
        }'''
        result = self.geo(self.scan(code))
        self.assertEqual(len(result), 1)
        self.assertIn('network', result[0]['message'])

    def test_process_through_helper(self):
        code = '''void execute() { system("echo test"); }
        void start(const char* region) {
           if (region == "BY") execute();
        }'''
        result = self.geo(self.scan(code, 'demo.c'))
        self.assertEqual(len(result), 1)
        self.assertIn('process', result[0]['message'])

    def test_caller_sibling_not_geographic(self):
        code = '''#include <filesystem>
        void clean(const char* file) { std::filesystem::remove_all(file); }
        void start(const char* country, const char* file) {
          if (country == "RU") { int x=5; }
          clean(file);
        }'''
        findings = self.scan(code)
        self.assertTrue(any(f['rule'] == 'CPP_FS_DELETE' for f in findings))
        self.assertFalse(self.geo(findings))

    def test_guarded_helper_without_sink(self):
        code = '''void log(const char* message) { printf("%s", message); }
        void run(const char* country) { if (country == "RU") log(country); }'''
        self.assertFalse(self.geo(self.scan(code)))

    def test_boolean_helper_geo_guard(self):
        code = '''#include <filesystem>
        bool is_ru(const char* region) { return region == "RU"; }
        void erase(const char* path) { std::filesystem::remove_all(path); }
        void start(const char* country, const char* path) {
          if (is_ru(country)) erase(path);
        }'''
        result = self.geo(self.scan(code))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['reachability']['call_depth'], 1)

    def test_boolean_helper_bound_to_caller_geo_parameter(self):
        code = '''#include <filesystem>
        bool equals_ru(const char* item) { return item == "RU"; }
        void erase(const char* path) { std::filesystem::remove_all(path); }
        void start(const char* country_code, const char* path) {
          if (equals_ru(country_code)) erase(path);
        }'''
        self.assertEqual(len(self.geo(self.scan(code))), 1)

    def test_boolean_helper_not_geo_if_input_not_geo(self):
        code = '''#include <filesystem>
        bool equals_ru(const char* item) { return item == "RU"; }
        void erase(const char* path) { std::filesystem::remove_all(path); }
        void start(const char* token, const char* path) {
          if (equals_ru(token)) erase(path);
        }'''
        self.assertFalse(self.geo(self.scan(code)))

    def test_ambiguous_duplicate_signature_not_assumed(self):
        code = '''#include <filesystem>
        namespace A { void action(const char* path) { std::filesystem::remove_all(path); } }
        namespace B { void action(const char* path) { puts(path); } }
        void run(const char* country, const char* target) {
          if (country == "RU") action(target);
        }'''
        # Both are defined, but neither is uniquely resolvable from action().
        self.assertFalse(self.geo(self.scan(code)))

    def test_overload_arity_is_resolved(self):
        code = '''#include <filesystem>
        void runit(const char* path) { std::filesystem::remove_all(path); }
        void runit(const char* path, int opt) { puts(path); }
        void start(const char* country, const char* path) {
           if (country == "RU") runit(path, 4);
        }'''
        self.assertFalse(self.geo(self.scan(code)))

    def test_recursive_helper_terminates(self):
        code = '''void bounce(const char* value) { bounce(value); }
        void start(const char* country) { if (country == "RU") bounce(country); }'''
        findings, diagnostic = polyglot_ast.scan_tree('code.cpp', code, [])
        self.assertFalse(self.geo(findings))
        self.assertIn('recursive call', diagnostic)

    def test_sarif_renders_c_cpp_call_path(self):
        code = '''#include <filesystem>
        void clean(const char* file){ std::filesystem::remove_all(file); }
        void start(const char* country, const char* file){ if(country=="RU")clean(file); }'''
        findings = self.geo(self.scan(code))
        report = {'tool':'protestware-check','version':'0.8.0','source':'fixture', 'findings':findings}
        sarif_doc = sarif(report)
        thread = sarif_doc['runs'][0]['results'][0]['codeFlows'][0]['threadFlows'][0]['locations']
        self.assertEqual(len(thread), 4)
        self.assertTrue(thread[0]['location']['message']['text'].endswith('RU/BY geographic condition'))


if __name__ == '__main__':
    unittest.main()
