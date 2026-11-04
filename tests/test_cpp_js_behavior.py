"""C/C++ parser and JavaScript behavior regressions; sample programs never run."""
import unittest
from unittest.mock import patch

import cpp_ast
import js_behavior
import polyglot_ast
import protestware_check as scanner


class OfflineCheckTests(unittest.TestCase):
    def test_cpp_language_extensions(self):
        for suffix, grammar in cpp_ast.C_CPP_GRAMMARS.items():
            self.assertEqual(polyglot_ast.GRAMMARS[suffix], grammar)
            self.assertIn(suffix, scanner.CODE_SUFFIXES)

    def test_cpp_does_not_confuse_algorithm_remove_with_file_deletion(self):
        self.assertFalse(cpp_ast.DELETE.fullmatch('std::remove'))
        self.assertTrue(cpp_ast.DELETE.fullmatch('std::filesystem::remove_all'))
        self.assertTrue(cpp_ast.DELETE.fullmatch('unlink'))

    def test_comment_text_is_not_an_obfuscation_signal(self):
        from language_analysis import mask_comments
        fake = '// a.push(a.shift()); ' + "x('0x1');" * 8
        clean = mask_comments(fake, '.js')
        self.assertFalse(js_behavior.ROTATE.search(clean))
        self.assertEqual(js_behavior.HEX_INDEX.findall(clean), [])

    def test_cpp_missing_parser_required_fails_closed(self):
        with patch.object(polyglot_ast, '_parser', side_effect=RuntimeError('not installed')):
            with self.assertRaises(scanner.ScanError):
                scanner.scan_text('src/demo.cpp', 'void f() {}', [], [], ast_mode='required')

    def test_cpp_missing_parser_auto_warns(self):
        warns, stats = [], {}
        with patch.object(polyglot_ast, '_parser', side_effect=RuntimeError('not installed')):
            scanner.scan_text('src/demo.cpp', 'void f() {}', [], [],
                              ast_mode='auto', ast_warnings=warns, ast_stats=stats)
        self.assertTrue(warns)
        self.assertEqual(stats.get('degraded'), 1)


class RealParserBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Tree-sitter grammars required in GitHub Actions')

    def rules(self, file, code):
        findings, diagnostic = polyglot_ast.scan_tree(file, code, [])
        self.assertIsNone(diagnostic, (file, diagnostic, findings))
        return {x['rule'] for x in findings}, findings

    def test_cpp_delete_with_geo_branch_has_proven_control_flow(self):
        code = ('#include <filesystem>\n'
                'void f(const char* country_code, const char* path) {\n'
                '  if (country_code == "RU") { std::filesystem::remove_all(path); }\n'
                '}\n')
        rules, findings = self.rules('code.cpp', code)
        self.assertTrue({'CPP_FS_DELETE', 'CPP_GEO_TARGET', 'CPP_GEO_ACTION'} <= rules)
        correlated = next(f for f in findings if f['rule'] == 'CPP_GEO_ACTION')
        self.assertEqual([x['kind'] for x in correlated['dataflow']], ['condition', 'sink'])

    def test_cpp_sibling_action_is_not_geo_correlated(self):
        code = ('void f(const char* country_code, const char* path) {\n'
                ' if (country_code == "RU") { int x = 1; }\n'
                ' std::filesystem::remove_all(path); }\n')
        rules, _ = self.rules('code.cpp', code)
        self.assertIn('CPP_FS_DELETE', rules)
        self.assertNotIn('CPP_GEO_ACTION', rules)

    def test_cpp_network_process_and_write(self):
        code = ('#include <fstream>\n'
                'void f(void* handle) {\n'
                ' std::ofstream out("log.txt");\n'
                ' curl_easy_perform(handle);\n'
                ' std::system("echo test");\n'
                '}\n')
        rules, _ = self.rules('code.cpp', code)
        self.assertIn('CPP_FS_WRITE', rules)
        self.assertIn('CPP_NETWORK', rules)
        self.assertIn('CPP_PROCESS', rules)

    def test_c_file_delete_and_mode_sensitive_write(self):
        code = 'void clean(const char* p) { unlink(p); fopen(p, "w"); fopen(p, "r"); }'
        rules, findings = self.rules('code.c', code)
        self.assertIn('CPP_FS_DELETE', rules)
        self.assertEqual(sum(f['rule'] == 'CPP_FS_WRITE' for f in findings), 1)

    def test_control_fmt_algorithms_do_not_trigger_cpp_fs_delete(self):
        code = '#include <algorithm>\nvoid f() { std::remove(begin(), end(), 0); }'
        rules, _ = self.rules('format.hpp', code)
        self.assertNotIn('CPP_FS_DELETE', rules)
        self.assertNotIn('CPP_GEO_ACTION', rules)

    def test_control_magic_enum_header_stays_clean(self):
        code = ('#include <string_view>\n'
                'template<class E> constexpr std::string_view name(E value) {\n'
                ' return "enum";\n}\n')
        rules, _ = self.rules('magic_enum.hpp', code)
        self.assertFalse({'CPP_FS_DELETE', 'CPP_GEO_ACTION', 'CPP_NETWORK'} & rules)

    def test_js_unbounded_direct_network_request(self):
        for ext in ('js', 'ts'):
            with self.subTest(ext=ext):
                code = 'function run(u) { while (true) { fetch(u); } }'
                rules, findings = self.rules('source.' + ext, code)
                self.assertIn('NETWORK_FLOOD', rules)
                self.assertEqual(next(f for f in findings if f['rule'] == 'NETWORK_FLOOD')['severity'], 'high')

    def test_js_unbounded_network_request_via_helper(self):
        code = ('async function send(url) { return fetch(url); }\n'
                'async function flood(target) {\n'
                '  while (true) { await send(target); }\n'
                '}\n')
        rules, findings = self.rules('scripts/main.js', code)
        self.assertIn('NETWORK_FLOOD', rules)
        flow = next(f for f in findings if f['rule'] == 'NETWORK_FLOOD')['dataflow']
        self.assertIn('call', [x['kind'] for x in flow])
        self.assertEqual(flow[-1]['kind'], 'sink')

    def test_js_unbounded_non_network_loop_is_not_flood(self):
        rules, _ = self.rules('app.js', 'function spin(){ while(true) { let c=1; } }')
        self.assertNotIn('NETWORK_FLOOD', rules)

    def test_js_ordinary_minification_is_not_obfuscation(self):
        code = 'const total = 1; ' * 220
        rules, _ = self.rules('source.js', code)
        self.assertNotIn('OBFUSCATED_JS', rules)

    def test_js_layered_obfuscation_is_reported(self):
        table = ';'.join('value' + str(i) for i in range(65))
        code = ("let a='" + table + "'.split(';');\n"
                "function b(i) { return a[parseInt(i)]; }\n"
                "a.push(a.shift());\n"
                + 'console.log(' + '+'.join("b('0x%x')" % i for i in range(10)) + ');')
        rules, findings = self.rules('scripts/invisible.js', code)
        self.assertIn('OBFUSCATED_JS', rules)
        self.assertEqual(next(f for f in findings if f['rule'] == 'OBFUSCATED_JS')['severity'], 'medium')


if __name__ == '__main__':
    unittest.main()
