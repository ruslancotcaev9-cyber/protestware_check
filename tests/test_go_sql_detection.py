"""Go import identity and SQL command boundaries; all source remains inert."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import go_bindings
import language_analysis
import protestware_check as scanner
import report_formats
import sql_operations


class GoLiteralTests(unittest.TestCase):
    def test_import_literals_are_decoded_without_evaluation(self):
        for text in ('"os"', '`os`', r'"\x6f\x73"', r'"\157\163"', r'"\u006f\u0073"'):
            with self.subTest(text=text):
                self.assertEqual(go_bindings.unquote(text), 'os')
        self.assertNotEqual(go_bindings.unquote(r'"\\x6f\\x73"'), 'os')

    def test_discard_is_not_a_deletion_api(self):
        self.assertNotIn('GO_FS_DELETE', {f['rule'] for f in language_analysis.scan_language('x.go', 'io.Discard(data)', [])})


class GoImportDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Go grammar is required for import resolution tests')

    def scan(self, imports, body, parameters='', prefix=''):
        source = 'package fixture\n' + imports + '\n' + prefix + '\nfunc run(' + parameters + ') {\n' + body + '\n}\n'
        return scanner.scan_text('fixture.go', source, [], [], ast_mode='required')

    def rules(self, *args, **kwargs):
        return {finding['rule'] for finding in self.scan(*args, **kwargs)}

    def test_default_alias_dot_and_escaped_imports(self):
        for imports, call in (('import "os"', 'os.Remove(path)'), ('import fs "os"', 'fs.RemoveAll(path)'),
                              ('import (. "os")', 'Remove(path)'), ('import . `os`', 'RemoveAll(path)'),
                              (r'import fs "\x6f\x73"', 'fs.Remove(path)')):
            with self.subTest(imports=imports):
                findings = self.scan(imports, call)
                finding = next(f for f in findings if f['rule'] == 'GO_FS_DELETE')
                self.assertIn(finding['resolved_symbol'], {'os.Remove', 'os.RemoveAll'})
                self.assertEqual(finding['analysis'], 'tree-sitter-ast')

    def test_defer_go_multiline_and_parenthesized_calls(self):
        for call in ('defer fs.Remove(path)', 'go fs.RemoveAll(path)', 'fs.\nRemove(\npath\n)', '(fs.Remove)(path)'):
            with self.subTest(call=call):
                self.assertIn('GO_FS_DELETE', self.rules('import fs "os"', call))

    def test_parameter_and_result_names_shadow_imports(self):
        for parameters in ('os fake', 'value, os fake', 'os ...fake'):
            with self.subTest(parameters=parameters):
                rules = self.rules('import "os"', 'os.Remove(path)', parameters)
                self.assertNotIn('GO_FS_DELETE', rules)
                self.assertNotIn('FS_DELETE', rules)
        source = 'package p\nimport "os"\nfunc run() (os fake) { os.Remove(path); return }'
        rules = {f['rule'] for f in scanner.scan_text('x.go', source, [], [], ast_mode='required')}
        self.assertNotIn('GO_FS_DELETE', rules)

    def test_local_variables_and_dot_names_shadow(self):
        for imports, body in (('import "os"', 'os := fake; os.Remove(path)'),
                              ('import fs "os"', 'var fs fake; fs.Remove(path)'),
                              ('import . "os"', 'Remove := cleanup; Remove(path)'),
                              ('import . "os"', 'var RemoveAll = cleanup; RemoveAll(path)')):
            with self.subTest(body=body):
                self.assertNotIn('GO_FS_DELETE', self.rules(imports, body))

    def test_declaration_rhs_uses_outer_binding(self):
        findings = self.scan('import . "os"', 'Remove := Remove(path); use(Remove)')
        self.assertEqual(sum(f['rule'] == 'GO_FS_DELETE' for f in findings), 1)

    def test_inner_block_shadow_does_not_escape(self):
        findings = self.scan('import fs "os"', '{ fs := fake; fs.Remove(path) }; fs.Remove(path)')
        self.assertEqual(sum(f['rule'] == 'GO_FS_DELETE' for f in findings), 1)

    def test_if_for_range_and_type_switch_scopes(self):
        for body in ('if fs := fake; enabled { fs.Remove(path) }; fs.Remove(path)',
                     'for fs := fake; enabled; next() { fs.Remove(path) }; fs.Remove(path)',
                     'for _, fs := range values { fs.Remove(path) }; fs.Remove(path)',
                     'switch fs := value.(type) { case fake: fs.Remove(path) }; fs.Remove(path)'):
            with self.subTest(body=body):
                self.assertEqual(sum(f['rule'] == 'GO_FS_DELETE' for f in self.scan('import fs "os"', body)), 1)

    def test_receiver_parameter_and_closure_shadow(self):
        source = ('package p\nimport fs "os"\ntype fake struct{}\n'
                  'func (fs fake) run(){ fs.Remove(path) }\n'
                  'func run(){ f := func(fs fake){ fs.Remove(path) }; use(f) }')
        self.assertNotIn('GO_FS_DELETE', {f['rule'] for f in scanner.scan_text('x.go', source, [], [], ast_mode='required')})

    def test_type_switch_value_precedes_its_alias_scope(self):
        findings = self.scan('import . "os"', 'switch Remove := any(Remove(path)).(type) { case error: use(Remove) }')
        self.assertEqual(sum(f['rule'] == 'GO_FS_DELETE' for f in findings), 1)

    def test_other_import_blank_import_and_own_function_are_not_os(self):
        for imports, body, prefix in (('import fs "example.test/fs"', 'fs.Remove(path)', ''),
                                      ('import _ "os"', 'Remove(path)', ''),
                                      ('', 'Remove(path)', 'func Remove(path string) {}'),
                                      ('import "os"', 'object.os.Remove(path)', '')):
            with self.subTest(imports=imports, body=body):
                self.assertNotIn('GO_FS_DELETE', self.rules(imports, body, prefix=prefix))

    def test_strings_comments_and_similar_names_are_not_calls(self):
        rules = self.rules('import fs "os"', 'println("fs.Remove(path)"); /* fs.RemoveAll(path) */ fs.RemoveAt(path)')
        self.assertNotIn('GO_FS_DELETE', rules)

    def test_geographic_correlation_uses_resolved_calls(self):
        for imports, call in (('import fs "os"', 'fs.RemoveAll(path)'), ('import . "os"', 'Remove(path)')):
            self.assertIn('AST_GEO_ACTION', self.rules(imports, 'if country == "RU" { ' + call + ' }'))
        self.assertNotIn('AST_GEO_ACTION', self.rules('import fs "os"', 'fs := fake; if country == "RU" { fs.RemoveAll(path) }'))

    def test_ambiguous_dot_imports_are_explicitly_partial(self):
        with self.assertRaisesRegex(scanner.ScanError, 'ambiguous dot imports'):
            self.scan('import (. "os"; . "example.test/other")', 'Remove(path)')

    def test_no_target_execution_and_sarif_preserves_symbol(self):
        with patch('subprocess.run', side_effect=AssertionError('No Go invocation')):
            findings = self.scan('import fs "os"', 'fs.Remove(path)')
        report = {'tool': 'protestware-check', 'version': scanner.VERSION, 'source': 'inert', 'findings': findings}
        result = next(x for x in report_formats.sarif(report)['runs'][0]['results'] if x['ruleId'] == 'GO_FS_DELETE')
        self.assertEqual(result['properties']['resolved_symbol'], 'os.Remove')


class SqlCommandTests(unittest.TestCase):
    def rules(self, code):
        return {f['rule'] for f in scanner.scan_text('fixture.sql', code, [], [], ast_mode='off')}

    def test_postgresql_truncate_forms(self):
        for code in ('TRUNCATE records;', 'truncate table records;', 'TRUNCATE ONLY public.records;',
                     'TRUNCATE TABLE ONLY "schema"."records" RESTART IDENTITY CASCADE;',
                     'TRUNCATE records*, other CONTINUE IDENTITY RESTRICT;',
                     'TRUNCATE\n/* reason */\nTABLE\nrecords;', 'BEGIN; TRUNCATE records; ROLLBACK;'):
            with self.subTest(code=code):
                self.assertIn('SQL_DESTRUCTIVE', self.rules(code))

    def test_strings_dollar_quotes_identifiers_and_comments(self):
        for code in ("SELECT 'TRUNCATE records; DROP TABLE x';", 'SELECT "TRUNCATE TABLE records" FROM t;',
                     "SELECT 'It''s TRUNCATE TABLE records';", 'SELECT $$TRUNCATE records; DROP TABLE x$$;',
                     'SELECT $body$TRUNCATE records; DROP TABLE x$body$;',
                     r"SELECT E'can\'t; TRUNCATE records; DROP TABLE x';",
                     '/* outer /* nested */ TRUNCATE records; DROP TABLE x */ SELECT 1;',
                     '-- TRUNCATE records;\nSELECT 1;', 'SELECT truncate(value, 3) FROM t;',
                     'SELECT value AS truncate FROM t;', 'CREATE TABLE truncate_log(id int);'):
            with self.subTest(code=code):
                self.assertNotIn('SQL_DESTRUCTIVE', self.rules(code))

    def test_multiple_commands_and_line_numbers(self):
        code = 'SELECT $$hidden; TRUNCATE x$$;\n-- note\nTRUNCATE records;\nTRUNCATE TABLE archive;'
        findings = [f for f in scanner.scan_text('x.sql', code, [], [], ast_mode='off') if f['rule'] == 'SQL_DESTRUCTIVE']
        self.assertEqual([f['line'] for f in findings], [3, 4])

    def test_mask_preserves_offsets_and_newlines(self):
        code = 'SELECT $a$DROP\nTABLE x$a$, "TRUNCATE TABLE x"; /* nested /* x */ tail */\nTRUNCATE t;'
        masked = sql_operations.mask(code)
        self.assertEqual(len(code), len(masked))
        self.assertEqual([i for i, c in enumerate(code) if c == '\n'], [i for i, c in enumerate(masked) if c == '\n'])
        self.assertNotIn('DROP', masked)
        self.assertEqual(sql_operations.truncates(code), [3])

    def test_dynamic_sql_signal_is_preserved(self):
        self.assertIn('SQL_DYNAMIC', self.rules("EXECUTE IMMEDIATE 'TRUNCATE records';"))
        self.assertNotIn('SQL_DESTRUCTIVE', self.rules("EXECUTE IMMEDIATE 'TRUNCATE records';"))

    def test_validated_parser_options_preserve_utf8_offsets(self):
        code = 'TRUNCATE TABLE ONLY "данные"*, other RESTART IDENTITY CASCADE;'
        normalized = sql_operations.parser_source(code)
        self.assertEqual(len(code.encode()), len(normalized.encode()))
        self.assertEqual(normalized.index('"данные"'), code.index('"данные"'))
        self.assertNotIn('RESTART', normalized)
        for invalid in ('TRUNCATE t RESTART IDENTITY SELECT 1;', 'TRUNCATE t RESTART;',
                        "SELECT 'TRUNCATE t RESTART IDENTITY';", 'TRUNCATE t,;', 'TRUNCATE t RESTART ıdentity;'):
            self.assertEqual(sql_operations.parser_source(invalid), invalid)


class SqlGrammarOptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('SQL grammar required')

    def test_postgresql_options_in_required_mode(self):
        for code in ('TRUNCATE t RESTART IDENTITY;', 'TRUNCATE TABLE ONLY "данные" CASCADE;',
                     'TRUNCATE t*, other CONTINUE IDENTITY RESTRICT;'):
            with self.subTest(code=code):
                rules = {f['rule'] for f in scanner.scan_text('x.sql', code, [], [], ast_mode='required')}
                self.assertIn('SQL_DESTRUCTIVE', rules)

    def test_unrecognized_trailing_sql_is_not_normalized(self):
        with self.assertRaises(scanner.ScanError):
            scanner.scan_text('x.sql', 'TRUNCATE t RESTART IDENTITY SELECT 1;', [], [], ast_mode='required')

    def test_cli_medium_gate_without_ast(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder, 'source'); source.mkdir()
            (source / 'code.sql').write_text('TRUNCATE records;')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = scanner.main(['--path', str(source), '--dependencies', 'off', '--ast-mode', 'off', '--fail-on', 'medium', '--format', 'json'])
            self.assertEqual(code, 1)
            self.assertTrue(any(f['rule'] == 'SQL_DESTRUCTIVE' for f in json.loads(out.getvalue())['findings']))


if __name__ == '__main__':
    unittest.main()
