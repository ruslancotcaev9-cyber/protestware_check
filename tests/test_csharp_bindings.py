"""Filesystem identities from selected C# declarations, with hostile lookalikes."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import csharp_bindings
import polyglot_ast
import protestware_check as scanner
from report_formats import sarif

ROOT = Path(__file__).resolve().parents[1]


class CSharpBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('C# grammar required')

    def scan(self, code, mode='required'):
        return scanner.scan_text('fixture.cs', code, [], [], ast_mode=mode)

    def calls(self, code):
        root = polyglot_ast._parser('csharp').parse(code.encode()).root_node
        self.assertFalse(root.has_error, code)
        return csharp_bindings.resolve(code, root)

    def symbols(self, code):
        return [f['resolved_symbol'] for f in self.scan(code) if f['rule'] == 'CS_FS_DELETE']

    def test_readonly_fields_match_both_pinned_cake_files(self):
        cases = json.loads((ROOT / 'tests/corpus/fresh-v7.json').read_text())['cases']
        for case in cases:
            if case['provenance']['repository'] == 'cake-build/cake':
                findings = self.scan(case['code'])
                deletion = [f for f in findings if f['rule'] == 'CS_FS_DELETE']
                self.assertEqual(bool(deletion), case['positive'])
                for finding in deletion:
                    self.assertIn(finding['resolved_symbol'], {'System.IO.FileInfo.Delete', 'System.IO.DirectoryInfo.Delete'})
                    self.assertEqual(finding['binding_basis'], 'selected-file-type')
                    self.assertEqual(finding['dataflow'][-1]['kind'], 'sink')

    def test_locals_parameters_fields_and_target_typed_new(self):
        code = '''using System.IO;
        class C { readonly FileInfo f = new("a"); DirectoryInfo d;
          C(){d=new DirectoryInfo("b");}
          void M(FileInfo input) { var local = input; local.Delete();
            this.f.Delete();
            d.Delete(true);
            new FileInfo("c").Delete(); } }'''
        self.assertEqual(self.symbols(code).count('System.IO.FileInfo.Delete'), 3)
        self.assertIn('System.IO.DirectoryInfo.Delete', self.symbols(code))

    def test_namespace_type_aliases_and_global_qualification(self):
        for prefix, call in (
            ('using IO = System.IO;', 'new IO.FileInfo("x").Delete()'),
            ('using FI = global::System.IO.FileInfo;', 'new FI("x").Delete()'),
            ('', 'new global::System.IO.DirectoryInfo("x").Delete(true)'),
            ('using F = System.IO.File;', 'F.Delete("x")'),
            ('namespace System.IO;', 'File.Delete("x")')):
            with self.subTest(call=call):
                self.assertTrue(self.symbols(prefix + ' class C { void M(){' + call + ';} }'))

    def test_namespace_scoped_imports_do_not_escape(self):
        code = '''namespace A { using System.IO; class C {void M(){File.Delete("a");}} }
        namespace B { class File {public static void Delete(string x){}}
          class C {void M(){File.Delete("b");}} }'''
        calls, diagnostics = self.calls(code)
        # A same-named selected type in another namespace conservatively blocks
        # unqualified File, rather than pretending to run a compiler.
        self.assertFalse(calls)

    def test_static_imports_and_local_method_shadowing(self):
        self.assertEqual(self.symbols('using static System.IO.File; class C {void M(){Delete("x");}}'), ['System.IO.File.Delete'])
        for code in (
            'using static System.IO.File; class C {void Delete(string p){} void M(){Delete("x");}}',
            'using static System.IO.File; class C {void M(){void Delete(string p){} Delete("x");}}'):
            self.assertFalse(self.calls(code)[0])

    def test_user_defined_fileinfo_and_directoryinfo_are_not_native(self):
        for name in ('FileInfo', 'DirectoryInfo', 'File', 'Directory'):
            code = f'''using System.IO; class {name} {{ public {name}(string p){{}}
            public void Delete(){{}} }} class C {{ void M(){{new {name}("x").Delete();}} }}'''
            self.assertFalse(self.symbols(code))

    def test_shadowed_static_names_and_parameter_types(self):
        for body in ('void M(Fake File){File.Delete("x");}',
                     'void M(){var File=new Fake();File.Delete("x");}',
                     'void M<FileInfo>(FileInfo value){value.Delete();}'):
            code = 'using System.IO; class Fake {public void Delete(string x){}} class C {' + body + '}'
            self.assertFalse(self.calls(code)[0])

    def test_namespace_lookalikes_and_aliases_do_not_gain_identity(self):
        for prefix, expression in (
            ('using FI = Other.FileInfo;', 'new FI("x").Delete()'),
            ('using IO = Other;', 'new IO.FileInfo("x").Delete()'),
            ('', 'new Other.FileInfo("x").Delete()'),
            ('using FI = System.IO.FileInfo;', 'new FI("x").Delete()')):
            extra = 'class System {public class IO {public class FileInfo {}}}' if 'System.IO.FileInfo' in prefix else ''
            code = prefix + extra + ' class C {void M(){' + expression + ';}}'
            self.assertFalse(self.calls(code)[0])

    def test_global_namespace_bypasses_a_local_system_name(self):
        code = 'namespace N {class System {} class C {void M(){new global::System.IO.FileInfo("x").Delete();}}}'
        self.assertEqual(self.symbols(code), ['System.IO.FileInfo.Delete'])

    def test_source_declared_system_io_type_blocks_even_global_name(self):
        code = '''namespace System.IO {class FileInfo {public FileInfo(string p){} public void Delete(){}}}
        class C {void M(){new global::System.IO.FileInfo("x").Delete();}}'''
        self.assertFalse(self.symbols(code))

    def test_local_scopes_restore_fields_after_shadowing(self):
        code = '''using System.IO; class Fake {public void Delete(){}}
        class C {FileInfo f; void M(){{var f=new Fake();f.Delete();} f.Delete();}}'''
        self.assertEqual(self.symbols(code), ['System.IO.FileInfo.Delete'])

    def test_null_conditional_parentheses_and_null_forgiving(self):
        for call in ('f?.Delete()', '(f).Delete()', 'f!.Delete()'):
            self.assertEqual(self.symbols('using System.IO; class C {void M(FileInfo f){'+call+';}}'), ['System.IO.FileInfo.Delete'])

    def test_typed_lambda_and_foreach_parameters(self):
        code = '''using System.IO; class C {void M(){
          System.Action<FileInfo> a=(FileInfo f)=>f.Delete();
          foreach (DirectoryInfo d in dirs) {d.Delete();} }}'''
        self.assertEqual(set(self.symbols(code)), {'System.IO.FileInfo.Delete','System.IO.DirectoryInfo.Delete'})

    def test_parameters_and_fields_of_other_classes_do_not_leak(self):
        code = '''using System.IO; class C {FileInfo f; void M(){f.Delete();}}
          class D {object f;void M(){f.Delete();}}'''
        calls, diagnostics = self.calls(code)
        self.assertEqual(len(calls), 1)
        self.assertTrue(diagnostics)

    def test_unknown_factory_and_dynamic_receiver_are_explicitly_partial(self):
        for expression in ('Get().Delete()', 'd.Delete()'):
            code = 'class C {void M(dynamic d){' + expression + ';}}'
            calls, diagnostics = self.calls(code)
            self.assertFalse(calls)
            self.assertTrue(diagnostics)
            with self.assertRaises(scanner.ScanError):
                self.scan(code)

    def test_implicit_global_using_is_not_assumed(self):
        calls, diagnostics = self.calls('class C {void M(){Directory.Delete("x");}}')
        self.assertFalse(calls)
        self.assertTrue(diagnostics)

    def test_strings_comments_and_uninvoked_method_groups_are_not_calls(self):
        code = '''using System.IO; class C {void M(FileInfo f){
        // f.Delete(); File.Delete("x");
        var text="f.Delete()"; var method=f.Delete; var name=nameof(f.Delete);}}'''
        self.assertFalse(self.symbols(code))

    def test_geographic_action_uses_bound_identity(self):
        code = '''using System.IO; class C {void M(string country, FileInfo f){
          if(country=="RU"){f.Delete();}}}'''
        self.assertIn('AST_GEO_ACTION', {f['rule'] for f in self.scan(code)})
        geo = next(f for f in self.scan(code) if f['rule']=='AST_GEO_ACTION')
        self.assertEqual(geo['resolved_symbol'],'System.IO.FileInfo.Delete')
        self.assertEqual(geo['dataflow'][0]['kind'],'condition')
        safe = 'class File {public static void Delete(string x){}} class C {void M(string country){if(country=="RU"){File.Delete("x");}}}'
        self.assertFalse({'CS_FS_DELETE','AST_GEO_ACTION'} & {f['rule'] for f in self.scan(safe)})

    def test_sarif_retains_type_identity_and_source_route(self):
        report = scanner.build_report('inert', [('x.cs','using System.IO; class C {FileInfo f;void M(){f.Delete();}}')], [], [], [], dependency_mode='off',ast_mode='required')
        result = next(r for r in sarif(report)['runs'][0]['results'] if r['ruleId']=='CS_FS_DELETE')
        self.assertEqual(result['properties']['resolved_symbol'],'System.IO.FileInfo.Delete')
        self.assertTrue(result['codeFlows'])

    def test_budget_and_no_target_execution(self):
        code = 'using System.IO; class C {void M(){File.Delete("x");}}'
        root = polyglot_ast._parser('csharp').parse(code.encode()).root_node
        self.assertTrue(csharp_bindings.resolve(code,root,max_nodes=1)[1])
        with patch('builtins.open', side_effect=AssertionError('No target reads')), patch('subprocess.run', side_effect=AssertionError('No target execution')):
            self.assertTrue(csharp_bindings.resolve(code,root)[0])

    def test_reassignments_do_not_change_a_statically_declared_type(self):
        code = '''using System.IO; class C {void M(FileInfo input){
        var value=input;value=OtherFactory();value.Delete();}}'''
        self.assertEqual(self.symbols(code), ['System.IO.FileInfo.Delete'])

    def test_untyped_lambda_parameter_shadows_static_file(self):
        code='using System.IO; class C {void M(){var callback=File=>File.Delete("x");}}'
        calls, diagnostics=self.calls(code)
        self.assertFalse(calls)
        self.assertTrue(diagnostics)

    def test_repeated_context_lookup_has_a_separate_budget(self):
        code = 'using System.IO; ' + '\n'.join(
            f'class C{i} {{FileInfo f;void M(){{f.Delete();}}}}' for i in range(80))
        root = polyglot_ast._parser('csharp').parse(code.encode()).root_node
        calls, diagnostics = csharp_bindings.resolve(code,root,max_context_steps=100)
        self.assertTrue(calls)
        self.assertTrue(any('context budget exceeded' in item for item in diagnostics))


if __name__ == '__main__':
    unittest.main()
