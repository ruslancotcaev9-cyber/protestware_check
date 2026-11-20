"""Selected-source C# summaries. All C# test inputs are inert text."""
import json
from pathlib import Path
import unittest

import csharp_project
import protestware_check as scanner
from report_formats import sarif

ROOT = Path(__file__).resolve().parents[1]
DEFINITION = '''using System.IO;
namespace Demo;
class Document {}
static class Methods {
    public static void Clean(this Document doc) { File.Delete("fixture"); }
}
'''


class CSharpProjectTests(unittest.TestCase):
    def scan(self, files, mode='required'):
        return scanner.build_report('regression', files, [], [], [], ast_mode=mode, dependency_mode='off')

    def test_pinned_nuke_caller_and_helper_with_sarif(self):
        cases = json.loads((ROOT/'tests/corpus/fresh-v8.json').read_bytes())['cases']
        pair = [(c['path'], c['code']) for c in cases if c['provenance']['repository'] == 'nuke-build/nuke' and c['positive']]
        helper, caller = (p for p, _ in pair)
        for files in (pair, list(reversed(pair))):
            report = self.scan(files)
            self.assertEqual(report['ast']['parsed'], 2)
            found = {f['line']: f for f in report['findings'] if f['rule'] == 'CS_FS_DELETE' and f['file'] == caller}
            self.assertEqual(set(found), {164, 224})
            for line, sink, symbol in [(164, 22, 'System.IO.File.Delete'), (224, 34, 'System.IO.Directory.Delete')]:
                item = found[line]
                self.assertEqual((item['resolved_symbol'], item['binding_basis']), (symbol, 'selected-csharp-method'))
                route = item['dataflow']
                self.assertEqual((route[-1]['file'], route[-1]['line']), (helper, sink))
                self.assertIn((caller, line, 'call'), [(h['file'], h['line'], h['kind']) for h in route])
            results = sarif(report)['runs'][0]['results']
            links = [r for r in results if r['ruleId'] == 'CS_FS_DELETE' and r['properties']['binding_basis'] == 'selected-csharp-method']
            self.assertEqual(len(links), 2)
            for link in links:
                hops = link['codeFlows'][0]['threadFlows'][0]['locations']
                self.assertEqual(hops[-1]['location']['physicalLocation']['artifactLocation']['uri'], helper)
        alone = self.scan([pair[1]])
        self.assertFalse(any(f['rule'] == 'CS_FS_DELETE' for f in alone['findings']))

    def test_partial_methods_and_scoped_alias(self):
        part = 'namespace Demo; partial class C { void Cleanup(){ System.IO.File.Delete("fixture"); } }'
        other = 'namespace Demo; partial class C { void Run(){ this.Cleanup(); } }'
        caller = 'using D = Demo.Document; using Demo; namespace UI; class Caller {void Run(D d){ var a=d; a.Clean(); }}'
        report = self.scan([('a.cs', part), ('b.cs', other), ('def.cs', DEFINITION), ('call.cs', caller)])
        self.assertEqual({f['file'] for f in report['findings'] if f.get('binding_basis') == 'selected-csharp-method'},
                         {'b.cs', 'call.cs'})

    def test_unrelated_types_scopes_and_uninvoked_callbacks(self):
        for declaration, caller in [
                (DEFINITION, 'namespace Demo; class Other {} class C { void M(Other d){d.Clean();} }'),
                (DEFINITION, 'using Document = Other.Doc; using Demo; class C {void M(Document d){d.Clean();}}'),
                (DEFINITION, 'namespace Hidden; class C {void M(Demo.Document d){d.Clean();}}'),
                (DEFINITION.replace('class Document {}','class Document { public void Clean(){} }'),
                 'namespace Demo; class C { void M(Document d){d.Clean();} }'),
                (DEFINITION.replace('File.Delete("fixture");','System.Action cb = () => File.Delete("fixture");'),
                 'namespace Demo; class C { void M(Document d){d.Clean();} }'),
                ('namespace N; partial class C {void Work(){System.IO.File.Delete("fixture");}}',
                 'namespace N; partial class C {void M(){void Work(){} Work();}}'),
                ('namespace A; partial class C {void Work(){System.IO.File.Delete("fixture");}}',
                 'namespace B; partial class C {void M(){Work();}}')]:
            with self.subTest(caller=caller, definition=declaration):
                report = self.scan([('a.cs',declaration), ('b.cs',caller)], 'auto')
                self.assertFalse(any(f.get('binding_basis') == 'selected-csharp-method' for f in report['findings']))

    def test_ambiguous_extensions_never_guessed_and_strict_fails(self):
        files = [('a.cs', DEFINITION), ('b.cs', DEFINITION.replace('class Document {}','').replace('Methods','Other')),
                 ('c.cs','namespace Demo; class C {void M(Document d){d.Clean();}}')]
        report = self.scan(files, 'auto')
        self.assertTrue(any('ambiguous' in w for w in report['warnings']))
        self.assertFalse(any(f.get('binding_basis') == 'selected-csharp-method' for f in report['findings']))
        with self.assertRaises(scanner.ScanError):
            self.scan(files)

    def test_project_budgets_and_directory_boundary(self):
        caller = 'namespace Demo; class C {void M(Document d){d.Clean();}}'
        files = [('p/a.cs', DEFINITION), ('q/b.cs', caller)]
        self.assertFalse(any(f.get('binding_basis') == 'selected-csharp-method' for f in self.scan(files)['findings']))
        for limit in ({'max_files':1},{'max_nodes':1},{'max_methods':1},{'max_bytes':1}):
            with self.subTest(limit=limit):
                obj = csharp_project.Project(files, **limit)
                self.assertIn('budget', obj.problem)
                self.assertTrue(obj.calls(files[0][0])[1])
