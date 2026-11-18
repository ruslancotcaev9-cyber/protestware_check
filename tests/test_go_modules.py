"""Native Root types and selected-package wrappers without executing Go."""
from hashlib import sha256, sha1
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import corpus_evaluation
from go_modules import Project
import polyglot_ast
import protestware_check as scanner
from report_formats import sarif

ROOT = Path(__file__).resolve().parents[1]


class GoModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Go grammar required')

    def scan(self, body, prefix='import "os"', parameters='r *os.Root'):
        code='package p\n'+prefix+'\nfunc M('+parameters+') {\n'+body+'\n}'
        return scanner.scan_text('x.go',code,[],[],ast_mode='required')

    def project(self, caller=None, helper=None, **limits):
        helper = helper or ('package p\nimport "os"\ntype FS struct{root *os.Root}\n'
                            'func (f *FS) Remove(p string)error{return f.root.Remove(p)}')
        caller = caller or 'package p\nfunc Make()*FS{return nil}\nfunc M(){r:=Make();r.Remove("x")}'
        return Project([('api.go',helper),('main.go',caller)],**limits)

    def test_pointer_parameters_and_value_parameters(self):
        for parameter in ('r *os.Root','r os.Root'):
            fs=[f for f in self.scan('r.Remove("x")',parameters=parameter) if f['rule']=='GO_FS_DELETE']
            self.assertEqual(fs[0]['resolved_symbol'],'os.Root.Remove')
            self.assertEqual(fs[0]['binding_basis'],'selected-go-types')

    def test_openroot_tuple_var_and_native_child_root(self):
        for statement in ('r,_:=os.OpenRoot("x")','var r,err=os.OpenRoot("x");_ = err',
                          'parent,_:=os.OpenRoot("x");r,_:=parent.OpenRoot("sub")'):
            findings=self.scan(statement+'\nr.RemoveAll("x")',parameters='')
            self.assertTrue(any(f.get('resolved_symbol')=='os.Root.RemoveAll' for f in findings))

    def test_constructor_new_root_and_top_level_alias(self):
        for statement,prefix in (('r:=new(os.Root)','import "os"'),
                                 ('r:=new(R)','import "os"\ntype R = os.Root'),
                                 ('var r *R','import "os"\ntype R = *os.Root'),
                                 ('r:=os.Root{}','import "os"')):
            self.assertTrue(any(f.get('resolved_symbol')=='os.Root.Remove' for f in self.scan(statement+'\nr.Remove("x")',prefix,parameters='')))

    def test_import_alias_and_escaped_standard_library_path(self):
        for source in ('import fs "os"',r'import fs "\x6f\x73"'):
            self.assertTrue(any(f.get('resolved_symbol')=='os.Root.Remove' for f in self.scan('r.Remove("x")',source,'r *fs.Root')))

    def test_root_fields_and_this_receiver(self):
        code='package p\nimport "os"\ntype FS struct{a,b *os.Root}\nfunc(f *FS)M(){f.a.Remove("a");\nf.b.RemoveAll("b")}'
        p=Project([('api.go',code)])
        self.assertEqual({x[1] for x in p.calls('api.go')[0].values()},{'os.Root.Remove','os.Root.RemoveAll'})

    def test_shadowed_import_and_local_scope(self):
        prefix='import "os"\ntype Fake struct{}\nfunc(Fake)Remove(string){}'
        fs=self.scan('{r:=Fake{};r.Remove("x")}\nr.Remove("x")',prefix)
        self.assertEqual(sum(f['rule']=='GO_FS_DELETE' for f in fs),1)
        fs=self.scan('os:=Fake{};os.Remove("x")',prefix)
        self.assertFalse([f for f in fs if f['rule']=='GO_FS_DELETE'])

    def test_other_package_root_is_not_os_root(self):
        fs=self.scan('r.Remove("x")','import os "example.test/os"','r *os.Root')
        self.assertFalse([f for f in fs if f['rule']=='GO_FS_DELETE'])

    def test_defined_root_type_does_not_inherit_methods_from_underlying_type(self):
        code='package p\nimport "os"\ntype R os.Root\nfunc(R)Remove(string){}\nfunc M(r R){r.Remove("x")}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_builtin_new_can_be_shadowed(self):
        code='package p\ntype Fake struct{}\nfunc new(string)*Fake{return nil}\nfunc(*Fake)Remove(string){}\nfunc M(){r:=new("x");r.Remove("x")}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_dot_import_and_generic_parameter_shadow(self):
        self.assertTrue(self.scan('r.Remove("x")','import . "os"','r *Root'))
        code='package p\nimport . "os"\nfunc M[Root interface{Remove(string)error}](r Root){r.Remove("x")}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_interface_dispatch_is_not_inferred_from_method_name(self):
        code='package p\ntype I interface{Remove(string)error}\nfunc M(r I){r.Remove("x")}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_selected_files_link_return_types_and_wrapper_methods(self):
        p=self.project();calls,diagnostics=p.calls('main.go')
        self.assertFalse(diagnostics);self.assertTrue(p.metadata()['complete'])
        self.assertEqual({x[1] for x in calls.values()},{'os.Root.Remove'})
        route=next(iter(calls.values()))[2]
        self.assertIn('return-type',{h[2] for h in route})
        self.assertEqual({h[0] for h in route},{'main.go','api.go'})

    def test_package_directory_test_and_build_scope_boundaries(self):
        helper='package p\nimport "os"\ntype FS struct{root *os.Root}\nfunc(f *FS)Remove(p string)error{return f.root.Remove(p)}'
        caller='package p\nfunc Make()*FS{return nil}\nfunc M(){Make().Remove("x")}'
        for path,source in (('sub/api.go',helper),('api.go',helper.replace('package p','package q')),
                            ('api_test.go',helper),('api.go','//go:build linux\n\n'+helper)):
            p=Project([('main.go',caller),(path,source)])
            self.assertFalse(p.calls('main.go')[0]);self.assertTrue(p.calls('main.go')[1])

    def test_matching_build_tags_allow_selected_package_links(self):
        helper='//go:build !js\n\npackage p\nimport "os"\ntype FS struct{root *os.Root}\nfunc(f *FS)Remove(p string)error{return f.root.Remove(p)}'
        caller='//go:build !js\n\npackage p\nfunc Make()*FS{return nil}\nfunc M(){Make().Remove("x")}'
        p=self.project(caller,helper)
        self.assertTrue(p.calls('main.go')[0], (p.metadata(), p.calls('main.go')[1]))

    def test_missing_duplicate_and_broken_helpers_do_not_establish_links(self):
        caller='package p\nfunc Make()*FS{return nil}\nfunc M(){Make().Remove("x")}'
        p=Project([('main.go',caller)]);self.assertFalse(p.calls('main.go')[0]);self.assertTrue(p.calls('main.go')[1])
        good='package p\nimport "os"\ntype FS struct{root *os.Root}\nfunc(f *FS)Remove(p string)error{return f.root.Remove(p)}'
        for files in ([('api.go',good),('api.go',good)], [('api.go',good+'\nfunc broken(')]):
            p=Project([('main.go',caller),*files]);self.assertFalse(p.calls('main.go')[0]);self.assertTrue(p.calls('main.go')[1])

    def test_duplicate_declarations_are_ambiguous(self):
        helper='package p\nimport "os"\ntype FS struct{root *os.Root}\nfunc(f *FS)Remove(p string)error{return f.root.Remove(p)}'
        p=Project([('api.go',helper),('other.go',helper),('main.go','package p\nfunc M(r *FS){r.Remove("x")}')])
        self.assertFalse(p.calls('main.go')[0]);self.assertTrue(p.calls('main.go')[1])

    def test_recursive_summaries_stabilize_and_routes_are_bounded(self):
        code='package p\nimport "os"\nfunc a(r *os.Root){b(r)}\nfunc b(r *os.Root){a(r);r.Remove("x")}\nfunc M(r *os.Root){a(r)}'
        p=Project([('x.go',code)]);self.assertTrue(p.calls('x.go')[0]);self.assertTrue(p.metadata()['complete'])
        code='package p\nimport "os"\nfunc f0(r *os.Root){r.Remove("x")}\n'+'\n'.join(f'func f{i}(r *os.Root){{f{i-1}(r)}}' for i in range(1,60))
        p=Project([('x.go',code)]);self.assertEqual(len(p.calls('x.go')[0]),60)
        self.assertTrue(all(len(x[2])<=24 for x in p.calls('x.go')[0].values()))

    def test_alias_cycles_are_explicit(self):
        p=Project([('x.go','package p\ntype A=B\ntype B=A\nfunc M(a A){a.Remove("x")}')])
        self.assertFalse(p.calls('x.go')[0]);self.assertTrue(p.calls('x.go')[1])

    def test_escaped_callback_does_not_make_factory_creation_a_deletion(self):
        code='package p\nimport "os"\nfunc Make(r *os.Root)func(){return func(){r.Remove("x")}}\nfunc M(r *os.Root){Make(r)}'
        p=Project([('x.go',code)]);calls=p.calls('x.go')[0]
        self.assertEqual(len(calls),1)
        self.assertEqual(next(iter(calls.values()))[0].start_point[0]+1,3)

    def test_unused_native_argument_does_not_create_a_deletion(self):
        code='package p\nimport "os"\nfunc Safe(r *os.Root){}\nfunc M(r *os.Root){Safe(r)}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_range_receivers_are_not_inferred_from_the_container(self):
        helper='package p\nimport "os"\ntype Other struct{}\nfunc(Other)Remove(string){}\ntype FS struct{root *os.Root;items chan Other}\nfunc(f *FS)Remove(p string)error{return f.root.Remove(p)}\nfunc M(f *FS){for r:=range f.items{r.Remove("x")}}'
        self.assertEqual(len(Project([('x.go',helper)]).calls('x.go')[0]),1)

    def test_method_value_is_not_an_executed_deletion(self):
        code='package p\nimport "os"\nfunc M(r *os.Root){remove:=r.Remove;_=remove}'
        self.assertFalse(Project([('x.go',code)]).calls('x.go')[0])

    def test_geographic_correlation_and_sarif_keep_selected_type_route(self):
        code='package p\nimport "os"\nfunc M(r *os.Root,country string){if country=="RU"{r.Remove("x")}}'
        report=scanner.build_report('inert',[('x.go',code)],[],[],[],dependency_mode='off',ast_mode='required')
        geo=next(f for f in report['findings'] if f['rule']=='AST_GEO_ACTION')
        self.assertEqual(geo['resolved_symbol'],'os.Root.Remove')
        self.assertEqual(geo['dataflow'][0]['kind'],'condition')
        deletion=next(r for r in sarif(report)['runs'][0]['results'] if r['ruleId']=='GO_FS_DELETE')
        self.assertEqual(deletion['properties']['resolved_symbol'],'os.Root.Remove')
        self.assertTrue(deletion['codeFlows']);self.assertTrue(report['ast']['go_modules']['complete'])

    def test_helper_findings_do_not_satisfy_a_negative_primary(self):
        helper='package p\nimport "os"\nfunc Clean(r *os.Root){r.Remove("x")}'
        raw=helper.encode()
        case={'id':'negative','language':'Go','path':'main.go','code':'package p\nfunc Safe(){}','rule':'GO_FS_DELETE','positive':False,'ast_mode':'auto',
              'project_files':[{'path':'api.go','code':helper,'sha256':sha256(raw).hexdigest(),'git_blob_sha':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}]}
        result=corpus_evaluation.evaluate([case]);self.assertEqual(result['overall']['tn'],1);self.assertEqual(result['overall']['errors'],0)

    def test_resource_budgets_and_no_target_reads_execution_or_network(self):
        p=self.project(max_edges=0);self.assertTrue(p.calls('main.go')[1]);self.assertTrue(p.calls('api.go')[0])
        for limits in ({'max_files':1},{'max_bytes':1},{'max_nodes':1},{'max_steps':1},{'max_declarations':1},{'max_summary_steps':0}):
            self.assertTrue(self.project(**limits).global_diagnostics,limits)
        files=[('x.go','package p\nimport "os"\nfunc M(r *os.Root){r.Remove("x")}')]
        trees={p:polyglot_ast._parser('go').parse(c.encode()) for p,c in files}
        with patch('builtins.open',side_effect=AssertionError('No target reads')),patch('subprocess.run',side_effect=AssertionError('No execution')),patch('urllib.request.urlopen',side_effect=AssertionError('No network')):
            self.assertTrue(Project(files,trees=trees).calls('x.go')[0])

    def test_required_rejects_partial_graph_and_paths_are_canonical(self):
        p=self.project(max_edges=0)
        with self.assertRaises(scanner.ScanError):scanner.scan_text('main.go',p.units['main.go'].source,[],[],ast_mode='required',go_project=p)
        for path in ('../x.go','/x.go','a\\x.go','x\n.go'):
            self.assertTrue(Project([(path,'package p')]).global_diagnostics)

    def test_original_pinned_os_root_and_boundos_project(self):
        original=json.loads((ROOT/'tests/corpus/fresh-v7.json').read_text())['cases']
        files=[(c['path'],c['code']) for c in original if c['provenance']['repository']=='go-git/go-billy' and c['positive']]
        p=Project(files)
        for path,_ in files:
            self.assertEqual({x[1] for x in p.calls(path)[0].values()},{'os.Root.Remove','os.Root.RemoveAll'})
            self.assertFalse(p.calls(path)[1])


if __name__=='__main__':unittest.main()
