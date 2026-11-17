"""Static callable returns and separate captured environments; no target execution."""
import unittest
from unittest.mock import patch
from pathlib import Path
import corpus_evaluation

from js_modules import Project
import protestware_check as scanner
from report_formats import sarif


class JavaScriptFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('JS/TS grammar required')

    def project(self, api, main, **limits):
        return Project([('api.ts', api), ('main.ts', main)], **limits)

    def main(self, code):
        return "import {make} from './api.js'; import {rmSync} from 'fs';\n"+code

    def lines(self, project):
        return {node.start_point[0]+1 for node, symbol, route in project.calls('main.ts')[0].values()}

    def test_arrow_block_and_direct_native_returns(self):
        for api in ('export const make=fn=>p=>fn(p)',
                    'export function make(fn){return function(p){fn(p)}}',
                    'export function make(fn){return fn}'):
            p=self.project(api,self.main('const erase=make(rmSync);\nerase(path)'))
            self.assertEqual(self.lines(p),{3})
            self.assertTrue(p.metadata()['complete'])

    def test_creation_without_invocation_does_not_delete_in_the_caller(self):
        p=self.project('export const make=fn=>p=>fn(p)',self.main('const erase=make(rmSync)'))
        self.assertFalse(self.lines(p))

    def test_actual_factory_side_effect_is_distinct_from_invoking_its_result(self):
        p=self.project('export function make(fn){fn(path);return ()=>{}}',self.main('const safe=make(rmSync);\nsafe(path)'))
        self.assertEqual(self.lines(p),{2})

    def test_factory_ignoring_the_native_argument_does_not_return_it_implicitly(self):
        p=self.project('export function make(fn){return ()=>{}}',self.main('make(rmSync)(path)'))
        self.assertFalse(self.lines(p))

    def test_sync_factory_may_return_an_async_callable(self):
        p=self.project('export const make=fn=>async p=>fn(p)',self.main('make(rmSync)(path)'))
        self.assertEqual(self.lines(p),{2})
        self.assertTrue(p.metadata()['complete'])

    def test_captured_native_and_safe_instances_stay_separate(self):
        p=self.project('export const make=fn=>p=>fn(p)', self.main('const erase=make(rmSync); const safe=make(()=>{});\nerase(path);\nsafe(path)'))
        self.assertEqual(self.lines(p),{3})
        self.assertTrue(p.metadata()['complete'])

    def test_composed_factories_stabilize_before_caller_results_are_scored(self):
        api='const wrap=fn=>p=>fn(p); export const make=fn=>wrap(wrap(fn))'
        p=self.project(api,self.main('const erase=make(rmSync);\nerase(path)'))
        self.assertEqual(self.lines(p),{3})
        self.assertTrue(p.metadata()['complete'])

    def test_direct_invocation_and_default_callback(self):
        api="import {rmSync} from 'fs'; export function make(fn=rmSync){return p=>fn(p)}"
        for call in ('make()(path)', 'make(rmSync)(path)', 'make(/* comment */ rmSync)(path)'):
            p=self.project(api,self.main(call))
            self.assertEqual(self.lines(p),{2})

    def test_returned_object_method_keeps_its_capture(self):
        p=self.project('export const make=fn=>({erase:p=>fn(p)})',self.main('const disk=make(rmSync);\ndisk.erase(path)'))
        self.assertEqual(self.lines(p),{3})
        self.assertTrue(p.metadata()['complete'])

    def test_local_alias_and_commonjs_exported_factory(self):
        files=[('api.cjs','module.exports=fn=>p=>fn(p)'),
               ('main.cjs',"const make=require('./api.cjs'); const {rmSync}=require('fs'); const f=make(rmSync); const alias=f; alias(path)")]
        p=Project(files)
        self.assertTrue(p.calls('main.cjs')[0])

    def test_factory_reexport_keeps_all_local_modules_in_its_witness(self):
        p=Project([('impl.ts','export const make=fn=>p=>fn(p)'),('api.ts',"export {make} from './impl.js'"),('main.ts',self.main('make(rmSync)(path)'))])
        call=next(iter(p.calls('main.ts')[0].values()))
        self.assertEqual({hop['file'] for hop in call[2]},{'main.ts','api.ts','impl.ts'})

    def test_parameter_reassignment_and_literal_dead_return_do_not_invent_deletion(self):
        for api in ('export function make(fn){fn=()=>{};return p=>fn(p)}',
                    'export function make(fn){if(false)return fn;return ()=>{}}',
                    'export function make(fn){function unused(){fn(path)}return ()=>{}}'):
            p=self.project(api,self.main('make(rmSync)(path)'))
            self.assertFalse(self.lines(p),api)

    def test_reassignment_of_returned_callable_removes_later_identity(self):
        p=self.project('export const make=fn=>p=>fn(p)',self.main('let erase=make(rmSync);\nerase(path);\nerase=()=>{};erase(path)'))
        self.assertEqual(self.lines(p),{3})

    def test_returned_object_mutation_is_partial_and_preserves_earlier_calls(self):
        p=self.project('export const make=fn=>({erase:p=>fn(p)})', self.main('const disk=make(rmSync); const alias=disk;\ndisk.erase(path);\ndisk.erase=()=>{};alias.erase(path)'))
        self.assertEqual(self.lines(p),{3})
        self.assertIn('factory result property mutation',' '.join(p.diagnostics('main.ts')))

    def test_async_and_generator_factories_are_not_synchronous_callable_returns(self):
        for api in ('export async function make(fn){return p=>fn(p)}', 'export function* make(fn){return fn}'):
            p=self.project(api,self.main('make(rmSync)(path)'))
            self.assertFalse(self.lines(p))
            self.assertIn('async/generator',' '.join(p.diagnostics('main.ts')))

    def test_generator_creation_does_not_execute_its_body_in_the_caller(self):
        p=self.project("import {rmSync} from 'fs'; export function* make(){rmSync(path);yield 1}", self.main('const iterator=make()'))
        self.assertFalse(self.lines(p))
        self.assertIn('iterator execution',' '.join(p.diagnostics('main.ts')))

    def test_recursive_return_without_a_base_stabilizes_without_a_sink(self):
        p=self.project('export function make(fn){return make(fn)}', self.main('make(rmSync)(path)'))
        self.assertFalse(self.lines(p))
        self.assertTrue(p.metadata()['complete'])

    def test_closure_budget_is_explicit_and_required_refuses_partial(self):
        files=[('api.ts','export const make=fn=>p=>fn(p)'),('main.ts',self.main('make(rmSync)(path)'))]
        p=Project(files,max_closures=0)
        self.assertIn('closure budget',' '.join(p.diagnostics('main.ts')))
        with patch('js_modules.Project',return_value=p),self.assertRaisesRegex(scanner.ScanError,'partial'):
            scanner.build_report('inert',files,[],[],[],dependency_mode='off',ast_mode='required')

    def test_json_sarif_keep_factory_return_capture_and_sink_locations(self):
        files=[('api.ts','export const make=fn=>p=>fn(p)'),('main.ts',self.main("const erase=make(rmSync);\nif(country==='RU')erase(path)"))]
        with patch('subprocess.run',side_effect=AssertionError('No target execution')):
            report=scanner.build_report('inert',files,[],[],[],dependency_mode='off',ast_mode='required')
        result=next(f for f in report['findings'] if f['file']=='main.ts' and f['rule']=='AST_GEO_ACTION')
        self.assertTrue({'factory','return','capture','sink'} <= {hop['kind'] for hop in result['dataflow']})
        self.assertEqual({hop['file'] for hop in result['dataflow']},{'api.ts','main.ts'})
        self.assertTrue(next(r for r in sarif(report)['runs'][0]['results'] if r['ruleId']=='AST_GEO_ACTION')['codeFlows'])

    def test_pinned_rimraf_factory_invocations_are_separate_from_creation(self):
        root=Path(__file__).resolve().parents[1]
        case=next(c for c in corpus_evaluation.load(root/'tests/corpus/promoted.json') if c['id']=='promoted-rimraf-whole-v4-3')
        p=Project([(case['path'],case['code']),*((f['path'],f['code']) for f in case['project_files'])])
        sites={node.start_point[0]+1 for node,symbol,route in p.calls(case['path'])[0].values()}
        self.assertTrue({122,176}<=sites)
        self.assertFalse({26,27,28,29}&sites)


if __name__=='__main__':
    unittest.main()
