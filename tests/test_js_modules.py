"""Project-level JS/TS static links, precision boundaries and inert input handling."""
import unittest
from unittest.mock import patch

from js_modules import Project
import protestware_check as scanner
from report_formats import sarif


class JavaScriptProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('JS/TS grammar required for project analysis')

    def project(self, api, main, *, ext='ts', **limits):
        return Project([('api.' + ext, api), ('main.' + ext, main)], **limits)

    def calls(self, project, path='main.ts'):
        return project.calls(path)[0]

    def test_named_default_namespace_and_reexports(self):
        providers = [
            ("export {rmSync as erase} from 'node:fs'", "import {erase} from './api.js'; erase(path)"),
            ("export {rmSync as default} from 'fs'", "import erase from './api.js'; erase(path)"),
            ("export * from 'node:fs/promises'", "import * as disk from './api.js'; disk.rm(path)"),
            ("export * as disk from 'node:fs'", "import {disk} from './api.js'; disk.unlinkSync(path)"),
            ("import {rm} from 'fs/promises'; export const erase=rm", "import {erase} from './api.js'; erase(path)"),
        ]
        for api, main in providers:
            with self.subTest(api=api):
                project = self.project(api, main)
                self.assertEqual(len(self.calls(project)), 1)
                self.assertFalse(project.diagnostics('main.ts'))

    def test_wrapper_and_callback_parameter_reach_the_native_sink(self):
        api = "export const invoke=(fn,p)=>fn(p);"
        main = "import {invoke} from './api.js'; import {rmSync} from 'fs'; invoke(()=>rmSync(path),path)"
        found = self.calls(self.project(api, main))
        self.assertTrue(found)
        route = next(iter(found.values()))[2]
        self.assertTrue({'api.ts', 'main.ts'} <= {hop['file'] for hop in route})
        self.assertTrue(any(hop['kind'] == 'import' and hop['message'] == 'fs' for hop in route))

    def test_default_callback_and_typed_parameter(self):
        for parameter in ('fn=rmSync', 'fn: (p:string)=>void=rmSync'):
            api = "import {rmSync} from 'fs'; export function erase(" + parameter + "){fn(path)}"
            project = self.project(api, "import {erase} from './api.js'; erase()")
            self.assertTrue(self.calls(project))

    def test_commonjs_exports_objects_functions_and_alias_break(self):
        for api, main, expected in (
            ("exports.erase=require('fs').rmSync", "const {erase}=require('./api'); erase(path)", True),
            ("module.exports={erase:require('fs').rmSync}", "const disk=require('./api'); disk.erase(path)", True),
            ("module.exports=p=>require('fs').unlinkSync(p)", "const erase=require('./api'); erase(path)", True),
            ("exports={erase:require('fs').rmSync}", "const disk=require('./api'); disk.erase(path)", False),
            ("module.exports={}; exports.erase=require('fs').rmSync", "const disk=require('./api'); disk.erase(path)", False),
        ):
            with self.subTest(api=api):
                self.assertEqual(bool(self.calls(self.project(api, main, ext='cjs'), 'main.cjs')), expected)

    def test_extension_and_index_resolution_is_bounded_and_unambiguous(self):
        project = Project([('lib/index.ts', "export {rmSync} from 'fs'"), ('main.ts', "import {rmSync} from './lib'; rmSync(path)")])
        self.assertTrue(self.calls(project))
        project = Project([('api.ts', "export {rmSync} from 'fs'"), ('api.js', "export {rmSync} from 'fs'"),
                           ('main.ts', "import {rmSync} from './api.js'; rmSync(path)")])
        self.assertFalse(self.calls(project))
        self.assertIn('ambiguous', ' '.join(project.diagnostics('main.ts')))
        # Native ESM requires an explicit file extension; no speculative JS index lookup.
        project = self.project("export {rmSync} from 'fs'", "import {rmSync} from './api'; rmSync(path)", ext='js')
        self.assertFalse(self.calls(project, 'main.js'))

    def test_star_export_conflicts_do_not_choose_an_arbitrary_sink(self):
        project = Project([('a.ts', "export {rmSync as erase} from 'fs'"),
                           ('b.ts', 'export const erase=()=>{}'),
                           ('api.ts', "export * from './a.js'; export * from './b.js'"),
                           ('main.ts', "import {erase} from './api.js'; erase(path)")])
        self.assertFalse(self.calls(project))
        self.assertIn('ambiguous', ' '.join(project.diagnostics('main.ts')))

    def test_type_only_imports_do_not_create_runtime_edges(self):
        project = self.project("export {rmSync} from 'fs'", "import type {rmSync} from './api.js'; import {type rm} from './missing.js'; rmSync(path)")
        self.assertFalse(self.calls(project))
        self.assertEqual(project.metadata()['import_edges'], 0)
        self.assertFalse(project.diagnostics('main.ts'))

    def test_shadowing_reassignments_noop_and_unused_nested_functions(self):
        api = "export function erase(p){ function unused(){require('fs').rmSync(p)} }"
        self.assertFalse(self.calls(self.project(api, "import {erase} from './api.js'; erase(path)")))
        for main in ("import {erase} from './api.js'; function run(erase){erase(path)}",
                     "import {erase} from './api.js'; {erase(path); let erase=fake}",
                     "import {erase} from './api.js'; let f=erase; f=fake; f(path)"):
            self.assertFalse(self.calls(self.project("export {rmSync as erase} from 'fs'", main)))

    def test_dead_literal_branches_do_not_make_a_wrapper_destructive(self):
        for body in ("if(false){rmSync(path)}", "while(false){rmSync(path)}", "false && rmSync(path)",
                     "true || rmSync(path)", "return; rmSync(path)"):
            project = self.project("import {rmSync} from 'fs'; export function erase(){" + body + '}',
                                   "import {erase} from './api.js'; erase(path)")
            self.assertFalse(self.calls(project), body)

    def test_mutable_and_conditional_exports_are_partial_not_proven(self):
        for api in ("import {rmSync} from 'fs'; export let erase=rmSync; erase=fake",
                    "if(flag){exports.erase=require('fs').rmSync}"):
            ext = 'cjs' if 'exports.' in api else 'ts'
            main = "const {erase}=require('./api'); erase(path)" if ext == 'cjs' else "import {erase} from './api.js'; erase(path)"
            project = self.project(api, main, ext=ext)
            self.assertFalse(self.calls(project, 'main.' + ext))
            self.assertTrue(project.diagnostics('main.' + ext))

    def test_local_and_native_property_replacement_removes_identity(self):
        for api in ("const disk={erase:require('fs').rmSync}; disk.erase=()=>{}; module.exports=disk",
                    "const disk=require('fs'); disk.rmSync=()=>{}; exports.erase=disk.rmSync"):
            project = self.project(api, "const disk=require('./api'); disk.erase(path)", ext='cjs')
            self.assertFalse(self.calls(project, 'main.cjs'))
        for change in ('delete disk.erase', 'disk.erase++', 'disk.erase+=safe'):
            project = self.project("const disk={erase:require('fs').rmSync}; " + change + '; module.exports=disk',
                                   "require('./api').erase(path)", ext='cjs')
            self.assertFalse(self.calls(project, 'main.cjs'), change)

    def test_unknown_third_party_and_factories_are_not_whitelisted(self):
        for api in ("export {rmSync as erase} from 'graceful-fs'", "import {rmSync} from 'fs'; const factory=()=>rmSync; export const erase=factory()"):
            self.assertFalse(self.calls(self.project(api, "import {erase} from './api.js'; erase(path)")))
        self.assertFalse(self.calls(self.project("module.exports=require('fs').default", "require('./api').rmSync(path)", ext='cjs'), 'main.cjs'))

    def test_same_callback_helper_can_be_called_with_another_callback(self):
        project = self.project('export function invoke(fn){fn()}',
                               "import {invoke} from './api.js'; import {rmSync} from 'fs'; invoke(()=>invoke(()=>rmSync(path)))")
        self.assertTrue(self.calls(project))

    def test_native_namespace_mutation_does_not_prove_an_export(self):
        project = self.project("import * as fs from 'fs'; fs.rmSync=()=>{}; export const erase=fs.rmSync",
                               "import {erase} from './api.js'; erase(path)")
        self.assertFalse(self.calls(project))
        self.assertTrue(project.diagnostics('main.ts'))

    def test_object_spread_computed_and_duplicate_members_cannot_preserve_a_replaced_api(self):
        for members in ('erase:rmSync,...safe', 'erase:rmSync,[name]:safe', 'erase:rmSync,erase(){}',
                        'erase:rmSync,get erase(){return safe}'):
            project = self.project("import {rmSync} from 'fs'; export const disk={" + members + '}',
                                   "import {disk} from './api.js'; disk.erase(path)")
            self.assertFalse(self.calls(project), members)
        project = self.project("import {rmSync} from 'fs'; export const disk={erase(p){rmSync(p)}}",
                               "import {disk} from './api.js'; disk.erase(path)")
        self.assertTrue(self.calls(project))

    def test_only_selected_source_text_is_read_and_target_code_is_never_executed(self):
        with patch('builtins.open', side_effect=AssertionError('No target reads')), \
             patch('subprocess.run', side_effect=AssertionError('No execution')):
            project = self.project("export {rmSync as erase} from 'fs'", "import {erase} from './api.js'; erase(path)")
            self.assertTrue(self.calls(project))
            project = self.project("export {rmSync as erase} from 'fs'", "import {erase} from './outside.js'; erase(path)")
            self.assertFalse(self.calls(project))

    def test_escaping_encoded_and_nonlocal_paths_never_resolve(self):
        for specifier in ('../../api.js', './%61pi.js', './api.js?x', './api.js#x', './api\\\\x.js', '/api.js', 'https://host/api.js', 'C:/api.js'):
            project = self.project("export {rmSync} from 'fs'", "import {rmSync} from '" + specifier + "'; rmSync(path)")
            self.assertFalse(self.calls(project), specifier)

    def test_cycles_recursion_and_budgets_are_visible(self):
        project = self.project("export * from './main.js'", "export * from './api.js'; import {erase} from './api.js'; erase(path)")
        self.assertTrue(project.diagnostics('main.ts'))
        for limits in ({'max_modules': 1}, {'max_bytes': 1}, {'max_nodes': 1}, {'max_edges': 0}, {'max_contexts': 0}):
            project = self.project("export function erase(){require('fs').rmSync(path)}", "import {erase} from './api.js'; erase(path)", **limits)
            self.calls(project)
            self.assertTrue(project.diagnostics('main.ts'), limits)
        project = self.project("export function erase(){erase()}", "import {erase} from './api.js'; erase(path)")
        self.assertFalse(self.calls(project))
        self.assertTrue(project.diagnostics('main.ts'))

    def test_duplicate_and_noncanonical_paths_are_partial(self):
        for files in ([('a.ts', ''), ('a.ts', '')], [('../a.ts', 'x')], [('/a.ts', 'x')]):
            project = Project(files)
            self.assertFalse(project.metadata()['complete'])

    def test_report_geo_chain_sarif_and_tree_reuse(self):
        files = [('api.ts', "import {rmSync} from 'fs'; export const erase=(p)=>rmSync(p)"),
                 ('main.ts', "import {erase} from './api.js'; if(country==='RU') erase(path)")]
        import polyglot_ast
        original = polyglot_ast._parser
        with patch.object(polyglot_ast, '_parser', wraps=original) as parse:
            report = scanner.build_report('inert', iter(files), [], [], [], dependency_mode='off', ast_mode='required')
        self.assertEqual(parse.call_count, 2)
        self.assertTrue(report['ast']['modules']['complete'])
        geo = next(f for f in report['findings'] if f['file'] == 'main.ts' and f['rule'] == 'AST_GEO_ACTION')
        self.assertEqual(geo['dataflow'][0]['kind'], 'condition')
        self.assertEqual({hop['file'] for hop in geo['dataflow']}, {'api.ts', 'main.ts'})
        output = sarif(report)
        result = next(r for r in output['runs'][0]['results'] if r['ruleId'] == 'AST_GEO_ACTION')
        self.assertTrue(result['codeFlows'])
        self.assertEqual(result['properties']['module_analysis'], 'selected-text-only')

    def test_required_refuses_missing_local_context_auto_retains_observations(self):
        files = [('main.ts', "import {erase} from './absent.js'; import {rmSync} from 'fs'; rmSync(path); erase(path)")]
        with self.assertRaisesRegex(scanner.ScanError, 'partial'):
            scanner.build_report('inert', files, [], [], [], dependency_mode='off', ast_mode='required')
        report = scanner.build_report('inert', files, [], [], [], dependency_mode='off', ast_mode='auto')
        self.assertFalse(report['ast']['complete'])
        self.assertTrue(any(f['rule'] == 'FS_DELETE' for f in report['findings']))

    def test_off_does_not_construct_module_graph_and_ingestion_budget_is_unchanged(self):
        with patch('js_modules.Project', side_effect=AssertionError('AST disabled')):
            scanner.build_report('inert', [('a.ts', 'x')], [], [], [], dependency_mode='off', ast_mode='off')
        with self.assertRaisesRegex(scanner.ScanError, 'budget'):
            scanner.build_report('inert', [('a.ts', 'x'), ('b.ts', 'y')], [], [], [], dependency_mode='off', max_files=1)


if __name__ == '__main__':
    unittest.main()
