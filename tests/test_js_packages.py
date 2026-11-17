"""Selected package source linking, exact adapter hashes and negative identity cases."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import js_package_models
from js_modules import Project
import protestware_check as scanner
from report_formats import sarif

ROOT=Path(__file__).resolve().parents[1]


class PackageModelSourceTests(unittest.TestCase):
    def test_fs_extra_context_bytes_have_pinned_git_hashes(self):
        data=json.loads((ROOT/'tests/corpus/js-package-models/fs-extra-context.json').read_text())
        for item in data['sources'].values():
            raw=item['text'].encode();self.assertEqual(sha256(raw).hexdigest(),item['sha256'])
            self.assertEqual(sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),item['git_blob_sha'])
    def test_package_lookup_budget_is_explicit(self):
        from js_packages import Packages
        packages=Packages({}, {}, max_lookups=0)
        self.assertIn('lookup budget',packages.resolve('main.js','disk')[1])

    def test_truncated_trace_preserves_model_basis_and_terminal_sink(self):
        from js_modules import bounded_trace
        hops=[('main.js',i+1,'call','wrapper') for i in range(30)]
        model=('node_modules/disk/index.js',1,'package-model','exact model')
        end=('main.js',40,'sink','node:fs.rmSync')
        result=bounded_trace([*hops,model,end])
        self.assertEqual(len(result),24);self.assertIn(model,result);self.assertEqual(result[-1],end)

    def test_all_model_bytes_have_pinned_git_hashes_and_isc_license(self):
        data=json.loads((ROOT/'tests/corpus/js-package-models/graceful-fs-4.2.11.json').read_text())
        model=js_package_models.MODELS['graceful-fs']
        self.assertEqual(model['revision'],data['revision'])
        for path,item in data['sources'].items():
            raw=item['text'].encode()
            self.assertEqual(sha256(raw).hexdigest(),item['sha256'])
            self.assertEqual(sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),item['git_blob_sha'])
            if path!='LICENSE':self.assertEqual(model['files'][path],item['sha256'])
        self.assertEqual((ROOT/'tests/corpus/licenses/isaacs-node-graceful-fs.txt').read_text(),data['sources']['LICENSE']['text'])


class JavaScriptPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa:F401
        except ImportError:raise unittest.SkipTest('JS/TS grammar required')

    def package(self,name='disk',root='node_modules/disk',entry='index.js',code="exports.erase=require('fs').rmSync",**metadata):
        return [(root+'/package.json',json.dumps({'name':name,'version':'1.0.0','main':entry,**metadata})),(root+'/'+entry,code)]

    def adapter(self,root='node_modules/graceful-fs'):
        data=json.loads((ROOT/'tests/corpus/js-package-models/graceful-fs-4.2.11.json').read_text())
        return [(root+'/'+p,v['text']) for p,v in data['sources'].items() if p!='LICENSE']

    def calls(self,files,path='main.js',code="require('disk').erase(path)"):
        p=Project([(path,code),*files]);return p,p.calls(path)[0]

    def test_bare_commonjs_and_esm_use_selected_package_entry_sources(self):
        for code in ("require('disk').erase(path)","import {erase} from 'disk'; erase(path)"):
            p,calls=self.calls(self.package(),code=code)
            self.assertTrue(calls);self.assertFalse(p.diagnostics('main.js'))

    def test_noop_same_named_method_is_not_native(self):
        p,calls=self.calls(self.package(code='exports.erase=()=>{}'))
        self.assertFalse(calls)

    def test_nearest_package_shadowing_does_not_fall_back_to_ancestor(self):
        files=[*self.package(),*self.package(root='app/node_modules/disk',code='exports.erase=()=>{}')]
        self.assertFalse(self.calls(files,path='app/main.js')[1])
        files=[*self.package(),('app/node_modules/disk/package.json','{broken')]
        p,calls=self.calls(files,path='app/main.js');self.assertFalse(calls);self.assertTrue(p.diagnostics('app/main.js'))

    def test_core_modules_cannot_be_shadowed_by_selected_packages(self):
        p,calls=self.calls(self.package(name='path',root='node_modules/path'),code="require('path').erase(path)")
        self.assertFalse(calls);self.assertFalse(p.packages.used)

    def test_scoped_packages_subpaths_and_default_index(self):
        files=self.package(name='@scope/disk',root='node_modules/@scope/disk')
        self.assertTrue(self.calls(files,code="require('@scope/disk').erase(path)")[1])
        self.assertTrue(self.calls([('node_modules/disk/lib/remove.js',"exports.erase=require('fs').rmSync")],code="require('disk/lib/remove').erase(path)")[1])
        p,calls=self.calls([('node_modules/disk/index.js',"exports.erase=require('fs').rmSync")]);self.assertTrue(calls)
        self.assertTrue(all(h['file']!='node_modules/disk/package.json' for x in calls.values() for h in x[2]))

    def test_simple_exports_and_module_format_boundaries(self):
        self.assertTrue(self.calls(self.package(exports='./index.js'))[1])
        p,calls=self.calls(self.package(type='module'));self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))
        self.assertTrue(self.calls(self.package(entry='index.cjs',type='module'))[1])
        files=self.package(code="export {rmSync as erase} from 'fs'",type='module')
        self.assertTrue(self.calls(files,code="import {erase} from 'disk'; erase(path)")[1])
        files=[('package.json','{"type":"module"}'),('node_modules/disk/index.js',"exports.erase=require('fs').rmSync")]
        self.assertTrue(self.calls(files)[1])
        p,calls=self.calls(self.package(code="export {rmSync as erase} from 'fs'",type='commonjs'),code="import {erase} from 'disk';erase(path)")
        self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))

    def test_unsafe_entries_and_unsupported_exports_fail_explicitly(self):
        for main in ('../outside.js','/outside.js','https://host/x.js','x%2f.js','x.js?y'):
            files=[('node_modules/disk/package.json',json.dumps({'name':'disk','main':main})),('node_modules/disk/index.js',"exports.erase=require('fs').rmSync")]
            p,calls=self.calls(files);self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))
        for exports in ({'require':'./index.js'},None,'index.js'):
            p,calls=self.calls(self.package(exports=exports));self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))

    def test_name_mismatch_duplicate_json_and_ambiguous_entry_are_not_guessed(self):
        for manifest in ('{"name":"other","main":"index.js"}','{"name":"disk","name":"other","main":"index.js"}'):
            p,calls=self.calls([('node_modules/disk/package.json',manifest),('node_modules/disk/index.js',"exports.erase=require('fs').rmSync")]);self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))
        files=self.package(entry='lib/index.js');files[0]=(files[0][0],'{"name":"disk","main":"lib"}')
        files.append(('node_modules/disk/lib.js',"exports.erase=require('fs').rmSync"))
        p,calls=self.calls(files);self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))

    def test_absent_package_source_does_not_gain_identity_from_its_name(self):
        for name in ('disk','graceful-fs','fs-extra'):
            p,calls=self.calls([],code="require('"+name+"').rmSync(path)");self.assertFalse(calls);self.assertFalse(p.packages.matched)

    def test_exact_graceful_sources_model_only_deletion_exports(self):
        p,calls=self.calls(self.adapter(),code="const fs=require('graceful-fs');fs.rmSync(path);fs.readFile(path);fs.erase(path)")
        self.assertEqual(len(calls),1);self.assertEqual(len(p.packages.matched),1)
        self.assertIn('package-model',{h['kind'] for x in calls.values() for h in x[2]})
        self.assertTrue(any(u.diagnostics for u in p.units.values())) # internal limitations remain visible
        self.assertTrue(self.calls(self.adapter(),code="import fs from 'graceful-fs';fs.rmSync(path)")[1])
        self.assertFalse(self.calls(self.adapter(),code="require('graceful-fs').default.rmSync(path)")[1])
        p,calls=self.calls(self.adapter(),code="import {rmSync} from 'graceful-fs';rmSync(path)")
        self.assertFalse(calls);self.assertTrue(p.diagnostics('main.js'))

    def test_pinned_fs_extra_remove_and_move_sync_link_through_selected_dependency(self):
        data=json.loads((ROOT/'tests/corpus/js-package-models/fs-extra-context.json').read_text())
        p=Project([*((path,item['text']) for path,item in data['sources'].items()),*self.adapter()])
        for path in ('lib/remove/index.js','lib/move/move-sync.js'):
            calls=p.calls(path)[0];self.assertTrue(calls,path)
            self.assertTrue(any(symbol=='node:fs.rmSync' for node,symbol,route in calls.values()))
            self.assertTrue(any(h['kind']=='package-model' for node,symbol,route in calls.values() for h in route))

    def test_each_adapter_file_must_be_present_and_byte_identical(self):
        files=self.adapter()
        for index in range(len(files)):
            for altered in (files[:index]+files[index+1:], [*files[:index],(files[index][0],files[index][1]+'\n'),*files[index+1:]]):
                p,calls=self.calls(altered,code="require('graceful-fs').rmSync(path)");self.assertFalse(calls);self.assertFalse(p.packages.matched);self.assertTrue(p.diagnostics('main.js'))

    def test_duplicate_critical_inputs_cannot_activate_model(self):
        files=self.adapter();p,calls=self.calls([*files,files[0]],code="require('graceful-fs').rmSync(path)")
        self.assertFalse(calls);self.assertFalse(p.packages.matched)

    def test_wrong_version_and_safe_lookalike_never_activate_model(self):
        files=self.adapter()
        for version in ('4.2.10','9.0.0'):
            changed=[(p,s.replace('4.2.11',version)) if p.endswith('/package.json') else(p,s) for p,s in files]
            p,calls=self.calls(changed,code="require('graceful-fs').rmSync(path)");self.assertFalse(calls);self.assertFalse(p.packages.matched)
        p,calls=self.calls(self.package(name='graceful-fs',root='node_modules/graceful-fs',code='exports.rmSync=()=>{}'),code="require('graceful-fs').rmSync(path)")
        self.assertFalse(calls);self.assertFalse(p.packages.matched)

    def test_observed_require_cache_override_prevents_later_package_linking(self):
        for prefix in ("require.cache['graceful-fs']={exports:{rmSync(){}}};", "const cache=require.cache;cache['graceful-fs']={exports:{}};"):
            p,calls=self.calls(self.adapter(),code=prefix+"require('graceful-fs').rmSync(path)")
            self.assertFalse(calls);self.assertFalse(p.packages.matched);self.assertTrue(p.diagnostics('main.js'))

    def test_overwrite_of_modelled_method_removes_subsequent_native_identity(self):
        p,calls=self.calls(self.adapter(),code="const fs=require('graceful-fs');fs.rmSync(path);fs.rmSync=()=>{};fs.rmSync(path)")
        self.assertEqual(len(calls),1);self.assertTrue(p.diagnostics('main.js'))
        files=[('bridge.js',"module.exports=require('graceful-fs')"),*self.adapter()]
        p,calls=self.calls(files,code="const fs=require('./bridge.js');fs.rmSync(path);fs.rmSync=()=>{};fs.rmSync(path)")
        self.assertEqual(len(calls),1)

    def test_artifact_profile_selects_dependencies_source_profile_excludes_them(self):
        self.assertFalse(scanner.is_scannable('node_modules/graceful-fs/graceful-fs.js',[],profile='source'))
        self.assertTrue(scanner.is_scannable('node_modules/graceful-fs/graceful-fs.js',[],profile='artifact'))

    def test_no_target_reads_or_execution_during_package_resolution(self):
        files=self.adapter()
        with patch('builtins.open',side_effect=AssertionError('No target reads')),patch('subprocess.run',side_effect=AssertionError('No execution')):
            p,calls=self.calls(files,code="require('graceful-fs').rmSync(path)")
        self.assertTrue(calls)

    def test_sarif_keeps_cross_package_model_evidence(self):
        report=scanner.build_report('inert',[('main.js',"require('graceful-fs').rmSync(path)"),*self.adapter()],[],[],[],dependency_mode='off',ast_mode='auto')
        finding=next(f for f in report['findings'] if f['file']=='main.js' and f['rule']=='FS_DELETE')
        self.assertIn('package-model',{h['kind'] for h in finding['dataflow']})
        result=next(r for r in sarif(report)['runs'][0]['results'] if r['ruleId']=='FS_DELETE' and r['locations'][0]['physicalLocation']['artifactLocation']['uri']=='main.js')
        self.assertTrue(result['codeFlows'])
        self.assertEqual(result['properties']['binding_basis'],'source-hash-model')
        self.assertTrue(sarif(report)['runs'][0]['invocations'][0]['properties']['jsPackageModels'])


if __name__=='__main__':unittest.main()
