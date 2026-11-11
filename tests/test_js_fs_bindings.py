"""Node filesystem imports and lexical identities; fixtures are never executed."""
import unittest
from unittest.mock import patch

import js_bindings
import protestware_check as scanner
from report_formats import sarif


class JavaScriptLiteralTests(unittest.TestCase):
    def test_literal_module_names_are_decoded_as_data(self):
        for value in ("'node:fs/promises'", '"node:fs/promises"', r"'node:\x66s/\u0070romises'", r"'node:\u{66}s/promises'"):
            self.assertEqual(js_bindings.string(value), 'node:fs/promises')
        self.assertIsNone(js_bindings.string('`node:${module}`'))
        self.assertIsNone(js_bindings.string('process.env.MODULE'))


class NodeFilesystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tree_sitter_language_pack  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('JS/TS grammar required for filesystem binding tests')

    def scan(self, source, suffix='ts'):
        return scanner.scan_text('fixture.' + suffix, source, [], [], ast_mode='required')

    def deletions(self, source, suffix='ts'):
        return [f for f in self.scan(source, suffix) if f['rule'] == 'FS_DELETE']

    def test_commonjs_default_and_promise_modules(self):
        for module, call in (('fs', 'fs.promises.rm(path)'), ('node:fs', 'fs.promises.unlink(path)'),
                             ('fs/promises', 'fs.rm(path)'), ('node:fs/promises', 'fs.rmdir(path)')):
            with self.subTest(module=module):
                found = self.deletions(f"const fs = require('{module}'); {call}")
                self.assertEqual(len(found), 1)
                self.assertTrue(found[0]['resolved_symbol'].startswith('node:fs/promises.'))

    def test_esm_default_namespace_and_named_imports(self):
        for source in ("import * as fs from 'fs'; fs.promises.rm(path);",
                       "import fs from 'node:fs'; fs.promises.rm(path);",
                       "import fsp from 'node:fs/promises'; await fsp.unlink(path);",
                       "import { rm as erase } from 'node:fs/promises'; erase(path);",
                       "import { promises as fsp } from 'fs'; fsp.rm(path);",
                       "import { unlink as erase } from 'fs'; erase(path, callback);"):
            with self.subTest(source=source):
                self.assertEqual(len(self.deletions(source)), 1)

    def test_destructuring_and_straight_line_aliases(self):
        for source in ("const { rm: erase } = require('fs/promises'); erase(path);",
                       "const { promises: { unlink: erase } } = require('node:fs'); erase(path);",
                       "const fs = require('fs'); const { rm } = fs.promises; const erase = rm; erase(path);",
                       "const fsp = require('node:fs').promises; fsp.rm(path);"):
            with self.subTest(source=source):
                self.assertEqual(len(self.deletions(source)), 1)

    def test_static_subscripts_optional_calls_and_type_wrappers(self):
        for source in ("import fs from 'fs'; fs['promises']['rm'](path);",
                       "import fs from 'fs'; fs.promises?.rm?.(path);",
                       "import fs from 'fs'; (fs.promises.rm)(path);",
                       "import fs from 'fs'; (fs as any).promises.rm(path);",
                       r"const fs = require('node:\x66s'); fs.promises.rm(path);"):
            with self.subTest(source=source):
                self.assertEqual(len(self.deletions(source)), 1)

    def test_supported_javascript_extensions(self):
        for suffix in ('js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx'):
            self.assertEqual(len(self.deletions("const fs = require('node:fs'); fs.promises.rm(path)", suffix)), 1)

    def test_parameters_and_destructuring_shadow_imports(self):
        for parameters in ('fs', '{ fs }', '...fs', 'fs = fake'):
            source = "import fs from 'fs'; function run(" + parameters + "){ fs.promises.rm(path) }"
            with self.subTest(parameters=parameters):
                self.assertFalse(self.deletions(source))

    def test_local_objects_and_unrelated_imports_are_not_native_api(self):
        for source in ("const fs = {promises: {rm(){}}}; fs.promises.rm(path);",
                       "import fs from './fs'; fs.promises.rm(path);",
                       "import { rm } from 'custom'; rm(path);", "object.unlink(path);",
                       "const fs = fake; fs.rm(path);", "declare const fs: any; fs.promises.rm(path);",
                       "import type fs from 'fs'; fs.promises.rm(path);",
                       "import { type rm } from 'fs/promises'; rm(path);"):
            with self.subTest(source=source):
                self.assertFalse(self.deletions(source))

    def test_block_shadow_and_tdz(self):
        source = "import fs from 'fs'; { const fs = fake; fs.promises.rm(path); } fs.promises.rm(path);"
        self.assertEqual(len(self.deletions(source)), 1)
        self.assertFalse(self.deletions("import fs from 'fs'; { fs.promises.rm(path); let fs = fake; }"))

    def test_var_hoisting_and_function_shadow(self):
        for body in ("fs.promises.rm(path); if(flag){ var fs = fake; }", "fs.promises.rm(path); function fs(){}",
                     "fs.promises.rm(path); for(var fs of values){}"):
            self.assertFalse(self.deletions("const fs = require('fs'); function run(){" + body + '}'))

    def test_catch_and_loop_bindings(self):
        for source in ("try {} catch(fs){ fs.promises.rm(path) }",
                       "for (const fs of values){ fs.promises.rm(path) }",
                       "for (let fs=fake; flag; next()){ fs.promises.rm(path) }"):
            self.assertFalse(self.deletions("import fs from 'fs'; " + source))

    def test_reassigned_namespace_and_function_alias(self):
        for source in ("let fs = require('fs'); fs = fake; fs.promises.rm(path);",
                       "const {rm} = require('fs/promises'); let erase = rm; erase = fake; erase(path);",
                       "const fs = require('fs'); fs.promises.rm = safe; fs.promises.rm(path);",
                       "const fs = require('fs'); delete fs.promises.rm; fs.promises.rm(path);",
                       "let {rm} = require('fs/promises'); rm++; rm(path);"):
            with self.subTest(source=source):
                self.assertFalse(self.deletions(source))

    def test_reassignment_does_not_remove_earlier_observation(self):
        found = self.deletions("let fs = require('fs'); fs.promises.rm(path); fs = fake; fs.promises.rm(path);")
        self.assertEqual(len(found), 1)

    def test_computed_native_property_write_is_explicitly_partial(self):
        with self.assertRaisesRegex(scanner.ScanError, 'computed property write'):
            self.scan("const fs = require('fs'); fs.promises[key] = safe; fs.promises.rm(path)")

    def test_branch_merging_preserves_possible_native_identity(self):
        source = "let fs = require('fs'); if(flag){ fs = fake; } fs.promises.rm(path);"
        found = self.deletions(source)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['binding_certainty'], 'possible')
        source = "let fs = require('fs'); if(flag){ fs = fake; } else { fs = other; } fs.promises.rm(path);"
        self.assertFalse(self.deletions(source))

    def test_loop_merge_does_not_assume_an_iteration(self):
        source = "let fs = fake; while(flag){ fs = require('fs'); } fs.promises.rm(path);"
        found = self.deletions(source)
        self.assertEqual(found[0]['binding_certainty'], 'possible')

    def test_shadowed_require_and_dynamic_module_do_not_prove_identity(self):
        for source in ("function run(require){ const fs=require('fs'); fs.promises.rm(path); }",
                       "const fs = require(moduleName); fs.promises.rm(path);",
                       "const fs=require('fs'); function require(x){return fake} fs.promises.rm(path);"):
            self.assertFalse(self.deletions(source))

    def test_strings_and_comments_are_not_operations(self):
        source = "import fs from 'fs'; const text='fs.promises.rm(path)'; // fs.rmSync(path)\n/* fs.unlink(path) */"
        self.assertFalse(self.deletions(source))

    def test_geographic_correlation_uses_import_identity(self):
        source = "import {rm} from 'node:fs/promises'; if(country === 'RU'){ await rm(path) }"
        self.assertIn('AST_GEO_ACTION', {f['rule'] for f in self.scan(source)})
        source = "import fs from 'fs'; function run(fs){ if(country === 'RU'){ fs.promises.rm(path) } }"
        self.assertNotIn('AST_GEO_ACTION', {f['rule'] for f in self.scan(source)})

    def test_sync_and_callback_api_are_preserved(self):
        for call in ('rmSync(path)', 'unlinkSync(path)', 'rmdirSync(path)', 'rm(path, callback)', 'unlink(path, callback)'):
            self.assertEqual(len(self.deletions("const fs=require('fs'); fs." + call)), 1)

    def test_sarif_preserves_identity_and_no_execution(self):
        with patch('subprocess.run', side_effect=AssertionError('No target execution')):
            findings = self.scan("import fs from 'fs'; fs.promises.rm(path)")
        report = {'tool':'protestware-check','version':scanner.VERSION,'source':'inert','findings':findings}
        result = next(r for r in sarif(report)['runs'][0]['results'] if r['ruleId']=='FS_DELETE')
        self.assertEqual(result['properties']['resolved_symbol'], 'node:fs/promises.rm')
        self.assertEqual(result['properties']['binding_certainty'], 'resolved')


if __name__ == '__main__':
    unittest.main()
