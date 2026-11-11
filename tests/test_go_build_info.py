"""Trusted Go listing imports are data, bounded and tied to current source."""
import contextlib
import copy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_analysis
import go_build_info as go
import malware_intel
import protestware_check as scanner
from report_formats import cyclonedx
from scripts.prepare_go_build_info import main as prepare

REVISION = 'a' * 40


class GoBuildInfoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'go.mod').write_text('module example.test/app\ngo 1.22\nrequire example.test/lib v1.0.0\n')
        (self.root / 'main.go').write_text('package app\nimport "example.test/lib"\nfunc Work() { lib.Work() }\n')
        self.modules = [{'Path': 'example.test/app', 'Main': True, 'GoMod': str(self.root / 'go.mod')},
                        {'Path': 'example.test/lib', 'Version': 'v1.2.0'},
                        {'Path': 'example.test/unused', 'Version': 'v4.0.0'}]
        self.packages = [{'ImportPath': 'example.test/app', 'Dir': str(self.root), 'GoFiles': ['main.go'],
                          'Module': self.modules[0], 'Imports': ['example.test/lib']},
                         {'ImportPath': 'example.test/lib', 'DepOnly': True, 'Module': self.modules[1], 'Imports': ['fmt']},
                         {'ImportPath': 'fmt', 'Standard': True, 'DepOnly': True}]
        self.env = {'GOOS': 'linux', 'GOARCH': 'amd64', 'GOVERSION': 'go1.22.0', 'CGO_ENABLED': '0', 'GOFLAGS': '', 'GOWORK': 'off'}
        self.raw = [self.base / name for name in ('modules.json', 'packages.json', 'env.json')]
        self.snapshot = self.base / 'build-info.json'

    def export(self, **kwargs):
        for path, values in zip(self.raw, (self.modules, self.packages, self.env)):
            path.write_text(('\n'.join(json.dumps(value) for value in values) if isinstance(values, list) else json.dumps(values)))
        return go.export(self.root, REVISION, *self.raw, **kwargs)

    def loaded(self, data=None):
        self.snapshot.write_text(json.dumps(data or self.export()))
        return go.load(self.snapshot, self.root, REVISION)

    def inventory(self, data=None):
        manifests = {p.relative_to(self.root).as_posix(): p.read_text() for p in self.root.rglob('*') if p.is_file() and p.name in go.METADATA}
        return dependency_analysis.analyze_dependencies(manifests, go_builds=[self.loaded(data)])

    def test_selected_used_versions_replace_declared_or_historical_versions(self):
        (self.root / 'go.sum').write_text('example.test/lib v0.9.0 h1:' + 'A' * 43 + '=\n')
        result = self.inventory()
        self.assertTrue(result['summary']['complete'], result['summary']['warnings'])
        self.assertEqual([(p['name'], p['version'], p['direct'], p['depth']) for p in result['packages']], [('example.test/lib', 'v1.2.0', True, 1)])
        self.assertEqual(result['go_builds'][0]['unused_selected_modules'], ['example.test/unused'])
        self.assertEqual(result['packages'][0]['build_context']['source_revision'], REVISION)

    def test_remote_replacement_uses_actual_identity_and_transitive_edges(self):
        self.modules[1]['Replace'] = {'Path': 'example.test/fork', 'Version': 'v1.3.0'}
        self.modules.append({'Path': 'example.test/leaf', 'Version': 'v0.4.0'})
        self.packages[1]['Imports'].append('example.test/leaf')
        self.packages.append({'ImportPath': 'example.test/leaf', 'DepOnly': True, 'Module': self.modules[-1]})
        packages = {p['name']: p for p in self.inventory()['packages']}
        self.assertEqual(packages['example.test/fork']['version'], 'v1.3.0')
        self.assertEqual(packages['example.test/leaf']['via'], ['example.test/fork@v1.3.0'])
        self.assertEqual(packages['example.test/leaf']['depth'], 2)

    def test_local_replacement_is_bound_and_not_sent_to_public_advisory_api(self):
        lib = self.root / 'lib'
        lib.mkdir()
        (lib / 'go.mod').write_text('module example.test/lib\ngo 1.22\n')
        (lib / 'lib.go').write_text('package lib\nfunc Work() {}\n')
        self.modules[1]['Replace'] = {'Path': './lib', 'Dir': str(lib), 'GoMod': str(lib / 'go.mod')}
        self.packages[1].update(Dir=str(lib), GoFiles=['lib.go'])
        result = self.inventory()
        self.assertTrue(result['summary']['complete'], result['summary']['warnings'])
        package = result['packages'][0]
        self.assertEqual(package['origin']['kind'], 'local')
        self.assertEqual(package['manifest'], 'go.mod')
        with patch.object(malware_intel, 'fetch_json', side_effect=AssertionError('Network must not be used')):
            report = malware_intel.check_packages(result['packages'], mode='osv')
        self.assertEqual(report['metadata']['eligible_packages'], 0)

    def test_revision_and_changed_added_deleted_source_are_rejected(self):
        data = self.export()
        self.snapshot.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'revision'):
            go.load(self.snapshot, self.root, 'b' * 40)
        source = self.root / 'main.go'
        original = source.read_bytes()
        for change in ('edit', 'add', 'delete'):
            with self.subTest(change=change):
                if change == 'edit':
                    source.write_bytes(original + b'// change\n')
                elif change == 'add':
                    (self.root / 'new.go').write_text('package app\n')
                else:
                    source.unlink()
                with self.assertRaisesRegex(ValueError, 'stale'):
                    go.load(self.snapshot, self.root, REVISION)
                source.write_bytes(original)
                (self.root / 'new.go').unlink(missing_ok=True)

    def test_new_embed_match_is_detected(self):
        assets = self.root / 'assets'
        assets.mkdir()
        (assets / 'first.txt').write_text('one')
        self.packages[0].update(EmbedPatterns=['assets/*.txt'], EmbedFiles=['assets/first.txt'])
        self.loaded()
        (assets / 'second.txt').write_text('two')
        with self.assertRaisesRegex(ValueError, 'stale'):
            go.load(self.snapshot, self.root, REVISION)

    def test_manifest_edits_are_detected(self):
        self.loaded()
        (self.root / 'go.mod').write_text('module changed\n')
        with self.assertRaisesRegex(ValueError, 'stale'):
            go.load(self.snapshot, self.root, REVISION)

    def test_revision_only_does_not_change_logical_graph_digest(self):
        old = self.export()
        new = {**old, 'source_revision': 'b' * 40}
        self.assertEqual(go.logical_digest(old), go.logical_digest(new))

    def test_profiles_have_separate_package_identities(self):
        first = self.loaded()
        self.env['GOOS'] = 'windows'
        second = self.loaded()
        result = dependency_analysis.analyze_dependencies({'go.mod': (self.root / 'go.mod').read_text()}, go_builds=[first, second])
        self.assertTrue(result['summary']['complete'])
        self.assertEqual(len(result['packages']), 2)
        self.assertEqual(len({p['origin']['profile'] for p in result['packages']}), 2)

    def test_unverified_or_duplicate_profiles_do_not_claim_complete_inventory(self):
        data = self.export()
        for builds in ([data], [self.loaded(data)] * 2):
            result = dependency_analysis.analyze_dependencies({'go.mod': (self.root / 'go.mod').read_text()}, go_builds=builds)
            self.assertFalse(result['summary']['complete'])

    def test_missing_edges_cycles_and_unknown_modules_are_rejected(self):
        original = self.export()
        for mutation in ('missing', 'cycle', 'module', 'unreachable'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                data = copy.deepcopy(original)
                by_name = {p['path']: p for p in data['packages']}
                if mutation == 'missing':
                    by_name['example.test/app']['imports'].append('missing')
                elif mutation == 'cycle':
                    by_name['example.test/lib']['imports'].append('example.test/app')
                elif mutation == 'module':
                    by_name['example.test/app']['module'] = 'unknown'
                else:
                    data['packages'].append({'path': 'unreachable', 'module': 'example.test/lib', 'standard': False, 'dep_only': True, 'imports': []})
                go.validate(data)

    def test_bad_scopes_and_digest_shapes_are_rejected(self):
        data = self.export()
        for key, value in (('module_roots', ['..']), ('module_roots', ['.', '.']), ('inputs', {'../bad.go': 'a' * 64}), ('inputs', {'main.go': 'bad'})):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                go.validate({**data, key: value})

    def test_symlink_and_outside_local_replacement_are_rejected(self):
        (self.root / 'linked.go').symlink_to(self.root / 'main.go')
        with self.assertRaises((ValueError, OSError)):
            self.export()
        (self.root / 'linked.go').unlink()
        self.modules[1]['Replace'] = {'Path': '../outside', 'Dir': str(self.base), 'GoMod': str(self.base / 'go.mod')}
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.export()

    def test_incomplete_test_vendor_and_hidden_flag_exports_are_rejected(self):
        for key, value in (('Incomplete', True), ('ForTest', 'example.test/app'), ('Error', {'Err': 'failed'})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.packages[0][key] = value
                try:
                    self.export()
                finally:
                    self.packages[0].pop(key)
        with self.assertRaises(ValueError):
            self.export(mod_mode='vendor')
        self.env['GOFLAGS'] = '-modfile=alternate.mod'
        with self.assertRaisesRegex(ValueError, 'GOFLAGS'):
            self.export()

    def test_input_budgets_are_enforced(self):
        for limits in ({'max_files': 1}, {'max_bytes': 1}, {'max_total_bytes': 1}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.export(**limits)

    def test_export_cli_and_strict_scan_round_trip_without_process_execution(self):
        self.export()
        argv = ['--source-root', str(self.root), '--source-revision', REVISION, '--modules', str(self.raw[0]),
                '--packages', str(self.raw[1]), '--environment', str(self.raw[2]), '--output', str(self.snapshot)]
        with contextlib.redirect_stdout(io.StringIO()), patch('subprocess.run', side_effect=AssertionError('No target command')):
            self.assertEqual(prepare(argv), 0)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                status = scanner.main(['--path', str(self.root), '--go-build-info', str(self.snapshot), '--source-revision', REVISION,
                                       '--ast-mode', 'off', '--dependency-strict', '--format', 'json'])
        self.assertEqual(status, 0)
        report = json.loads(out.getvalue())
        self.assertTrue(report['dependencies']['summary']['complete'])
        component = cyclonedx(report)['components'][0]
        self.assertTrue(any(p['name'] == 'protestware-check:build-context' for p in component['properties']))

    def test_bad_snapshot_fails_before_watchlist_or_advisory_network(self):
        data = self.export()
        data['source_revision'] = 'b' * 40
        self.snapshot.write_text(json.dumps(data))
        with contextlib.redirect_stderr(io.StringIO()), patch.object(scanner.threat_intel, 'load_watchlists', side_effect=AssertionError('Must fail first')):
            status = scanner.main(['--path', str(self.root), '--go-build-info', str(self.snapshot), '--source-revision', REVISION])
        self.assertEqual(status, 2)

    def test_concurrent_read_change_is_rejected_before_advisories(self):
        build = self.loaded()
        coverage = scanner.Coverage()
        coverage.raw_hashes['main.go'] = sha256(b'changed').hexdigest()
        with self.assertRaisesRegex(scanner.ScanError, 'no longer matches'):
            scanner.build_report('test', [], [], [], [], go_builds=[build], coverage=coverage)

    def test_multi_module_workspace_is_bound(self):
        workspace = self.root / 'go.work'
        workspace.write_text('go 1.22\nuse (. ./other)\n')
        other = self.root / 'other'
        other.mkdir()
        (other / 'go.mod').write_text('module example.test/other\ngo 1.22\n')
        (other / 'other.go').write_text('package other\n')
        self.env['GOWORK'] = str(workspace)
        module = {'Path': 'example.test/other', 'Main': True, 'GoMod': str(other / 'go.mod')}
        self.modules.append(module)
        self.packages.append({'ImportPath': 'example.test/other', 'Dir': str(other), 'GoFiles': ['other.go'], 'Module': module})
        result = self.inventory()
        self.assertTrue(result['summary']['complete'], result['summary']['warnings'])
        self.assertEqual(result['packages'][0]['manifest'], 'go.work')
        workspace.write_text('go 1.22\nuse .\n')
        with self.assertRaisesRegex(ValueError, 'stale'):
            go.load(self.snapshot, self.root, REVISION)


if __name__ == '__main__':
    unittest.main()
