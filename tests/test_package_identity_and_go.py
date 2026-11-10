"""Origin and Go inventory regressions; all advisory/registry calls are mocked."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_analysis as dep
import malware_intel as mi
import protestware_check as scanner
from package_identity import advisory_origin_matches
from report_formats import cyclonedx


def npm_lock(resolved=None, version=3):
    item = {'version': '1.2.3', 'integrity': 'sha512-fixture'}
    if resolved is not None:
        item['resolved'] = resolved
    if version == 1:
        return {'lockfileVersion': 1, 'dependencies': {'demo': item}}
    return {'lockfileVersion': version, 'packages': {
        '': {'dependencies': {'demo': '1.2.3'}}, 'node_modules/demo': item}}


class PackageOriginTests(unittest.TestCase):
    def inventory(self, resolved=None, version=3):
        return dep.analyze_dependencies({'package-lock.json': json.dumps(npm_lock(resolved, version))})

    def test_private_git_local_unknown_origins_never_reach_advisory_apis(self):
        for resolved in (None, 'git+https://github.com/example/fork.git#' + 'a' * 40,
                         'https://private.example/demo.tgz', 'file:../demo',
                         'https://registry.npmjs.org.evil.example/demo.tgz'):
            for version in (1, 2, 3):
                with self.subTest(resolved=resolved, lock_version=version):
                    inventory = self.inventory(resolved, version)
                    with patch.object(mi, 'fetch_json') as fetch:
                        result = mi.check_packages(inventory['packages'], mode='both')
                    fetch.assert_not_called()
                    self.assertFalse(result['metadata']['complete'])
                    self.assertEqual(result['metadata']['skipped_unverified_origin'], 1)

    def test_public_origin_is_queried_with_exact_version(self):
        inventory = self.inventory('https://registry.npmjs.org/demo/-/demo-1.2.3.tgz')
        with patch.object(mi, 'fetch_json', return_value={'results': [{}]}) as fetch:
            result = mi.check_packages(inventory['packages'], mode='osv')
        self.assertEqual(fetch.call_args.args[1]['queries'], [{'version': '1.2.3', 'package': {'name': 'demo', 'ecosystem': 'npm'}}])
        self.assertTrue(result['metadata']['complete'])
        self.assertEqual(inventory['packages'][0]['origin']['integrity'], 'sha512-fixture')

    def test_git_commit_and_origin_are_preserved(self):
        package = self.inventory('git+https://github.com/example/fork.git#' + 'a' * 40)['packages'][0]
        self.assertEqual(package['origin']['kind'], 'git')
        self.assertEqual(package['origin']['revision'], 'a' * 40)
        self.assertEqual(package['origin']['url'], 'https://github.com/example/fork.git')

    def test_credentialed_and_signed_urls_are_redacted_and_not_trusted(self):
        for raw in ('https://user:secret@registry.npmjs.org/demo.tgz',
                    'https://registry.npmjs.org/demo.tgz?token=secret',
                    'https://registry.npmjs.org:8443/demo.tgz'):
            with self.subTest(raw=raw):
                package = self.inventory(raw)['packages'][0]
                self.assertNotIn('secret', json.dumps(package['origin']))
                self.assertFalse(advisory_origin_matches(package))

    def test_equal_coordinates_with_different_origins_do_not_merge(self):
        lock = npm_lock('https://registry.npmjs.org/demo/-/demo-1.2.3.tgz')
        lock['packages']['']['dependencies']['parent'] = '2.0.0'
        lock['packages']['node_modules/parent'] = {
            'version': '2.0.0', 'dependencies': {'demo': '1.2.3'},
            'resolved': 'https://registry.npmjs.org/parent/-/parent-2.0.0.tgz'}
        lock['packages']['node_modules/parent/node_modules/demo'] = {
            'version': '1.2.3', 'resolved': 'https://private.example/demo.tgz'}
        def fake(url, payload=None):
            if url == mi.OSV_BATCH_URL:
                return {'results': [{'vulns': [{'id': 'MAL-2026-123'}]} if q['package']['name'] == 'demo' else {}
                                    for q in payload['queries']]}
            return {'id': 'MAL-2026-123'}
        with patch.object(mi, 'fetch_json', side_effect=fake):
            report = scanner.build_report('test', [('package-lock.json', json.dumps(lock))], [], [], [], malware_mode='osv')
        packages = report['dependencies']['packages']
        self.assertEqual(len(packages), 3)
        demos = [p for p in packages if p['name'] == 'demo']
        self.assertEqual({p['depth'] for p in demos}, {1, 2})
        self.assertEqual(len(report['findings']), 1)
        self.assertTrue(report['findings'][0]['package']['origin']['url'].startswith('https://registry.npmjs.org/'))
        self.assertFalse(report['malware_intel']['complete'])
        bom = cyclonedx(report)
        self.assertEqual(len({p['bom-ref'] for p in bom['components']}), 3)

    def test_registry_enrichment_does_not_relabel_forks_or_unknown_origins(self):
        for resolved in (None, 'git+https://github.com/example/fork.git#' + 'b' * 40, 'https://private.example/demo.tgz'):
            with self.subTest(resolved=resolved), patch.object(dep, 'official_json') as fetch:
                result = dep.analyze_dependencies({'package-lock.json': json.dumps(npm_lock(resolved))}, mode='registry')
            fetch.assert_not_called()
            self.assertFalse(result['summary']['complete'])

    def test_python_and_cargo_sources_are_checked(self):
        for filename, text, expected in (
            ('uv.lock', '[[package]]\nname="demo"\nversion="1.2.3"\nsource={registry="https://pypi.org/simple"}', True),
            ('uv.lock', '[[package]]\nname="demo"\nversion="1.2.3"\nsource={git="https://github.com/example/fork"}', False),
            ('poetry.lock', '[[package]]\nname="demo"\nversion="1.2.3"\n[package.source]\ntype="legacy"\nurl="https://private.example/simple"', False),
            ('Cargo.lock', '[[package]]\nname="demo"\nversion="1.2.3"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="abc"', True),
            ('Cargo.lock', '[[package]]\nname="demo"\nversion="1.2.3"\nsource="git+https://github.com/example/fork#aaa"', False),
        ):
            with self.subTest(filename=filename, text=text):
                package = dep.analyze_dependencies({filename: text})['packages'][0]
                self.assertEqual(advisory_origin_matches(package), expected)

    def test_requirements_mixed_or_missing_indexes_are_unverified(self):
        for prefix in ('', '--extra-index-url https://pypi.org/simple\n', '--no-index\n',
                       '--index-url https://pypi.org/simple\n--extra-index-url https://private.example/simple\n'):
            package = dep.analyze_dependencies({'requirements.txt': prefix + 'demo==1.2.3'})['packages'][0]
            self.assertFalse(advisory_origin_matches(package))
        package = dep.analyze_dependencies({'requirements.txt': '--index-url https://pypi.org/simple\ndemo==1.2.3'})['packages'][0]
        self.assertTrue(advisory_origin_matches(package))

    def test_cli_strict_origin_gate_returns_two_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'package-lock.json').write_text(json.dumps(npm_lock('https://private.example/demo.tgz')))
            with patch.object(mi, 'fetch_json') as fetch, contextlib.redirect_stdout(io.StringIO()) as out:
                status = scanner.main(['--path', folder, '--malware-intel', 'both', '--malware-strict', '--format', 'json'])
            fetch.assert_not_called()
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(out.getvalue())['malware_intel']['skipped_unverified_origin'], 1)


HASH = 'h1:' + 'A' * 43 + '='


def checksum(name, version, mod_only=False):
    return f'{name} {version}{"/go.mod" if mod_only else ""} {HASH}\n'


class GoInventoryTests(unittest.TestCase):
    def test_old_versions_are_not_current_and_indirect_flag_is_preserved(self):
        manifests = {'go.mod': 'module example.org/app\ngo 1.22\nrequire (\n example.org/lib v1.2.0\n example.org/helper v0.3.0 // indirect\n)\n',
                     'go.sum': checksum('example.org/lib', 'v1.1.0') + checksum('example.org/lib', 'v1.2.0') + checksum('example.org/helper', 'v0.3.0')}
        report = dep.analyze_dependencies(manifests)
        packages = {p['name']: p for p in report['packages']}
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages['example.org/lib']['version'], 'v1.2.0')
        self.assertTrue(packages['example.org/lib']['direct'])
        self.assertFalse(packages['example.org/helper']['direct'])
        self.assertEqual(report['summary']['go_unselected_checksums'], 1)
        self.assertFalse(report['summary']['complete'])  # No selected transitive build list was supplied.

    def test_missing_version_is_retained_as_unverified_requirement(self):
        report = dep.analyze_dependencies({'go.mod': 'module example.org/app\nrequire example.org/lib v1.2.0',
                                           'go.sum': checksum('example.org/lib', 'v1.1.0')})
        self.assertEqual([p['version'] for p in report['packages']], ['v1.2.0'])
        self.assertIn('missing-module-checksum', report['packages'][0]['qualifiers'])
        self.assertFalse(report['summary']['complete'])

    def test_go_mod_checksum_is_not_archive_checksum(self):
        report = dep.analyze_dependencies({'go.mod': 'module example.org/app\nrequire example.org/lib v1.2.0',
                                           'go.sum': checksum('example.org/lib', 'v1.2.0', mod_only=True)})
        package = report['packages'][0]
        self.assertIn('missing-module-checksum', package['qualifiers'])
        self.assertEqual(package['origin']['checksums'], {'go.mod': HASH})

    def test_replacements_select_effective_identity_with_exact_precedence(self):
        mod = ('module example.org/app\nreplace example.org/lib => ../generic\n'
               'replace (\n example.org/lib v1.2.0 => example.org/fork v1.3.0\n)\n'
               'require example.org/lib v1.2.0\n')
        package = dep.analyze_dependencies({'go.mod': mod, 'go.sum': checksum('example.org/fork', 'v1.3.0')})['packages'][0]
        self.assertEqual((package['name'], package['version']), ('example.org/fork', 'v1.3.0'))
        self.assertEqual(package['origin']['replaces'], {'module': 'example.org/lib', 'version': 'v1.2.0'})
        self.assertTrue(advisory_origin_matches(package))

    def test_local_replacement_is_never_checked_as_public_module(self):
        mod = 'module example.org/app\nrequire example.org/lib v1.2.0\nreplace example.org/lib => "../local fork"'
        package = dep.analyze_dependencies({'go.mod': mod})['packages'][0]
        self.assertEqual(package['origin']['kind'], 'local')
        self.assertEqual(package['origin']['url'], '../local fork')
        self.assertEqual(package['version'], '')
        self.assertFalse(advisory_origin_matches(package))

    def test_go_sum_alone_is_not_a_build_list(self):
        report = dep.analyze_dependencies({'go.sum': checksum('example.org/lib', 'v1.2.0')})
        self.assertFalse(report['summary']['complete'])
        self.assertIn('go.sum-only', report['packages'][0]['qualifiers'])
        with patch.object(mi, 'fetch_json') as fetch:
            result = mi.check_packages(report['packages'], mode='osv')
        fetch.assert_not_called()
        self.assertFalse(result['metadata']['complete'])

    def test_empty_module_does_not_require_go_sum(self):
        report = dep.analyze_dependencies({'go.mod': 'module example.org/app\ngo 1.22\n'})
        self.assertEqual(report['packages'], [])
        self.assertTrue(report['summary']['complete'])

    def test_malformed_and_unclosed_requirements_are_incomplete(self):
        for mod in ('require example.org/lib v1', 'require (\n example.org/lib v1.2.0',
                    'replace example.org/lib => nonsense'):
            with self.subTest(mod=mod):
                report = dep.analyze_dependencies({'go.mod': 'module example.org/app\n' + mod})
                self.assertFalse(report['summary']['complete'])

    def test_invalid_checksum_cannot_confirm_module_archive(self):
        report = dep.analyze_dependencies({'go.mod': 'module example.org/app\nrequire example.org/lib v1.2.0',
                                           'go.sum': 'example.org/lib v1.2.0 h1:not-a-checksum'})
        self.assertIn('missing-module-checksum', report['packages'][0]['qualifiers'])
        self.assertTrue(any('checksum' in item for item in report['summary']['warnings']))


if __name__ == '__main__':
    unittest.main()
