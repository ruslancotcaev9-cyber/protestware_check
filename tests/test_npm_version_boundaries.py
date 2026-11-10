"""Version/coverage regressions using inert manifests and simulated API responses."""
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
from package_identity import public_origin


class NpmVersionBoundaryTests(unittest.TestCase):
    def test_partial_versions_are_ranges(self):
        for version in ('0', '1', '0.0', '1.2', 'v1', 'v1.2'):
            with self.subTest(version=version):
                self.assertFalse(dep.is_exact_version('npm', version))

    def test_full_versions_including_prerelease_and_build_are_eligible(self):
        versions = ('0.0.0', '1.2.3', 'v1.2.3', '1.2.3-rc.1',
                    '1.2.3-0', '1.2.3-01alpha', '1.2.3+build.001',
                    '1.2.3-beta.2+build.007')
        packages = [{'ecosystem': 'npm', 'name': 'example', 'version': v, 'origin': public_origin('npm')}
                    for v in versions]
        with patch.object(mi, 'fetch_json', return_value={
                'results': [{} for _ in versions]}) as fetch:
            result = mi.check_packages(packages, mode='osv')
        self.assertEqual([q['version'] for q in fetch.call_args.args[1]['queries']],
                         list(versions))
        self.assertTrue(result['metadata']['complete'])
        self.assertEqual(result['metadata']['checked_packages'], len(versions))

    def test_constraints_and_malformed_versions_are_not_exact(self):
        for version in ('', '^1.2.3', '~1.2.3', '1.*', '1.2.x', '>=1.2.3',
                        '1.2.3 || 2.0.0', 'latest', '01.2.3', '1.02.3',
                        '1.2.03', '1.2.3-01', '1.2.3-rc.01', '1.2.3-rc..1',
                        '1.2.3-', '1.2.3+', '1.2.3+build..1', '1.2.3.4'):
            with self.subTest(version=version):
                self.assertFalse(dep.is_exact_version('npm', version))

    def test_pypi_and_nuget_short_versions_remain_exact(self):
        for ecosystem in ('pypi', 'nuget'):
            with self.subTest(ecosystem=ecosystem):
                self.assertTrue(dep.is_exact_version(ecosystem, '1.2'))

    def test_advisory_guard_rejects_partial_versions_for_every_source(self):
        for mode in ('osv', 'github', 'both'):
            with self.subTest(mode=mode), patch.object(mi, 'fetch_json') as fetch:
                result = mi.check_packages([
                    {'ecosystem': 'npm', 'name': 'example', 'version': version}
                    for version in ('1', '1.2')], mode=mode)
            fetch.assert_not_called()
            self.assertFalse(result['metadata']['complete'])
            self.assertEqual(result['metadata']['skipped_unknown_version'], 2)
            self.assertEqual(result['metadata']['network_requests'], 0)

    def test_lockfiles_with_partial_versions_are_incomplete(self):
        for lock_version in (1, 2, 3):
            for version in ('1', '1.2'):
                with self.subTest(lock_version=lock_version, version=version):
                    doc = {'lockfileVersion': lock_version}
                    if lock_version == 1:
                        doc['dependencies'] = {'example': {'version': version}}
                    else:
                        doc['packages'] = {'': {'dependencies': {'example': version}},
                                           'node_modules/example': {'version': version}}
                    inventory = dep.analyze_dependencies({
                        'package.json': json.dumps({'dependencies': {'example': version}}),
                        'package-lock.json': json.dumps(doc)})
                    self.assertFalse(inventory['summary']['complete'])
                    self.assertEqual(inventory['packages'][0]['version'], '')
                    self.assertEqual(inventory['packages'][0]['requested'], version)

    def test_cli_partial_versions_fail_strict_gates_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            # A valid empty lock prevents unrelated missing-manifest errors from
            # making a broken strict-version check appear successful.
            Path(folder, 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3, 'packages': {'': {}}}), encoding='utf-8')
            for version in ('1', '1.2'):
                for flags, expected in (([], 0), (['--dependency-strict'], 2),
                                        (['--malware-strict'], 2),
                                        (['--dependency-strict', '--malware-strict'], 2)):
                    with self.subTest(version=version, flags=flags):
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out), patch.object(mi, 'fetch_json') as fetch:
                            status = scanner.main([
                                '--path', folder, '--ast-mode', 'off',
                                '--package', f'npm:@scope/example@{version}',
                                '--malware-intel', 'both', '--format', 'json', *flags])
                        self.assertEqual(status, expected)
                        fetch.assert_not_called()
                        report = json.loads(out.getvalue())
                        self.assertFalse(report['dependencies']['summary']['complete'])
                        self.assertFalse(report['malware_intel']['complete'])
                        self.assertFalse(report['malware_intel']['inventory_complete'])
                        package = report['dependencies']['packages'][0]
                        self.assertEqual(package['version'], '')
                        self.assertEqual(package['requested'], version)

    def test_registry_resolves_partial_versions_before_advisories(self):
        def registry(url):
            if url == 'https://registry.npmjs.org/example':
                return {'versions': {'1.2.3': {}, '1.2.9': {}, '1.9.0': {}, '2.0.0': {}}}
            if url in ('https://registry.npmjs.org/example/1.2.9',
                       'https://registry.npmjs.org/example/1.9.0'):
                return {'dependencies': {}}
            raise AssertionError(f'Unexpected registry request: {url}')

        for spec, expected in (('1', '1.9.0'), ('1.2', '1.2.9')):
            with self.subTest(spec=spec), patch.object(dep, 'official_json', side_effect=registry):
                inventory = dep.analyze_dependencies({
                    'package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {'': {}}})},
                    mode='registry', explicit_packages=[f'npm:example@{spec}'])
                package = inventory['packages'][0]
                self.assertEqual(package['version'], expected)
                self.assertEqual(package['source'], 'registry-selected')
                self.assertEqual(package['requested'], spec)
                self.assertFalse(inventory['summary']['complete'])
                with patch.object(mi, 'fetch_json', return_value={'results': [{}]}) as fetch:
                    result = mi.check_packages(inventory['packages'], mode='osv',
                                               inventory_complete=inventory['summary']['complete'])
                self.assertEqual(fetch.call_args.args[1]['queries'][0]['version'], expected)
                self.assertTrue(result['metadata']['complete'])
                self.assertFalse(result['metadata']['inventory_complete'])


if __name__ == '__main__':
    unittest.main()
