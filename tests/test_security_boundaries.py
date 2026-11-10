"""Inert regression cases for source ingestion and incomplete analysis."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.request import Request

import dependency_analysis as dependencies
import malware_intel
import protestware_check as scanner
import safe_io
import report_formats
import threat_intel
import python_taint
import polyglot_ast


class SecurityBoundaries(unittest.TestCase):
    def test_redirects_are_not_followed(self):
        handler = safe_io.NoRedirects()
        self.assertIsNone(handler.redirect_request(Request('https://api.github.com/x'), None,
                                                  302, 'redirect', {}, 'https://example.org/'))

    def test_github_rejects_other_hosts_before_request(self):
        with patch.object(safe_io, 'open_https') as opened:
            with self.assertRaises(scanner.ScanError):
                scanner.api_json('https://example.org/repos/a/b', 'dummy')
            opened.assert_not_called()

    def test_github_response_is_bounded_and_object_checked(self):
        for body in (b'[]', b'x' * 16_000_001, b'[' * 2000):
            with self.subTest(size=len(body)):
                response = MagicMock()
                response.__enter__.return_value.read.return_value = body
                with patch.object(safe_io, 'open_https', return_value=response):
                    with self.assertRaises(scanner.ScanError):
                        scanner.api_json('https://api.github.com/repos/a/b', None)
                response.__enter__.return_value.read.assert_called_once_with(16_000_001)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX special files')
    def test_special_file_is_never_opened(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td, 'input.py')
            os.mkfifo(path)
            with patch.object(os, 'open') as opened:
                with self.assertRaises(OSError):
                    safe_io.read_regular(path, 10)
                opened.assert_not_called()
            warnings = []
            self.assertEqual(list(scanner.iter_local(Path(td), 10, [], warnings)), [])
            self.assertTrue(warnings)

    def test_bounded_regular_read(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td, 'file.py')
            path.write_bytes(b'123456')
            with self.assertRaises(ValueError):
                safe_io.read_regular(path, 5)
            self.assertEqual(safe_io.read_regular(path, 6), b'123456')

    def test_skipped_source_is_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, 'package.json').write_text('{"dependencies":{}}')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = scanner.main(['--path', td, '--max-bytes', '1', '--format', 'json'])
            self.assertEqual(rc, 2)
            report = json.loads(output.getvalue())
            self.assertFalse(report['scan']['complete'])
            self.assertFalse(report['dependencies']['summary']['complete'])

    def test_output_cannot_overwrite_source_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td, 'original.py')
            source.write_text('print(1)')
            link = Path(td, 'report.json')
            link.symlink_to(source)
            for destination in (source, link):
                with contextlib.redirect_stderr(io.StringIO()):
                    rc = scanner.main(['--path', td, '--output', str(destination), '--ast-mode', 'off'])
                self.assertEqual(rc, 2)
                self.assertEqual(source.read_text(), 'print(1)')

    def test_malformed_url_is_data(self):
        result = scanner.scan_text('x.py', 'requests.get("http://[invalid")', [], [])
        self.assertTrue(any(x['rule'] == 'NET_DYNAMIC' for x in result))

    def test_deep_source_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, 'deep.py').write_text('x=' + '1+' * 1500 + '1')
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(scanner.main(['--path', td]), 2)
            self.assertNotIn('Traceback', error.getvalue())

    def test_malformed_manifests_are_incomplete(self):
        cases = [
            ('package-lock.json', {'packages': {'node_modules/x': {'version': []}}}),
            ('composer.lock', {'packages': None}),
            ('packages.lock.json', {'dependencies': {'net8': {'x': {'resolved': '1', 'type': []}}}}),
            ('package.json', []),
        ]
        for path, data in cases:
            with self.subTest(path=path):
                result = dependencies.analyze_dependencies({path: json.dumps(data)})
                self.assertFalse(result['summary']['complete'])

    def test_unsupported_manifest_among_supported_is_incomplete(self):
        result = dependencies.analyze_dependencies({'requirements.txt': 'requests==2.32.3',
                                                   'deno.lock': '{}'})
        self.assertFalse(result['summary']['complete'])

    def test_explicit_range_is_not_a_pinned_version(self):
        for spec in ('npm:example@^1.0.0', 'pypi:example@1.*', 'npm:example@latest'):
            with self.subTest(spec=spec):
                result = dependencies.analyze_dependencies({}, explicit_packages=[spec])
                self.assertEqual(result['packages'][0]['version'], '')
                self.assertFalse(result['summary']['complete'])

    def test_advisory_does_not_query_ranges(self):
        with patch.object(malware_intel, 'fetch_json') as fetch:
            result = malware_intel.check_packages([{'ecosystem': 'npm', 'name': 'x', 'version': '^1.0.0'}], 'osv')
            fetch.assert_not_called()
        self.assertFalse(result['metadata']['complete'])

    def test_go_advisory_name_preserves_case(self):
        record = {'type': 'malware', 'ghsa_id': 'GHSA-abcd-efgh-ijkl',
                  'vulnerabilities': [{'package': {'ecosystem': 'go', 'name': 'example.org/Owner/Module'}}]}
        self.assertEqual(len(malware_intel._github_records([record], 'go', 'example.org/Owner/Module')), 1)

    def test_total_source_budgets_fail_closed(self):
        for kwargs in ({"max_files": 1}, {"max_total_bytes": 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(scanner.ScanError):
                scanner.build_report('test', [('a.py', 'x=1'), ('b.py', 'x=2')], [], [], [], **kwargs)

    def test_registry_enriches_each_manifest_occurrence(self):
        manifests = {name + '/package-lock.json': json.dumps({
            'packages': {'': {'dependencies': {'parent': '1.0.0'}},
                         'node_modules/parent': {'version': '1.0.0'}}}) for name in ('a', 'b')}
        with patch.object(dependencies, 'official_json', return_value={
                'repository': 'https://github.com/example/parent', 'dependencies': {}}):
            result = dependencies.analyze_dependencies(manifests, mode='registry')
        self.assertEqual(len(result['packages']), 2)
        self.assertTrue(all(p['repository'] == 'example/parent' for p in result['packages']))

    def test_explicit_range_resolves_before_advisory_query(self):
        def response(url):
            if url.endswith('/1.2.0'):
                return {'dependencies': {}}
            return {'versions': {'1.0.0': {}, '1.2.0': {}}}
        with patch.object(dependencies, 'official_json', side_effect=response):
            result = dependencies.analyze_dependencies({}, mode='registry', explicit_packages=['npm:example@^1.0.0'])
        self.assertEqual(result['packages'][0]['version'], '1.2.0')
        self.assertEqual(result['summary']['count'], 1)

    def test_saved_formats_preserve_incomplete_scan_warning(self):
        report = scanner.build_report('test', [], [], [], ['Could not read source'])
        self.assertIn('Warning: Could not read source', scanner.report_text(report))
        invocation = report_formats.sarif(report)['runs'][0]['invocations'][0]
        self.assertFalse(invocation['executionSuccessful'])
        self.assertTrue(invocation['toolExecutionNotifications'])

    def test_go_watchlist_identity_is_case_sensitive(self):
        data = threat_intel.parse_toxic_packages(json.dumps([{
            'id': 'case-test', 'PURL': 'pkg:golang/example.org/Owner/Module@v1.0.0'}]))
        package = {'ecosystem': 'go', 'name': 'example.org/Owner/Module',
                   'version': 'v1.0.0', 'manifest': 'go.sum', 'direct': True}
        self.assertEqual(len(threat_intel.match_packages([package], {'packages': data})), 1)
        package['name'] = package['name'].lower()
        self.assertEqual(threat_intel.match_packages([package], {'packages': data}), [])

    def test_uppercase_python_extension_keeps_taint_analysis(self):
        source = 'import os, requests\nrequests.get(os.getenv("ENDPOINT"))'
        self.assertTrue(any(f['rule'] == 'TAINT_URL' for f in
                            python_taint.scan_python_taint('example.PY', source, [])))

    def test_missing_grammar_does_not_download(self):
        fake = MagicMock()
        fake.downloaded_languages.return_value = []
        with patch.dict('sys.modules', {'tree_sitter_language_pack': fake}):
            with self.assertRaises(RuntimeError):
                polyglot_ast._parser('go')
        fake.get_parser.assert_not_called()

    def test_required_ast_does_not_assert_coverage_of_unsupported_languages(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, 'main.rs').write_text('fn main() {}\n', encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = scanner.main(['--path', td, '--ast-mode', 'required',
                                   '--dependencies', 'off', '--format', 'json'])
            report = json.loads(output.getvalue())
            self.assertEqual(rc, 0)
            self.assertFalse(report['ast']['complete'])
            self.assertEqual(report['ast']['parsed'], 0)


if __name__ == '__main__':
    unittest.main()
