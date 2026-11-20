"""Source ingestion and minimum coverage through the scanner and CI gate."""
import base64
import codecs
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ci_integration
import json_contracts
import protestware_check as scanner
import scan_policy
from scan_coverage import Coverage


class SourceDecodingTests(unittest.TestCase):
    def read(self, raw, origin):
        coverage = Coverage(enumeration=origin)
        warnings = []
        path = 'query.sql'
        if origin == 'local':
            with tempfile.TemporaryDirectory() as directory:
                Path(directory, path).write_bytes(raw)
                files = list(scanner.iter_local(Path(directory), 1024, [], warnings, coverage))
            if files:
                self.assertEqual(coverage.raw_hashes[path], sha256(raw).hexdigest())
        else:
            responses = [{'default_branch': 'main'}, {'sha': 'a' * 40},
                         {'tree': [{'path': path, 'type': 'blob', 'sha': 'b' * 40}]},
                         {'encoding': 'base64', 'content': base64.b64encode(raw).decode()}]
            with patch.object(scanner, 'api_json', side_effect=responses):
                files = list(scanner.iter_github('example/repo', None, 1024, [], warnings, coverage))
        return scanner.build_report('fixture', files, [], [], warnings, coverage=coverage,
                                    ast_mode='off', dependency_mode='off')

    def test_equivalent_encodings_preserve_sql_evidence_and_lines(self):
        sql = '-- таблица\r\nDROP TABLE example;\r\n'
        expected = None
        for origin in ('local', 'github'):
            for bom, encoding in [(b'', 'utf-8'), (codecs.BOM_UTF8, 'utf-8'),
                                  (codecs.BOM_UTF16_LE, 'utf-16-le'), (codecs.BOM_UTF16_BE, 'utf-16-be')]:
                with self.subTest(origin=origin, encoding=encoding, bom=bom):
                    raw = bom + sql.encode(encoding)
                    report = self.read(raw, origin)
                    self.assertTrue(report['scan']['complete'])
                    self.assertEqual(report['coverage']['file_counts'], {'scanned': 1})
                    self.assertEqual(report['coverage']['input_bytes_read'], len(raw))
                    self.assertEqual(report['coverage']['analysis_utf8_bytes'], len(sql.encode()))
                    findings = report['findings']
                    self.assertTrue(any(f['rule'] == 'SQL_DESTRUCTIVE' and f['line'] == 2 for f in findings))
                    if expected is None:
                        expected = findings
                    self.assertEqual(findings, expected)

    def test_utf16_retains_raw_byte_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = 'SELECT 1;'.encode('utf-16')
            (root/'query.sql').write_bytes(raw)
            warnings = []
            coverage = Coverage(enumeration='local')
            files = scanner.iter_local(root, 1024, [], warnings, coverage)
            with self.assertRaisesRegex(scanner.ScanError, 'budget'):
                scanner.build_report('fixture', files, [], [], warnings, coverage=coverage,
                                     max_total_bytes=len(raw) - 1)

    def test_malformed_text_and_binary_have_distinct_outcomes(self):
        for origin in ('local', 'github'):
            for raw, outcome in [(b'abc\xff', 'decode_error'), (codecs.BOM_UTF16_LE + b'x', 'decode_error'),
                                 (codecs.BOM_UTF32_LE + bytes(4), 'decode_error'),
                                 (b'\x00binary', 'binary')]:
                with self.subTest(origin=origin, raw=raw):
                    report = self.read(raw, origin)
                    self.assertEqual(report['coverage']['file_counts'], {outcome: 1})
                    self.assertEqual(report['coverage']['files_selected'], 1)
                    self.assertEqual(report['files_scanned'], 0)
                    scan_policy.apply(report, scan_policy.load())
                    self.assertEqual(report['gate']['exit_code'], 2 if outcome == 'decode_error' else 0)
                    self.assertEqual(bool(report['warnings']), outcome == 'decode_error')


class MinimumCoverageTests(unittest.TestCase):
    def test_scan_artifacts_and_gate(self):
        for minimum, number, expected in [(0, 0, 0), (1, 0, 2), (1, 1, 0), (2, 1, 2)]:
            with self.subTest(minimum=minimum, number=number), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output, policy = root/'source', root/'report', root/'policy.toml'
                source.mkdir()
                if number:
                    (source/'sample.py').write_text('x = 1\n')
                policy.write_text(f'schema=1\n[gate]\nmin_analyzed_files={minimum}\n')
                self.assertEqual(ci_integration.scan(source, output, ['--ast-mode', 'required', '--dependencies', 'off', '--policy', str(policy)]), 0)
                self.assertEqual(ci_integration.gate(output), expected)
                report = json.loads((output/'report.json').read_bytes())
                json_contracts.validate(report, 'report')
                self.assertEqual(report['gate']['reasons'], ['insufficient_files_analyzed'] if expected else [])
                invocation = json.loads((output/'findings.sarif').read_bytes())['runs'][0]['invocations'][0]
                self.assertEqual(invocation['executionSuccessful'], not expected)
                if expected:
                    messages = [n['message']['text'] for n in invocation['toolExecutionNotifications']]
                    self.assertIn(f'insufficient_files_analyzed: analyzed {number}, required {minimum}', messages)
                    report['gate'].update(reasons=[], exit_code=0)
                    with self.assertRaisesRegex(ValueError, 'minimum file coverage'):
                        json_contracts.report_semantics(report)

    def test_invalid_minimum_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory, 'policy.toml')
            for value in ('-1', 'true', '0.5', '"1"'):
                with self.subTest(value=value):
                    policy.write_text(f'schema=1\n[gate]\nmin_analyzed_files={value}\n')
                    with self.assertRaisesRegex(ValueError, 'min_analyzed_files'):
                        scan_policy.load(policy)
