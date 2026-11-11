"""CI report/gate handoff and rule-level corpus accounting."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import re
import unittest
from unittest.mock import patch

import ci_integration
import corpus_evaluation
import protestware_check as scanner
from report_formats import sarif

ROOT = Path(__file__).resolve().parents[1]


class GitLabTests(unittest.TestCase):
    def run_scan(self, source, extra=()):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'target'
            target.mkdir()
            (target / 'sample.py').write_text(source)
            output = root / 'report'
            result = ci_integration.scan(target, output, ['--dependencies', 'off', *extra])
            return result, ci_integration.gate(output), json.loads((output / 'status.json').read_text())

    def test_report_job_succeeds_and_required_gate_blocks_findings(self):
        report, gate, status = self.run_scan('if country == "RU":\n    import shutil\n    shutil.rmtree("demo")')
        self.assertEqual((report, gate), (0, 1))
        self.assertTrue(status['report_available'])

    def test_clean_report_and_gate_succeed(self):
        self.assertEqual(self.run_scan('value = 1')[:2], (0, 0))

    def test_partial_report_is_saved_but_gate_returns_two(self):
        report, gate, status = self.run_scan('value = 1', ['--dependency-strict', '--dependencies', 'lock'])
        self.assertEqual((report, gate), (0, 2))
        self.assertEqual(status['scanner_exit_code'], 2)

    def test_missing_report_fails_the_report_job(self):
        with contextlib.redirect_stderr(io.StringIO()):
            report, gate, status = self.run_scan('def broken(', ['--ast-mode', 'required'])
        self.assertEqual((report, gate), (2, 2))
        self.assertFalse(status['report_available'])

    def test_tampered_or_missing_artifacts_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.mkdir()
            (source / 'a.py').write_text('x=1')
            output = root / 'reports'
            ci_integration.scan(source, output, ['--dependencies', 'off'])
            (output / 'report.json').write_text('{}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ci_integration.gate(output), 2)
                self.assertEqual(ci_integration.gate(root / 'missing'), 2)

    def test_existing_output_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(FileExistsError):
            ci_integration.scan(folder, folder)

    def test_line_less_package_findings_have_distinct_gitlab_rule_ids(self):
        report = scanner.build_report('test', [], [], [], [], dependency_mode='off')
        report['findings'] = [{'rule': 'MALWARE_ADVISORY', 'category': 'malware_advisory', 'severity': 'medium',
                              'file': 'package-lock.json', 'line': 0, 'message': 'review',
                              'package': {'ecosystem': 'npm', 'name': name, 'version': '1.2.3'},
                              'advisory_ids': ['MAL-2026-123'], 'evidence': name} for name in ('one', 'two')]
        converted = sarif(report, gitlab=True)['runs'][0]
        self.assertEqual(len({item['ruleId'] for item in converted['results']}), 2)
        self.assertEqual(len(converted['tool']['driver']['rules']), 2)
        self.assertTrue(all(item['locations'] for item in converted['results']))

    def test_script_entrypoints_do_not_execute_target_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.mkdir()
            marker = root / 'must-not-exist'
            (source / 'sample.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()')
            output = root / 'reports'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/gitlab_scan.py'), '--source', str(source),
                                     '--output-dir', str(output), '--', '--dependencies', 'off'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/gitlab_gate.py'), str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

    def test_example_requires_gate_and_pins_real_scanner_code(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML required to inspect example configuration')
        data = yaml.load((ROOT / 'examples/gitlab-ci.yml').read_text(), Loader=yaml.BaseLoader)
        commit = data['variables']['PROTESTWARE_SCANNER_COMMIT']
        self.assertIsNotNone(re.fullmatch(r'[a-f0-9]{40}', commit))
        self.assertNotEqual(commit, '0' * 40)
        self.assertNotIn('allow_failure', data['protestware_gate'])
        self.assertEqual(data['protestware_gate']['needs'], [{'job': 'protestware_scan', 'artifacts': 'true'}])
        self.assertEqual(data['protestware_scan']['artifacts']['when'], 'always')
        self.assertTrue(any('gitlab_gate.py' in command for command in data['protestware_gate']['script']))


class CorpusTests(unittest.TestCase):
    def test_fixture_labels_are_balanced_per_language(self):
        cases = corpus_evaluation.load(ROOT / 'tests/corpus/cases.json')
        self.assertEqual(len(cases), 48)
        self.assertEqual({item['language'] for item in cases}, {'Go', 'C#', 'JavaScript', 'TypeScript', 'SQL', 'Python'})
        for language in {item['language'] for item in cases}:
            selected = [item for item in cases if item['language'] == language]
            self.assertEqual(sum(item['positive'] for item in selected), len(selected) // 2)

    def test_python_fixtures_detect_expected_dataflows(self):
        cases = [item for item in corpus_evaluation.load(ROOT / 'tests/corpus/cases.json') if item['language'] == 'Python']
        report = corpus_evaluation.evaluate(cases, measure=True)
        self.assertEqual(report['overall'], {'tp': 4, 'fp': 0, 'tn': 4, 'fn': 0, 'errors': 0,
                                             'precision': 1.0, 'recall': 1.0, 'false_positive_rate': 0.0})
        self.assertEqual(corpus_evaluation.status(report), 0)
        self.assertGreater(report['performance']['peak_traced_python_bytes'], 0)

    def test_metrics_account_for_false_positives_and_false_negatives(self):
        cases = [{'id': str(index), 'language': 'test', 'rule': 'RULE', 'positive': index < 2,
                  'path': str(index), 'code': 'inert'} for index in range(4)]
        def scan(path, *args, **kwargs):
            return [{'rule': 'RULE'}] if path in ('0', '2') else []
        report = corpus_evaluation.evaluate(cases, scan=scan)
        self.assertEqual(report['overall'], {'tp': 1, 'fp': 1, 'tn': 1, 'fn': 1, 'errors': 0,
                                             'precision': 0.5, 'recall': 0.5, 'false_positive_rate': 0.5})
        self.assertEqual(corpus_evaluation.status(report), 1)

    def test_analysis_error_invalidates_metrics(self):
        case = corpus_evaluation.load(ROOT / 'tests/corpus/cases.json')[:1]
        with patch.object(scanner, 'scan_text', side_effect=scanner.ScanError('parser missing')):
            report = corpus_evaluation.evaluate(case)
        self.assertFalse(report['metrics_valid'])
        self.assertEqual(corpus_evaluation.status(report), 2)


if __name__ == '__main__':
    unittest.main()
