"""Coverage and reviewed policy regressions; target source remains inert data."""
import contextlib
from datetime import date
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import protestware_check as scanner
from report_formats import sarif
from scan_coverage import Coverage
import scan_policy


class CoverageTests(unittest.TestCase):
    def scan(self, root, profile='source', exclude=(), samples=100):
        coverage = Coverage(profile, enumeration='local', sample_limit=samples)
        warnings = []
        return scanner.build_report('test', scanner.iter_local(root, 1000, list(exclude), warnings, coverage, profile),
                                    [], [], warnings, dependency_mode='off', ast_mode='off', coverage=coverage)

    def test_source_and_artifact_profiles_expose_different_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in ('main.py', 'dist/payload.js', 'node_modules/lib/index.js', 'bundle.min.js', 'image.png', 'blob.py'):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'\0binary' if path == 'blob.py' else b'x=1')
            source, artifact = self.scan(root), self.scan(root, 'artifact')
        self.assertEqual(source['files_scanned'], 1)
        self.assertEqual(artifact['files_scanned'], 4)
        self.assertEqual(source['coverage']['file_counts']['binary'], 1)
        self.assertEqual(source['coverage']['file_counts']['unsupported_extension'], 1)
        self.assertEqual(source['coverage']['pruned_directories']['default_directory'], 2)
        self.assertTrue(source['coverage']['pruned_subtree_file_counts_unknown'])
        self.assertEqual(source['coverage']['ast_by_extension']['.py'], {'disabled': 1})
        self.assertEqual(source['ast']['disabled'], 1)

    def test_user_glob_prunes_relative_directory_in_artifact_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'dist').mkdir()
            (root / 'dist/code.js').write_text('eval(payload)')
            result = self.scan(root, 'artifact', ('dist/**',))
        self.assertEqual(result['files_scanned'], 0)
        self.assertEqual(result['coverage']['pruned_directories'], {'user_exclude': 1})

    def test_samples_are_bounded_without_losing_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            for index in range(5):
                Path(folder, str(index) + '.bin').write_bytes(b'a')
            result = self.scan(Path(folder), samples=1)
        self.assertEqual(result['coverage']['file_counts']['unsupported_extension'], 5)
        self.assertEqual(len(result['coverage']['samples']), 1)
        self.assertTrue(result['coverage']['samples_truncated'])

    def test_github_report_pins_the_commit_and_counts_submodules(self):
        coverage = Coverage(enumeration='github')
        def api(url, token):
            if '/commits/' in url:
                return {'sha': 'a' * 40}
            if '/git/trees/' in url:
                self.assertIn('a' * 40, url)
                return {'sha': 'b' * 40, 'tree': [{'path': 'vendor', 'type': 'commit'}]}
            return {'default_branch': 'main'}
        with patch.object(scanner, 'api_json', side_effect=api):
            self.assertEqual(list(scanner.iter_github('example/demo', None, 1000, [], [], coverage)), [])
        self.assertEqual(coverage.as_dict()['resolved_commit'], 'a' * 40)
        self.assertEqual(coverage.as_dict()['file_counts'], {'submodule': 1})

    def test_invalid_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            scanner.is_scannable('app.py', [], 'invalid')


class PolicyTests(unittest.TestCase):
    def report(self):
        return scanner.build_report('test', [('demo.py', 'if country == "RU":\n    import shutil\n    shutil.rmtree("demo")')],
                                    [], [], [], dependency_mode='off')

    def apply(self, report, policy=None, **kwargs):
        return scan_policy.apply(report, policy or scan_policy.load(), **kwargs)

    def load(self, content):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'policy.toml')
            path.write_text(content)
            return scan_policy.load(path)

    def test_fingerprint_survives_line_shift_but_changes_with_evidence(self):
        first = self.report()['findings'][-1]
        moved = {**first, 'line': first['line'] + 20}
        self.assertEqual(scan_policy.fingerprint(first), scan_policy.fingerprint(moved))
        self.assertNotEqual(scan_policy.fingerprint(first), scan_policy.fingerprint({**first, 'evidence': 'different action'}))

    def test_baseline_only_new_and_new_action_remains_blocking(self):
        report = self.report()
        baseline = set(scan_policy.baseline(report)['fingerprints'])
        self.apply(report, baseline_values=baseline, only_new=True)
        self.assertEqual(report['gate']['exit_code'], 0)
        self.assertEqual(report['risk'], 'high')
        self.assertTrue(all(item['policy_decision'] == 'baseline' for item in report['findings']))
        report['findings'].append({'rule': 'NEW_ACTION', 'severity': 'high', 'file': 'new.py', 'line': 1, 'evidence': 'new'})
        self.apply(report, baseline_values=baseline, only_new=True)
        self.assertEqual(report['gate']['exit_code'], 1)

    def test_incompleteness_is_not_hidden_by_a_baseline(self):
        report = self.report()
        report['scan']['complete'] = False
        self.apply(report, baseline_values=set(scan_policy.baseline(report)['fingerprints']), only_new=True)
        self.assertEqual(report['gate']['exit_code'], 2)

    def test_suppression_is_retained_in_json_and_sarif(self):
        report = self.report()
        finding = next(item for item in report['findings'] if item['rule'] == 'GEO_ACTION')
        policy = self.load('schema=1\n[[suppressions]]\nrule="GEO_ACTION"\nfingerprint="' + scan_policy.fingerprint(finding) +
                           '"\nreason="Approved test fixture"\nowner="security-team"\nexpires="2030-01-01"')
        self.apply(report, policy, today=date(2026, 11, 11))
        self.assertIn(finding, report['findings'])
        self.assertEqual(finding['policy_decision'], 'suppressed')
        self.assertEqual(report['gate']['exit_code'], 0)
        result = next(item for item in sarif(report)['runs'][0]['results'] if item['ruleId'] == 'GEO_ACTION')
        self.assertEqual(result['suppressions'][0]['status'], 'accepted')
        self.apply(report, policy, today=date(2031, 1, 1))
        self.assertEqual(report['gate']['exit_code'], 1)
        self.assertTrue(any('Expired' in item for item in report['warnings']))
        self.apply(report, policy, today=date(2031, 1, 1),
                   baseline_values=set(scan_policy.baseline(report)['fingerprints']), only_new=True)
        self.assertEqual(report['gate']['exit_code'], 1)

    def test_rule_override_keeps_original_severity(self):
        report = self.report()
        policy = self.load('schema=1\n[rules.GEO_ACTION]\nseverity="low"\nreason="Reviewed fixture in test-only code"\nowner="security-team"\nexpires="2030-01-01"')
        self.apply(report, policy, today=date(2026, 11, 11))
        finding = next(item for item in report['findings'] if item['rule'] == 'GEO_ACTION')
        self.assertEqual((finding['severity'], finding['effective_severity']), ('high', 'low'))
        self.assertEqual(report['gate']['exit_code'], 0)

    def test_require_complete_catches_partial_enabled_engine(self):
        report = self.report()
        report['ast']['partial'] = 1
        policy = self.load('schema=1\n[gate]\nrequire_complete=true')
        self.apply(report, policy)
        self.assertEqual(report['gate']['exit_code'], 2)
        self.assertIn('ast_incomplete', report['gate']['reasons'])

    def test_invalid_policy_and_unreviewed_exceptions_are_rejected(self):
        for text in ('schema=1\nunknown=true', 'schema=1\n[rules.GEO_ACTION]\nenabled=false',
                     'schema=1\n[scan]\nexclude="*"', 'schema=1\n[gate]\nonly_new="yes"',
                     'schema=1\n[[suppressions]]\nrule="*"\nfingerprint="*"'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_cli_policy_and_baseline_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder, 'source')
            source.mkdir()
            (source / 'demo.py').write_text('if country == "RU":\n    import shutil\n    shutil.rmtree("demo")')
            baseline = Path(folder, 'baseline.json')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                first = scanner.main(['--path', str(source), '--dependencies', 'off', '--write-baseline', str(baseline), '--format', 'json'])
                second = scanner.main(['--path', str(source), '--dependencies', 'off', '--baseline', str(baseline), '--only-new', '--format', 'json'])
            self.assertEqual((first, second), (1, 0))
            policy = Path(folder, 'policy.toml')
            policy.write_text('schema=1\n[scan]\nprofile="artifact"\n[gate]\nonly_new=true')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = scanner.main(['--path', str(source), '--dependencies', 'off', '--policy', str(policy), '--baseline', str(baseline), '--all-findings', '--format', 'json'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())['coverage']['profile'], 'artifact')

    def test_cli_never_auto_loads_a_source_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'policy.toml').write_text('schema=1\n[scan]\nprofile="artifact"')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                scanner.main(['--path', folder, '--dependencies', 'off', '--format', 'json'])
        self.assertEqual(json.loads(out.getvalue())['coverage']['profile'], 'source')


if __name__ == '__main__':
    unittest.main()
