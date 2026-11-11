"""Context changes must reopen findings, without running scanned source."""
import copy
import unittest
from unittest.mock import patch

import analysis_context
import protestware_check as scanner
import report_formats
import scan_policy

CODE = 'import shutil\ndef handler(country):\n    if country == "RU":\n        shutil.rmtree("data")\n'


class BaselineContextTests(unittest.TestCase):
    def report(self, code=CODE, extra=(), **kwargs):
        return scanner.build_report('inert', [('handler.py', code), *extra], [], [], [],
                                    dependency_mode='off', **kwargs)

    def baseline(self, report=None, policy=None, **kwargs):
        report = report or self.report()
        scan_policy.apply(report, policy or scan_policy.load(), **kwargs)
        return scan_policy.parse_baseline(scan_policy.baseline(report))

    def test_added_call_reopens_identical_fingerprints(self):
        baseline = self.baseline()
        report = self.report(CODE + 'handler(context)\n')
        self.assertEqual({scan_policy.fingerprint(f) for f in report['findings']}, set(baseline))
        scan_policy.apply(report, scan_policy.load(), baseline_values=baseline, only_new=True)
        self.assertEqual(report['gate']['exit_code'], 1)
        self.assertEqual(report['policy']['baseline_context_changes'], ['source_digest'])
        self.assertTrue(all(f['baseline_state'] == 'updated' for f in report['findings']))
        self.assertTrue(all(f['policy_review_required'] for f in report['findings']))
        self.assertTrue(all(f['baselineState'] == 'updated' for f in report_formats.sarif(report)['runs'][0]['results']))

    def test_comments_line_shifts_and_documentation_preserve_parsed_python_context(self):
        baseline = self.baseline()
        report = self.report('\n# explanatory comment\n' + CODE, [('README.md', 'New documentation')])
        scan_policy.apply(report, scan_policy.load(), baseline_values=baseline, only_new=True)
        self.assertTrue(report['policy']['baseline_context_match'])
        self.assertEqual(report['gate']['exit_code'], 0)

    def test_caller_in_another_file_conservatively_reopens_review(self):
        report = self.report(extra=[('caller.py', 'from handler import handler\nhandler(context)\n')])
        scan_policy.apply(report, scan_policy.load(), baseline_values=self.baseline(), only_new=True)
        self.assertEqual(report['gate']['exit_code'], 1)

    def test_configuration_and_project_identity_are_bound(self):
        for changes in ({'analysis_settings': {'project_id': 'another/project'}}, {'ast_mode': 'off'}):
            with self.subTest(changes=changes):
                report = self.report(**changes)
                scan_policy.apply(report, scan_policy.load(), baseline_values=self.baseline(), only_new=True)
                self.assertIn('configuration_digest', report['policy']['baseline_context_changes'])
                self.assertEqual(report['gate']['exit_code'], 1)

    def test_policy_threshold_and_ruleset_changes_reopen_review(self):
        baseline = self.baseline()
        report = self.report()
        scan_policy.apply(report, scan_policy.load(), baseline_values=baseline, only_new=True, fail_on='medium')
        self.assertIn('policy_digest', report['policy']['baseline_context_changes'])
        with patch.object(analysis_context, 'ruleset_digest', return_value='0' * 64):
            report = self.report()
        scan_policy.apply(report, scan_policy.load(), baseline_values=baseline, only_new=True)
        self.assertIn('ruleset_digest', report['policy']['baseline_context_changes'])
        self.assertEqual(report['gate']['exit_code'], 1)

    def test_output_and_source_labels_are_not_context(self):
        report = self.report()
        report['source'] = '/different/checkout'
        scan_policy.apply(report, scan_policy.load(), baseline_values=self.baseline(), only_new=True)
        self.assertEqual(report['gate']['exit_code'], 0)

    def test_non_python_text_is_bound_conservatively(self):
        old = self.report(extra=[('config.json', '{"enabled":false}')])
        new = self.report(extra=[('config.json', '{"enabled":true}')])
        scan_policy.apply(new, scan_policy.load(), baseline_values=self.baseline(old), only_new=True)
        self.assertEqual(new['gate']['exit_code'], 1)

    def test_legacy_and_plain_set_cannot_silently_filter_findings(self):
        legacy = scan_policy.parse_baseline({'schema': 1, 'fingerprint_version': 1, 'fingerprints': list(self.baseline())})
        for baseline in (legacy, set(legacy)):
            with self.subTest(kind=type(baseline)), self.assertRaisesRegex(ValueError, 'schema 2'):
                scan_policy.apply(self.report(), scan_policy.load(), baseline_values=baseline, only_new=True)

    def test_malformed_review_context_is_rejected(self):
        document = scan_policy.baseline(self.report())
        for field, value in (('source_digest', 'x'), ('source_files', True), ('schema', 2), ('unexpected', 'x')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                changed = copy.deepcopy(document)
                changed['context'][field] = value
                scan_policy.parse_baseline(changed)

    def test_incomplete_scan_takes_priority_over_reopened_risk(self):
        report = self.report(CODE + 'handler(context)\n')
        report['scan']['complete'] = False
        scan_policy.apply(report, scan_policy.load(), baseline_values=self.baseline(), only_new=True)
        self.assertEqual(report['gate']['exit_code'], 2)


if __name__ == '__main__':
    unittest.main()
