"""Frozen external snippets are attributed, reproducible and never executed."""
from hashlib import sha256
import json
from pathlib import Path
import re
import unittest

import corpus_evaluation

ROOT = Path(__file__).resolve().parents[1]


class ExternalCorpusTests(unittest.TestCase):
    def test_provenance_and_licenses_are_pinned(self):
        cases = corpus_evaluation.load(ROOT / 'tests/corpus/external.json')
        self.assertEqual(len(cases), 24)
        self.assertEqual(len({c['language'] for c in cases}), 6)
        self.assertEqual(sum(c['positive'] for c in cases), 12)
        self.assertEqual(sum(c['provenance']['whole_file'] for c in cases), 8)
        self.assertEqual(len({c['provenance']['group'] for c in cases}), 14)
        for case in cases:
            p = case['provenance']
            self.assertIsNotNone(re.fullmatch('[a-f0-9]{40}', p['revision']))
            self.assertIsNotNone(re.fullmatch('[a-f0-9]{40}', p['git_blob_sha']))
            self.assertLessEqual(p['first_line'], p['last_line'])
            license_path = ROOT / p['license_path']
            self.assertTrue(license_path.resolve().is_relative_to(ROOT / 'tests/corpus/licenses'))
            self.assertEqual(sha256(license_path.read_bytes()).hexdigest(), p['license_sha256'])

    def test_report_only_does_not_hide_analysis_errors(self):
        for errors, expected in ((0, 0), (1, 2)):
            self.assertEqual(corpus_evaluation.status({'overall': {'fp': 1, 'fn': 1, 'errors': errors}}, report_only=True), expected)

    def test_external_python_fragments_are_parsed_without_execution(self):
        cases = [c for c in corpus_evaluation.load(ROOT / 'tests/corpus/external.json') if c['language'] == 'Python']
        report = corpus_evaluation.evaluate(cases)
        self.assertEqual(report['overall']['errors'], 0)
        self.assertEqual(report['overall']['tp'], 2)
        self.assertEqual(report['overall']['tn'], 2)

    def test_promoted_v1_has_no_shared_source_files_with_fresh_evaluation(self):
        old = corpus_evaluation.load(ROOT / 'tests/corpus/promoted.json')
        fresh = corpus_evaluation.load(ROOT / 'tests/corpus/external.json')
        self.assertEqual(len(old), 14)
        key = lambda c: (c['provenance']['repository'], c['provenance']['path'])
        self.assertTrue(set(map(key, old)).isdisjoint(set(map(key, fresh))))
        self.assertTrue({c['id'] for c in old}.isdisjoint({c['id'] for c in fresh}))


if __name__ == '__main__':
    unittest.main()
