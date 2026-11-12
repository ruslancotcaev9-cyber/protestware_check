"""Frozen external snippets are attributed, reproducible and never executed."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import unittest

import corpus_evaluation
import analysis_context

ROOT = Path(__file__).resolve().parents[1]


class ExternalCorpusTests(unittest.TestCase):
    def test_provenance_and_licenses_are_pinned(self):
        cases = corpus_evaluation.load(ROOT / 'tests/corpus/external.json')
        self.assertEqual(len(cases), 72)
        self.assertEqual(len({c['language'] for c in cases}), 6)
        self.assertEqual(sum(c['positive'] for c in cases), 36)
        self.assertEqual(sum(c['provenance']['whole_file'] for c in cases), 58)
        self.assertEqual(len({c['provenance']['group'] for c in cases}), 64)
        self.assertEqual(len({c['provenance']['repository'] for c in cases}), 15)
        for case in cases:
            p = case['provenance']
            self.assertIsNotNone(re.fullmatch('[a-f0-9]{40}', p['revision']))
            self.assertIsNotNone(re.fullmatch('[a-f0-9]{40}', p['git_blob_sha']))
            self.assertLessEqual(p['first_line'], p['last_line'])
            license_path = ROOT / p['license_path']
            self.assertTrue(license_path.resolve().is_relative_to(ROOT / 'tests/corpus/licenses'))
            self.assertEqual(sha256(license_path.read_bytes()).hexdigest(), p['license_sha256'])
            if p['whole_file']:
                raw = p['fragment'].encode()
                self.assertEqual(sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), p['git_blob_sha'])
                self.assertEqual((p['first_line'], p['last_line']), (1, len(p['fragment'].splitlines())))
                self.assertEqual((p['prefix'], p['suffix']), ('', ''))
            if p.get('binding_context'):
                context = p['binding_context']
                self.assertEqual(sha256(context['text'].encode()).hexdigest(), context['sha256'])
                self.assertIn(context['text'].replace('\r\n', '\n').strip(), case['code'])

    def test_report_only_does_not_hide_analysis_errors(self):
        for errors, expected in ((0, 0), (1, 2)):
            self.assertEqual(corpus_evaluation.status({'overall': {'fp': 1, 'fn': 1, 'errors': errors}}, report_only=True), expected)

    def test_external_python_fragments_are_parsed_without_execution(self):
        cases = [c for c in corpus_evaluation.load(ROOT / 'tests/corpus/external.json') if c['language'] == 'Python' and c['cohort'] == 'retained-v3']
        report = corpus_evaluation.evaluate(cases)
        self.assertEqual(report['overall']['errors'], 0)
        self.assertEqual(report['overall']['tp'], 2)
        self.assertEqual(report['overall']['tn'], 2)

    def test_promoted_v1_has_no_shared_source_files_with_fresh_evaluation(self):
        old = corpus_evaluation.load(ROOT / 'tests/corpus/promoted.json')
        fresh = corpus_evaluation.load(ROOT / 'tests/corpus/external.json')
        self.assertEqual(len(old), 22)
        key = lambda c: (c['provenance']['repository'], c['provenance']['path'])
        self.assertTrue(set(map(key, old)).isdisjoint(set(map(key, fresh))))
        self.assertTrue({c['id'] for c in old}.isdisjoint({c['id'] for c in fresh}))

    def test_new_whole_files_and_retained_cases_have_explicit_modes_and_candidate_labels(self):
        cases = corpus_evaluation.load(ROOT / 'tests/corpus/external.json')
        new = [c for c in cases if c['cohort'] == 'new-v4']
        old = [c for c in cases if c['cohort'] == 'retained-v3']
        self.assertEqual((len(new), len(old)), (48, 24))
        self.assertTrue(all(c['ast_mode'] == 'auto' and c['provenance']['whole_file'] for c in new))
        self.assertTrue(all(c['ast_mode'] == 'required' for c in old))
        for language in {c['language'] for c in new}:
            selected = [c for c in new if c['language'] == language]
            self.assertEqual((len(selected), sum(c['positive'] for c in selected)), (8, 4))
        for case in cases:
            self.assertEqual(case['label_status'], 'candidate-independent-review-pending')
        for case in new:
            self.assertTrue(case['rationale'])
            evidence = case['label_evidence']
            self.assertEqual(bool(evidence), case['positive'])
            for item in evidence:
                self.assertEqual(case['provenance']['fragment'].splitlines()[item['line'] - 1], item['text'])

    def test_wrapper_context_has_pinned_content_and_licenses(self):
        data = json.loads((ROOT / 'tests/corpus/supporting-sources.json').read_text())
        for source in data['sources'].values():
            raw = source['text'].encode()
            self.assertEqual(sha256(raw).hexdigest(), source['sha256'])
            self.assertEqual(sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), source['git_blob_sha'])
            self.assertIsNotNone(re.fullmatch('[a-f0-9]{40}', source['revision']))
            self.assertEqual(sha256((ROOT / source['license_path']).read_bytes()).hexdigest(), source['license_sha256'])
        for case in corpus_evaluation.load(ROOT / 'tests/corpus/external.json'):
            self.assertTrue(set(case.get('supporting_sources', [])) <= set(data['sources']))

    def test_detection_code_remains_frozen_during_evaluation(self):
        frozen = json.loads((ROOT / 'tests/corpus/detector-freeze.json').read_text())
        self.assertEqual(frozen['detector_reference_commit'], '3525be8f88b0d48a823c1466043d2d3612a2e3db')
        self.assertEqual(set(frozen['files']), set(analysis_context.RULE_FILES) | {'safe_io.py', 'requirements-ast.txt', 'requirements-resolver.txt'})
        for path, digest in frozen['files'].items():
            self.assertEqual(sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)


if __name__ == '__main__':
    unittest.main()
