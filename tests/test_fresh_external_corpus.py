"""Fresh whole-file selection is pinned before detection; never execute inputs."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import unittest

import corpus_evaluation
import corpus_review

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests/corpus/fresh-v7.json'


class FreshExternalCorpusTests(unittest.TestCase):
    def test_prespecified_languages_modes_and_balance(self):
        document, checksum = corpus_evaluation.load_document(CORPUS)
        cases = document['cases']
        self.assertEqual(checksum, '0d917304b8db1254c9532be38f6266220f068bf7468c1790a7182099657cd2a2')
        self.assertEqual(len(cases), 24)
        self.assertEqual({c['language'] for c in cases},
                         {'Go', 'C#', 'SQL', 'JavaScript', 'TypeScript', 'Python'})
        self.assertEqual(len({c['provenance']['repository'] for c in cases}), 6)
        for language in {c['language'] for c in cases}:
            group = [c for c in cases if c['language'] == language]
            self.assertEqual((len(group), sum(c['positive'] for c in group)), (4, 2))
        self.assertTrue(all(c['ast_mode'] == 'auto' and c['cohort'] == 'fresh-v7' for c in cases))
        self.assertTrue(all('project_files' not in c for c in cases))
        self.assertEqual(document['detector_reference_commit'],
                         json.loads((ROOT / 'docs/evaluation/detector-freeze-v1.7.0.json').read_text())['detector_reference_commit'])

    def test_complete_source_bytes_evidence_and_licenses(self):
        cases = corpus_evaluation.load(CORPUS)
        for case in cases:
            with self.subTest(case=case['id']):
                p = case['provenance']
                raw = p['fragment'].encode()
                self.assertTrue(p['whole_file'])
                self.assertEqual(case['path'], p['path'])
                self.assertEqual(case['code'], p['fragment'].replace('\r\n', '\n'))
                self.assertEqual((p['prefix'], p['suffix']), ('', ''))
                self.assertEqual((p['first_line'], p['last_line']), (1, len(p['fragment'].splitlines())))
                self.assertLessEqual(p['last_line'], 1000)
                self.assertEqual(sha256(raw).hexdigest(), p['fragment_sha256'])
                self.assertEqual(sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), p['git_blob_sha'])
                self.assertRegex(p['revision'], r'^[a-f0-9]{40}$')
                license_file = (ROOT / p['license_path']).resolve()
                self.assertTrue(license_file.is_relative_to(ROOT / 'tests/corpus/licenses'))
                self.assertEqual(sha256(license_file.read_bytes()).hexdigest(), p['license_sha256'])
                self.assertEqual(bool(case['label_evidence']), case['positive'])
                for item in case['label_evidence']:
                    self.assertEqual(p['fragment'].splitlines()[item['line'] - 1], item['text'])
                self.assertEqual(case['label_status'], 'candidate-independent-review-pending')

    def test_new_repositories_and_bytes_do_not_overlap_consumed_inputs(self):
        previous = [json.loads((ROOT / path).read_text()) for path in (
            'docs/evaluation/external-corpus-v6-1.7.0.json',
            'docs/evaluation/promoted-corpus-v1.7.0.json',
            'tests/corpus/supporting-sources.json')]
        previous.append(json.loads((ROOT / 'docs/evaluation/external-corpus-v4.json').read_text()))
        repositories, blobs, texts = set(), set(), set()
        for document in previous:
            for case in document.get('cases', []):
                p = case.get('provenance')
                if p:
                    repositories.add(p['repository'])
                    blobs.add(p['git_blob_sha'])
                    texts.add(p['fragment_sha256'])
                for helper in case.get('project_files', []):
                    repositories.add(helper.get('provenance', p)['repository'])
                    blobs.add(helper['git_blob_sha'])
                    texts.add(helper['sha256'])
            for source in document.get('sources', {}).values():
                repositories.add(source['repository'])
                blobs.add(source['git_blob_sha'])
                texts.add(source['sha256'])
        for case in corpus_evaluation.load(CORPUS):
            p = case['provenance']
            self.assertNotIn(p['repository'], repositories)
            self.assertNotIn(p['git_blob_sha'], blobs)
            self.assertNotIn(p['fragment_sha256'], texts)

    def test_selection_and_earlier_corpora_are_unchanged(self):
        manifest = json.loads((ROOT / 'tests/corpus/fresh-v7-selection.json').read_text())
        document, checksum = corpus_evaluation.load_document(CORPUS)
        self.assertEqual(manifest['corpus_sha256'], checksum)
        self.assertEqual(manifest['protocol_commit'], document['protocol_commit'])
        self.assertTrue(manifest['selection_before_results'])
        for path, digest in manifest['previous_inputs_sha256'].items():
            archive = {'tests/corpus/external.json': 'docs/evaluation/external-corpus-v6-1.7.0.json',
                       'tests/corpus/promoted.json': 'docs/evaluation/promoted-corpus-v1.7.0.json'}.get(path, path)
            self.assertEqual(sha256((ROOT / archive).read_bytes()).hexdigest(), digest)
        records = {item['id']: item for item in manifest['cases']}
        self.assertEqual(set(records), {case['id'] for case in document['cases']})
        for case in document['cases']:
            p, item = case['provenance'], records[case['id']]
            self.assertEqual(item['case_sha256'], corpus_review.case_digest(case))
            self.assertEqual(item['positive'], case['positive'])
            self.assertEqual((item['path'], item['repository'], item['git_blob_sha'], item['fragment_sha256']),
                             (p['path'], p['repository'], p['git_blob_sha'], p['fragment_sha256']))
            self.assertEqual(manifest['repositories'][p['repository']], p['revision'])

    def test_fresh_review_remains_separate_and_pending(self):
        document, checksum = corpus_evaluation.load_document(CORPUS)
        summary = corpus_review.load(ROOT / 'tests/corpus/fresh-v7-review.json', document['cases'], checksum)
        self.assertEqual(summary['counts'], {'pending': 24, 'confirmed': 0, 'disputed': 0})
        self.assertFalse(summary['identity_verified'])
        worksheet = corpus_review.worksheet(document['cases'], checksum)
        worksheet = worksheet.replace('supporting-sources.json для обёрток',
                                      'закреплённые исходные ссылки для обёрток').replace('external-review.json', 'fresh-v7-review.json')
        self.assertEqual(worksheet, (ROOT / 'docs/CORPUS_LABEL_REVIEW_V7.md').read_text())

    def test_consumed_cake_cases_are_promoted_and_retained_inputs_unchanged(self):
        original = {c['id']: c for c in corpus_evaluation.load(CORPUS)}
        retained = corpus_evaluation.load(ROOT / 'tests/corpus/retained-v7.json')
        self.assertEqual(len(retained), 20)
        for case in retained:
            self.assertEqual(case, original[case['id']])
        consumed = [c for c in corpus_evaluation.load(ROOT / 'tests/corpus/promoted.json')
                    if c.get('promoted_from') in original]
        self.assertEqual(len(consumed), 4)
        for case in consumed:
            before = original[case['promoted_from']]
            for key in ('code', 'path', 'rule', 'positive', 'ast_mode', 'provenance', 'label_evidence'):
                self.assertEqual(case[key], before[key])
        self.assertEqual({c['provenance']['repository'] for c in consumed}, {'cake-build/cake'})
        self.assertTrue({c['provenance']['repository'] for c in consumed}.isdisjoint(
                        {c['provenance']['repository'] for c in retained}))

    def test_current_retained_v7_review_has_twenty_pending_records(self):
        document, checksum = corpus_evaluation.load_document(ROOT / 'tests/corpus/retained-v7.json')
        summary = corpus_review.load(ROOT / 'tests/corpus/retained-v7-review.json', document['cases'], checksum)
        self.assertEqual(summary['counts'], {'pending': 20, 'confirmed': 0, 'disputed': 0})
        self.assertFalse(summary['identity_verified'])
        text = corpus_review.worksheet(document['cases'], checksum).replace(
            'supporting-sources.json для обёрток', 'закреплённые исходные ссылки для обёрток').replace(
            'external-review.json', 'retained-v7-review.json')
        self.assertEqual(text, (ROOT / 'docs/CORPUS_LABEL_REVIEW_RETAINED_V7.md').read_text())

    def test_ci_keeps_retained_measurement_report_only_and_archives_exact_bytes(self):
        workflow = (ROOT / '.github/workflows/tests.yml').read_text()
        command = next(line for line in workflow.splitlines()
                       if 'run: python scripts/evaluate_corpus.py --corpus tests/corpus/retained-v7.json' in line)
        self.assertIn('--report-only', command)
        self.assertIn('--review-file tests/corpus/retained-v7-review.json', command)
        self.assertNotIn('||', command)
        self.assertNotIn('continue-on-error', workflow)
        self.assertIn('retained-v7-metrics.json', workflow)
        self.assertIn('RETAINED_V7_SHA256=', workflow)
        self.assertIn('RETAINED_V7_BYTES=', workflow)


if __name__ == '__main__':
    unittest.main()
