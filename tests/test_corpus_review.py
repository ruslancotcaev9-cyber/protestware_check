"""Candidate labels, honest analysis coverage and review-ledger integrity."""
import contextlib
import copy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import corpus_evaluation as evaluation
import corpus_review
from scripts.corpus_review import main as review_cli
from scripts.evaluate_corpus import main as evaluate_cli

ROOT = Path(__file__).resolve().parents[1]


def case(identifier='one', positive=True):
    return {'id': identifier, 'language': 'test', 'path': identifier + '.py', 'rule': 'RULE',
            'positive': positive, 'code': 'inert data, never executed', 'cohort': 'new-v4', 'operation_scope': 'native-call'}


class EvaluationCoverageTests(unittest.TestCase):
    def test_grouped_metrics_and_configuration_are_not_inferred_from_results(self):
        cases = [case('one'), case('two', False)]
        cases[0]['ast_mode'] = 'auto'
        cases[1]['cohort'] = 'retained-v3'
        def scan(path, text, terms, domains, *, ast_mode, ast_stats, ast_warnings):
            self.assertEqual(ast_mode, 'auto' if path == 'one.py' else 'required')
            ast_stats['parsed'] = 1
            return [{'rule': 'RULE'}] if path == 'one.py' else []
        report = evaluation.evaluate(cases, scan=scan)
        self.assertEqual((report['overall']['tp'], report['overall']['tn']), (1, 1))
        self.assertTrue(report['analysis']['complete'])
        self.assertEqual({r['cohort'] for r in report['by_cohort']}, {'new-v4', 'retained-v3'})
        self.assertEqual({r['mode'] for r in report['by_ast_mode']}, {'auto', 'required'})

    def test_auto_partial_findings_and_diagnostics_remain_visible(self):
        value = {**case(), 'ast_mode': 'auto'}
        def scan(*args, **kwargs):
            kwargs['ast_stats']['partial'] = 1
            kwargs['ast_warnings'].append('AST partial analysis: explicit budget diagnostic')
            return [{'rule': 'RULE'}]
        report = evaluation.evaluate([value], scan=scan)
        self.assertEqual(report['overall']['tp'], 1)
        self.assertTrue(report['metrics_valid'])
        self.assertFalse(report['analysis']['complete'])
        self.assertEqual(report['analysis']['partial_cases'], 1)
        self.assertEqual(report['results'][0]['matching_analyses'], ['text-heuristic'])
        self.assertIn('budget', report['results'][0]['ast']['warnings'][0])

    def test_auto_backend_failure_is_not_hidden_by_fallback_or_report_only(self):
        def scan(*args, **kwargs):
            kwargs['ast_stats']['degraded'] = 1
            return [{'rule': 'RULE'}]
        report = evaluation.evaluate([{**case(), 'ast_mode': 'auto'}], scan=scan)
        self.assertFalse(report['metrics_valid'])
        self.assertEqual(report['overall']['errors'], 1)
        self.assertEqual(evaluation.status(report, report_only=True), 2)

    def test_unsupported_mode_and_group_types_are_rejected(self):
        for changed in ({'ast_mode': 'off'}, {'cohort': ['new-v4']}, {'operation_scope': 'unbounded group name'}):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder, 'corpus.json')
                path.write_text(json.dumps({'schema': 1, 'cases': [{**case(), **changed}]}))
                with self.assertRaises(ValueError):
                    evaluation.load(path)

    def test_corpus_metadata_and_hash_are_read_as_one_snapshot(self):
        document = {'schema': 1, 'cases': [case()]}
        raw = json.dumps(document).encode()
        with patch.object(evaluation.safe_io, 'read_regular', return_value=raw) as read:
            actual, checksum = evaluation.load_document('unused')
        read.assert_called_once()
        self.assertEqual((actual, checksum), (document, sha256(raw).hexdigest()))


class ReviewLedgerTests(unittest.TestCase):
    def setUp(self):
        self.cases = [case('one'), case('two', False)]
        self.checksum = 'a' * 64
        self.document = corpus_review.prepare(self.cases, self.checksum)

    def test_prepare_never_claims_human_review(self):
        summary = corpus_review.validate(self.document, self.cases, self.checksum)
        self.assertEqual(summary['status'], 'pending')
        self.assertEqual(summary['counts'], {'pending': 2, 'confirmed': 0, 'disputed': 0})
        self.assertFalse(summary['identity_verified'])

    def test_stale_corpus_case_content_or_label_is_rejected(self):
        for changed in ({'code': 'changed'}, {'positive': False}, {'rule': 'OTHER'}, {'ast_mode': 'auto'}):
            current = copy.deepcopy(self.cases)
            current[0].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                corpus_review.validate(self.document, current, self.checksum)
        with self.assertRaises(ValueError):
            corpus_review.validate(self.document, self.cases, 'b' * 64)

    def test_duplicate_missing_and_unknown_records_are_rejected(self):
        for records in ([self.document['cases'][0]] * 2, self.document['cases'][:1],
                        [self.document['cases'][0], {**self.document['cases'][1], 'id': 'unknown'}]):
            with self.assertRaises(ValueError):
                corpus_review.validate({**self.document, 'cases': records}, self.cases, self.checksum)

    def test_completed_review_requires_evidence_and_timezone(self):
        for changes in ({'decision': 'confirmed'}, {'decision': 'disputed', 'reviewer': 'Review fixture'},
                        {'reviewer': 'Named but still pending'}):
            document = copy.deepcopy(self.document)
            document['cases'][0].update(changes)
            with self.assertRaises(ValueError):
                corpus_review.validate(document, self.cases, self.checksum)

    def test_disputed_and_claimed_complete_are_distinct_from_authenticated_identity(self):
        for record in self.document['cases']:
            record.update(decision='confirmed', reviewer='Test reviewer fixture', reviewer_type='independent-human',
                          reviewed_at='2026-11-12T10:00:00+03:00', reason='Test-only review evidence; not a real adjudication')
        summary = corpus_review.validate(self.document, self.cases, self.checksum)
        self.assertEqual(summary['status'], 'claimed-complete')
        self.assertFalse(summary['identity_verified'])
        self.document['cases'][0]['decision'] = 'disputed'
        self.assertEqual(corpus_review.validate(self.document, self.cases, self.checksum)['status'], 'disputed')
        self.assertTrue(self.cases[0]['positive'])

    def test_preparing_files_cannot_overwrite_review_work(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            corpus = root / 'corpus.json'
            corpus.write_text(json.dumps({'schema': 1, 'cases': self.cases}))
            output = root / 'review.json'
            corpus_review.prepare_files(corpus, output)
            before = output.read_bytes()
            with self.assertRaisesRegex(ValueError, 'never overwritten'):
                corpus_review.prepare_files(corpus, output)
            self.assertEqual(output.read_bytes(), before)

    def test_require_complete_returns_one_for_pending_and_two_for_invalid(self):
        corpus = ROOT / 'tests/corpus/external.json'
        review = ROOT / 'tests/corpus/external-review.json'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(review_cli(['validate', '--corpus', str(corpus), '--review', str(review)]), 0)
            self.assertEqual(review_cli(['validate', '--corpus', str(corpus), '--review', str(review), '--require-complete']), 1)
        with tempfile.TemporaryDirectory() as folder:
            invalid = Path(folder, 'invalid.json')
            invalid.write_text('{}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(review_cli(['validate', '--corpus', str(corpus), '--review', str(invalid)]), 2)

    def test_repository_review_binds_every_candidate_without_approval(self):
        corpus = ROOT / 'tests/corpus/external.json'
        doc, checksum = evaluation.load_document(corpus)
        summary = corpus_review.load(ROOT / 'tests/corpus/external-review.json', doc['cases'], checksum)
        self.assertEqual(summary['counts'], {'pending': 72, 'confirmed': 0, 'disputed': 0})
        self.assertFalse(summary['identity_verified'])

    def test_worksheet_contains_pinned_sources_but_no_approval(self):
        document, checksum = evaluation.load_document(ROOT / 'tests/corpus/external.json')
        text = corpus_review.worksheet(document['cases'], checksum)
        self.assertIn('Независимое ревью не выполнено', text)
        self.assertIn(checksum, text)
        self.assertEqual(text, (ROOT / 'docs/CORPUS_LABEL_REVIEW_V4.md').read_text())

    def test_stale_review_is_rejected_before_any_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'review.json')
            path.write_text('{}')
            with patch.object(evaluation, 'evaluate', side_effect=AssertionError('Must validate first')), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(evaluate_cli(['--corpus', str(ROOT / 'tests/corpus/external.json'), '--review-file', str(path)]), 2)


if __name__ == '__main__':
    unittest.main()
