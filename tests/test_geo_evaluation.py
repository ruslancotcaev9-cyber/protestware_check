from contextlib import redirect_stderr
from hashlib import sha1, sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import corpus_review
from scripts import evaluate_geo as geo


class GeoEvaluationTests(unittest.TestCase):
    def test_cohort_is_pinned_and_worksheet_has_six_distinct_projects(self):
        raw = geo.MANIFEST.read_bytes()
        doc = json.loads(raw)
        checksum = sha256(raw).hexdigest()
        self.assertEqual(doc['detector_manifest_sha256'],
                         sha256(geo.FROZEN_SCANNER.read_bytes()).hexdigest())
        self.assertEqual(len({r['repository'] for r in doc['cases']}), 6)
        self.assertEqual(sum(r['positive'] for r in doc['cases']), 3)
        worksheet = (geo.ROOT/'docs/GEO_ACTION_REVIEW.md').read_text()
        for case in doc['cases']:
            self.assertEqual(bool(case['evidence_lines']), case['positive'])
            self.assertTrue(all(case['first'] <= line <= case['last'] for line in case['evidence_lines']))
            self.assertIn(case['revision'], worksheet)
        corpus_review.load(geo.REVIEW, doc['cases'], checksum)

    def test_unreviewed_or_disputed_labels_cannot_run_detector(self):
        with patch.object(geo.scanner, 'scan_text', side_effect=AssertionError):
            for status in ('pending', 'disputed'):
                with self.assertRaisesRegex(ValueError, 'review'):
                    geo.evaluate({}, None, {'status': status}, '')

    def test_preparation_rejects_an_unrelated_local_file(self):
        with tempfile.TemporaryDirectory() as temp:
            case = json.loads(geo.MANIFEST.read_bytes())['cases'][0]
            (Path(temp)/(case['id']+'.py')).write_bytes(b'unrelated')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                geo.prepare([case], Path(temp))

    def test_author_decision_is_scoped_and_cannot_be_used_for_a_first_blind_measurement(self):
        decision = dict(geo.read_author_decision(), manifest_sha256='synthetic-fixture')
        with patch.object(geo, 'read_author_decision', return_value=decision), \
                patch.object(geo, 'score_cases', return_value={}) as scorer:
            with self.assertRaisesRegex(ValueError, 'does not cover'):
                geo.evaluate_author({}, None, 'another-fixture')
            with self.assertRaisesRegex(ValueError, 'first blind'):
                geo.evaluate({}, None, {'status': 'claimed-complete'}, 'synthetic-fixture')
            scorer.assert_not_called()
            result = geo.evaluate_author({}, None, 'synthetic-fixture')
            scorer.assert_called_once_with({}, None, 'synthetic-fixture', 'author-geo-v1',
                                           detector_manifest=geo.FROZEN_SCANNER)
            self.assertEqual(result['evaluation_mode'], 'author-regression')
            self.assertIs(result['review']['independent_review'], False)

    def test_case_and_location_scoring_on_unrelated_inert_inputs(self):
        raw = b"# header\nx = 1\ny = 2\n"
        blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        cases = []
        with tempfile.TemporaryDirectory() as temp:
            for index in range(4):
                case = dict(id=f't{index}', path=f'{index}.py', repository='fixture/demo',
                            positive=index < 2, first=2, last=3, scope='fixture',
                            git_blob_sha=blob, source_sha256=sha256(raw).hexdigest(),
                            evidence_lines=[3] if index < 2 else [])
                cases.append(case)
                (Path(temp)/(case['id']+'.py')).write_bytes(raw)
            def inert(path, source, *args, **kwargs):
                self.assertEqual(source, 'x = 1\ny = 2\n')
                kwargs['ast_stats']['parsed'] = 1
                if path.endswith('3.py'):
                    return []
                return [{'rule':'GEO_ACTION', 'line': 2 if path.endswith('0.py') else 1}]
            doc = dict(cases=cases, detector_manifest_sha256=sha256(geo.CURRENT_SCANNER.read_bytes()).hexdigest())
            with patch.object(geo.scanner, 'scan_text', side_effect=inert):
                report = geo.score_cases(doc, Path(temp), 'fixture', 'author-geo-v1',
                                         detector_manifest=geo.CURRENT_SCANNER)
        self.assertEqual([report['overall'][key] for key in ('tp','fn','fp','tn','errors')], [1,1,1,1,0])
        self.assertEqual(report['original_source_lines']['t1']['outside_reviewed_evidence'], [2])

    def test_comparison_shows_original_lines_and_an_unscored_candidate_error(self):
        raw = geo.MANIFEST.read_bytes()
        candidate = json.loads((geo.REFERENCE / 'geo-author-first.json').read_bytes())
        candidate['detector_manifest_sha256'] = sha256(geo.CURRENT_SCANNER.read_bytes()).hexdigest()
        case = next(c for c in candidate['results'] if c['id'] == 'geo-4')
        case.update(outcome='errors', ast={'status': 'error'})
        del candidate['original_source_lines']['geo-4']
        with patch.object(geo, 'evaluate_author', return_value=candidate) as scorer:
            report = geo.compare(json.loads(raw), None, sha256(raw).hexdigest())
        self.assertEqual(scorer.call_args.kwargs['detector_manifest'], geo.CURRENT_SCANNER)
        compared = {c['id']: c for c in report['comparison']['cases']}
        self.assertEqual(compared['geo-2']['before'], compared['geo-2']['after'])
        self.assertEqual(compared['geo-2']['after']['reported'], [1056, 1133])
        self.assertEqual(compared['geo-4']['expected_lines'], [307, 308, 309, 321, 327])
        self.assertEqual(compared['geo-4']['after'], dict(outcome='errors', ast_status='error', reported=None))
        self.assertEqual(report['comparison']['candidate']['detector_files'], json.loads(geo.CURRENT_SCANNER.read_bytes()))

    def test_modified_reference_is_rejected_before_scanning(self):
        raw = geo.MANIFEST.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('geo-author-first.json', 'provenance.json', 'repeat-check.json'):
                (root / name).write_bytes((geo.REFERENCE / name).read_bytes())
            with (root / 'geo-author-first.json').open('ab') as stream:
                stream.write(b' ')
            with patch.object(geo, 'REFERENCE', root), patch.object(geo, 'evaluate_author') as scorer:
                with self.assertRaisesRegex(ValueError, 'Reference report'):
                    geo.compare(json.loads(raw), None, sha256(raw).hexdigest())
                scorer.assert_not_called()

    def test_compare_rejects_altered_source_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'geo-1.py').write_text('# changed\n')
            output = root / 'report.json'
            args = ['compare', '--sources', str(root), '--output', str(output)]
            with redirect_stderr(StringIO()) as err:
                self.assertEqual(geo.main(args), 2)
            self.assertIn('Source checksum mismatch: geo-1', err.getvalue())
            self.assertFalse(output.exists())
            output.write_text('previous run')
            with patch.object(geo, 'compare', return_value={}), redirect_stderr(StringIO()):
                self.assertEqual(geo.main(args), 2)
            self.assertEqual(output.read_text(), 'previous run')

    def test_detector_manifest_rejects_missing_files_and_wrong_digests(self):
        original = json.loads(geo.CURRENT_SCANNER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / 'current.json'
            with patch.object(geo, 'CURRENT_SCANNER', manifest):
                for files, message in (({}, 'does not cover'), ({**original, 'ast_analysis.py': 'changed'}, 'differs')):
                    with self.subTest(message=message):
                        manifest.write_text(json.dumps(files))
                        with self.assertRaisesRegex(ValueError, message):
                            geo.score_cases({}, None, '', 'author-geo-v1', detector_manifest=manifest)
