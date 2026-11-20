from hashlib import sha1, sha256
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
                         sha256((geo.ROOT/'tests/corpus/current-scanner-sha256.json').read_bytes()).hexdigest())
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
            doc = dict(cases=cases, detector_manifest_sha256=sha256(
                (geo.ROOT/'tests/corpus/current-scanner-sha256.json').read_bytes()).hexdigest())
            with patch.object(geo.scanner, 'scan_text', side_effect=inert):
                report = geo.evaluate(doc, Path(temp), {'status':'claimed-complete'}, 'fixture')
        self.assertEqual([report['overall'][key] for key in ('tp','fn','fp','tn','errors')], [1,1,1,1,0])
        self.assertEqual(report['original_source_lines']['t1']['outside_reviewed_evidence'], [2])
