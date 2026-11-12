"""Project evaluation integrity and separation of primary labels from helpers."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import corpus_evaluation


class CorpusProjectTests(unittest.TestCase):
    def case(self):
        code = "export {rmSync} from 'fs'"
        raw = code.encode()
        return {'id': 'project', 'language': 'TypeScript', 'path': 'main.ts', 'rule': 'FS_DELETE',
                'code': "import {rmSync} from './api.js'; rmSync(path)", 'positive': True,
                'project_files': [{'path': 'api.ts', 'code': code, 'sha256': sha256(raw).hexdigest(),
                                   'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}]}

    def load(self, case):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'cases.json'
            path.write_text(json.dumps({'schema': 1, 'cases': [case]}))
            result = corpus_evaluation.load_document(path)
            self.assertEqual(result[1], sha256(path.read_bytes()).hexdigest())
            return result

    def test_helpers_are_checksum_bound_with_unique_canonical_paths(self):
        self.load(self.case())
        for key, value in (('path', '../api.ts'), ('path', '/api.ts'), ('path', 'main.ts'),
                           ('path', 'a\\api.ts'), ('sha256', '0' * 64), ('git_blob_sha', '0' * 40), ('code', 'tampered')):
            case = self.case()
            case['project_files'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load(case)
        case = self.case()
        case['project_files'] *= 2
        with self.assertRaises(ValueError):
            self.load(case)

    def test_helper_findings_cannot_satisfy_the_primary_label(self):
        report = {'findings': [{'rule': 'FS_DELETE', 'file': 'api.ts'}], 'ast': {'parsed': 2}, 'warnings': []}
        with patch('protestware_check.build_report', return_value=report):
            result = corpus_evaluation.evaluate([self.case()])
        self.assertEqual(result['overall']['fn'], 1)
        self.assertEqual(result['results'][0]['input_kind'], 'project')

    def test_project_partial_and_unavailable_backends_are_counted(self):
        for stats, expected in (({'partial': 1}, 'tp'), ({'degraded': 1}, 'errors')):
            report = {'findings': [{'rule': 'FS_DELETE', 'file': 'main.ts'}], 'ast': stats, 'warnings': ['partial']}
            with patch('protestware_check.build_report', return_value=report):
                result = corpus_evaluation.evaluate([self.case()])
            self.assertEqual(result['results'][0]['outcome'], expected)
            self.assertFalse(result['analysis']['complete'])


if __name__ == '__main__':
    unittest.main()
