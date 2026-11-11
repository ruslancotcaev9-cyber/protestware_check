"""Exports retain the evidence needed to identify and review each advisory."""
import copy
import json
import unittest
from unittest.mock import patch

import malware_intel as mi
import protestware_check as scanner
from report_formats import sarif


class SarifFidelityTests(unittest.TestCase):
    def report(self):
        lock = {'lockfileVersion': 3, 'packages': {'': {'dependencies': {'demo': '1.2.3'}},
                'node_modules/demo': {'version': '1.2.3', 'resolved': 'https://registry.npmjs.org/demo/-/demo-1.2.3.tgz'}}}
        def fake(url, payload=None, **transport):
            if url == mi.OSV_BATCH_URL:
                return {'results': [{'vulns': [{'id': 'MAL-2026-123'}]}]}
            return {'id': 'MAL-2026-123', 'aliases': ['GHSA-abcd-1234-abcd']}
        with patch.object(mi, 'fetch_json', side_effect=fake):
            return scanner.build_report('test', [('package-lock.json', json.dumps(lock))], [], [], [], malware_mode='osv')

    def test_identity_and_all_advisory_evidence_survive_export(self):
        report = self.report()
        finding = report['findings'][0]
        result = sarif(report)['runs'][0]['results'][0]
        for key in ('package', 'advisory_ids', 'sources', 'references', 'version_match', 'origin_match', 'evidence'):
            self.assertEqual(result['properties'][key], finding[key])
        self.assertEqual(result['properties']['purl'], 'pkg:npm/demo@1.2.3')
        self.assertIn('npm:demo@1.2.3', result['message']['text'])
        self.assertIn('MAL-2026-123', result['message']['text'])
        self.assertIn('GHSA-abcd-1234-abcd', result['message']['text'])

    def test_manifest_location_does_not_invent_a_line_number(self):
        result = sarif(self.report())['runs'][0]['results'][0]
        location = result['locations'][0]['physicalLocation']
        self.assertEqual(location['artifactLocation']['uri'], 'package-lock.json')
        self.assertNotIn('region', location)

    def test_unsafe_and_synthetic_paths_have_no_location(self):
        for path in ('../outside.json', '/absolute/file.json', 'C:\\outside.json', '(package)'):
            with self.subTest(path=path):
                report = self.report()
                report['findings'][0]['file'] = path
                self.assertNotIn('locations', sarif(report)['runs'][0]['results'][0])

    def test_fingerprints_distinguish_advisories_and_origins(self):
        report = self.report()
        other = copy.deepcopy(report['findings'][0])
        other['advisory_ids'] = ['MAL-2026-124']
        report['findings'].append(other)
        third = copy.deepcopy(other)
        third['package']['origin']['integrity'] = 'sha512-other'
        report['findings'].append(third)
        fingerprints = [r['partialFingerprints']['primaryLocationLineHash'] for r in sarif(report)['runs'][0]['results']]
        self.assertEqual(len(set(fingerprints)), 3)

    def test_partial_dependency_and_advisory_checks_are_visible(self):
        report = self.report()
        report['dependencies']['summary']['complete'] = False
        report['malware_intel']['complete'] = False
        invocation = sarif(report)['runs'][0]['invocations'][0]
        self.assertFalse(invocation['executionSuccessful'])
        self.assertFalse(invocation['properties']['analysisCoverage']['dependencies'])
        self.assertFalse(invocation['properties']['analysisCoverage']['malware_intel'])


if __name__ == '__main__':
    unittest.main()
