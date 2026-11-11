"""Pagination, budgets and expiring snapshots with deterministic fake feeds."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from advisory_cache import AdvisoryCache, key_for
import malware_intel as mi
from package_identity import public_origin
import protestware_check as scanner


def package(name='demo'):
    return {'ecosystem': 'npm', 'name': name, 'version': '1.2.3', 'manifest': 'package-lock.json',
            'origin': public_origin('npm')}


def ghsa():
    return {'ghsa_id': 'GHSA-abcd-1234-abcd', 'type': 'malware',
            'vulnerabilities': [{'package': {'ecosystem': 'npm', 'name': 'demo'}}]}


class PaginationAndRetryTests(unittest.TestCase):
    def test_osv_only_continues_queries_that_have_another_page(self):
        payloads = []
        def fake(url, payload=None, **transport):
            if url.startswith(mi.OSV_DETAILS_PREFIX):
                return {'id': 'MAL-2026-123'}
            payloads.append(payload)
            if len(payloads) == 1:
                return {'results': [{'next_page_token': 'next'}, {}]}
            return {'results': [{'vulns': [{'id': 'MAL-2026-123'}]}]}
        with patch.object(mi, 'fetch_json', side_effect=fake):
            report = mi.check_packages([package(), package('other')], mode='osv')
        self.assertEqual(len(payloads[1]['queries']), 1)
        self.assertEqual(payloads[1]['queries'][0]['page_token'], 'next')
        self.assertEqual(report['metadata']['checked_packages'], 2)
        self.assertTrue(report['metadata']['complete'])
        self.assertEqual(len(report['findings']), 1)

    def test_repeated_osv_token_and_page_limits_are_incomplete(self):
        for pages, expected_calls in ((10, 2), (1, 1)):
            with self.subTest(pages=pages), patch.object(mi, 'fetch_json', return_value={'results': [{'next_page_token': 'repeat'}]}) as fetch:
                report = mi.check_packages([package()], mode='osv', max_pages=pages)
            self.assertEqual(fetch.call_count, expected_calls)
            self.assertFalse(report['metadata']['complete'])
            self.assertEqual(report['metadata']['checked_packages'], 0)

    def test_github_cursor_preserves_the_package_and_filters(self):
        with patch.object(mi, 'fetch_json', side_effect=[mi.AdvisoryPage([ghsa()], {'after': 'cursor'}), mi.AdvisoryPage([])]) as fetch:
            report = mi.check_packages([package()], mode='github')
        query = parse_qs(urlsplit(fetch.call_args.args[0]).query)
        self.assertEqual(query['after'], ['cursor'])
        self.assertEqual(query['affects'], ['demo@1.2.3'])
        self.assertEqual(query['type'], ['malware'])
        self.assertTrue(report['metadata']['complete'])
        self.assertEqual(report['metadata']['query_pages'], 2)

    def test_github_repeated_cursor_retains_partial_findings(self):
        with patch.object(mi, 'fetch_json', return_value=mi.AdvisoryPage([ghsa()], {'after': 'repeat'})):
            report = mi.check_packages([package()], mode='github')
        self.assertFalse(report['metadata']['complete'])
        self.assertEqual(len(report['findings']), 1)

    def test_external_pagination_url_is_rejected(self):
        for url in ('https://evil.example/advisories?after=cursor', 'https://api.github.com/repos/a/b?after=cursor',
                    'https://api.github.com/advisories?per_page=100'):
            with self.subTest(url=url), self.assertRaises(mi.IntelligenceError):
                mi._next_cursor(f'<{url}>; rel="next"')

    def test_retry_is_bounded_and_counts_against_request_budget(self):
        retry = mi.IntelligenceError('temporary', retryable=True, retry_after=0.1)
        with patch.object(mi, 'fetch_json', side_effect=[retry, {'results': [{}]}]) as fetch, patch.object(mi.time, 'sleep'):
            report = mi.check_packages([package()], mode='osv')
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(report['metadata']['retry_requests'], 1)
        self.assertTrue(report['metadata']['complete'])
        with patch.object(mi, 'fetch_json', side_effect=retry) as fetch, patch.object(mi.time, 'sleep'):
            report = mi.check_packages([package()], mode='osv', max_requests=1, retries=3)
        self.assertEqual(fetch.call_count, 1)
        self.assertFalse(report['metadata']['complete'])

    def test_exhausted_time_budget_does_not_send_a_request(self):
        with patch.object(mi.time, 'monotonic', side_effect=[0, 121]), patch.object(mi, 'fetch_json') as fetch:
            report = mi.check_packages([package()], mode='osv', time_budget=120)
        fetch.assert_not_called()
        self.assertFalse(report['metadata']['complete'])

    def test_nan_time_budget_is_rejected(self):
        with self.assertRaises(ValueError):
            mi.check_packages([package()], mode='osv', time_budget=float('nan'))

    def test_http_nonretryable_error_and_transport_body_limits(self):
        opener = SimpleNamespace(open=lambda *args, **kwargs: (_ for _ in ()).throw(HTTPError(args[0].full_url, 404, 'missing', {}, None)))
        with patch.object(mi, 'build_opener', return_value=opener), self.assertRaises(mi.IntelligenceError) as error:
            mi.fetch_json(mi.OSV_BATCH_URL)
        self.assertFalse(error.exception.retryable)
        body = io.BytesIO(b'x' * (mi.MAX_RESPONSE_BYTES + 1))
        body.headers = {}
        with patch.object(mi, 'build_opener', return_value=SimpleNamespace(open=lambda *args, **kwargs: body)), self.assertRaises(mi.IntelligenceError):
            mi.fetch_json(mi.OSV_BATCH_URL)

    def test_transport_exposes_validated_cursor_metadata(self):
        body = io.BytesIO(b'[]')
        body.headers = {'Link': '<https://api.github.com/advisories?after=abc>; rel="next"'}
        with patch.object(mi, 'build_opener', return_value=SimpleNamespace(open=lambda *args, **kwargs: body)):
            page = mi.fetch_json(mi.GITHUB_ADVISORIES_URL)
        self.assertEqual(page.next_cursor, {'after': 'abc'})


class SnapshotTests(unittest.TestCase):
    now = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)

    def populate(self, path, *, empty=False):
        cache = AdvisoryCache(path, now=self.now)
        with patch.object(mi, 'fetch_json', side_effect=[{'results': [{}]}] if empty else [
                {'results': [{'vulns': [{'id': 'MAL-2026-123'}]}]}, {'id': 'MAL-2026-123'}]):
            report = mi.check_packages([package()], mode='osv', snapshot=cache)
        self.assertTrue(report['metadata']['complete'])
        cache.save()
        return cache

    def test_fresh_snapshot_supports_offline_positive_and_negative_answers(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as folder:
                path = Path(folder, 'snapshot.json')
                self.populate(path, empty=empty)
                before = path.read_bytes()
                cache = AdvisoryCache(path, mode='offline', now=self.now + timedelta(hours=1))
                with patch.object(mi, 'fetch_json') as fetch:
                    report = mi.check_packages([package()], mode='osv', snapshot=cache)
                cache.save()
                fetch.assert_not_called()
                self.assertTrue(report['metadata']['complete'])
                self.assertEqual(len(report['findings']), 0 if empty else 1)
                self.assertEqual(report['metadata']['cache']['hits'], 1)
                self.assertEqual(path.read_bytes(), before)

    def test_stale_or_missing_snapshot_is_incomplete_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'snapshot.json')
            self.populate(path)
            for name in ('snapshot.json', 'missing.json'):
                cache = AdvisoryCache(Path(folder, name), mode='offline', now=self.now + timedelta(days=2))
                with patch.object(mi, 'fetch_json') as fetch:
                    report = mi.check_packages([package()], mode='osv', snapshot=cache)
                fetch.assert_not_called()
                self.assertFalse(report['metadata']['complete'])
                self.assertTrue(report['warnings'])

    def test_cache_hit_does_not_extend_entry_lifetime(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'snapshot.json')
            self.populate(path, empty=True)
            cache = AdvisoryCache(path, now=self.now + timedelta(hours=1))
            with patch.object(mi, 'fetch_json') as fetch:
                mi.check_packages([package()], mode='osv', snapshot=cache)
            fetch.assert_not_called()
            cache.save()
            value = json.loads(path.read_text())['entries'][key_for('osv', ('npm', 'demo', '1.2.3'))]
            self.assertEqual(value['retrieved_at_utc'], self.now.isoformat())

    def test_stale_negative_entry_is_refreshed_online(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'snapshot.json')
            self.populate(path, empty=True)
            later = self.now + timedelta(days=2)
            cache = AdvisoryCache(path, now=later)
            with patch.object(mi, 'fetch_json', return_value={'results': [{}]}) as fetch:
                report = mi.check_packages([package()], mode='osv', snapshot=cache)
            fetch.assert_called_once()
            self.assertTrue(report['metadata']['complete'])
            cache.save()
            value = json.loads(path.read_text())['entries'][key_for('osv', ('npm', 'demo', '1.2.3'))]
            self.assertEqual(value['retrieved_at_utc'], later.isoformat())

    def test_invalid_snapshot_timestamp_or_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'snapshot.json')
            self.populate(path)
            original = json.loads(path.read_text())
            for field in ('retrieved_at_utc', 'reference'):
                data = json.loads(json.dumps(original))
                entry = next(iter(data['entries'].values()))
                if field == 'reference':
                    entry['records'][0]['url'] = 'https://evil.example/advisory'
                else:
                    entry['retrieved_at_utc'] = 123
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    AdvisoryCache(path, now=self.now)

    def test_cli_offline_strict_uses_the_snapshot_and_never_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache_path = root / 'snapshot.json'
            cache = self.populate(cache_path, empty=True)
            source = root / 'source'
            source.mkdir()
            (source / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
                '': {'dependencies': {'demo': '1.2.3'}}, 'node_modules/demo': {
                    'version': '1.2.3', 'resolved': 'https://registry.npmjs.org/demo/-/demo-1.2.3.tgz'}}}))
            with patch.object(scanner, 'AdvisoryCache', return_value=AdvisoryCache(cache_path, mode='offline', now=self.now)), patch.object(mi, 'fetch_json') as fetch, contextlib.redirect_stdout(io.StringIO()) as output:
                code = scanner.main(['--path', str(source), '--malware-intel', 'osv', '--malware-strict',
                                     '--advisory-offline', '--advisory-cache', str(cache_path), '--format', 'json'])
            fetch.assert_not_called()
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())['malware_intel']['network_requests'], 0)


if __name__ == '__main__':
    unittest.main()
