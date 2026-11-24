"""Python GEO_ACTION controls. All samples are parsed as text."""
from textwrap import dedent, indent
import unittest

import ast_analysis
import protestware_check as scanner
import report_formats


def scan(code):
    return ast_analysis.scan_python("sample.py", dedent(code).lstrip("\n"), [])


def actions(findings):
    return {f["line"]: f for f in findings if f["rule"] == "GEO_ACTION"}


class PythonGeoCallsTests(unittest.TestCase):
    def test_elif_arms_keep_their_own_guard_and_network_findings(self):
        findings = scan("""
            import requests
            if country == "CA":
                pass
            elif country == "ru":
                requests.get(url)
            elif country == "it":
                requests.get(url)
            elif country == "by":
                requests.get(url)
            elif country == "my":
                requests.get(url)
        """)
        hits = actions(findings)
        self.assertEqual({f["line"] for f in findings if f["rule"] == "NET_DYNAMIC"}, {5, 7, 9, 11})
        self.assertEqual({n: f["dataflow"][0]["line"] for n, f in hits.items()}, {5: 4, 9: 8})

    def test_nested_if_in_explicit_else_and_enclosing_guard_remain(self):
        hits = actions(scan("""
            if country == "RU":
                pass
            else:
                if mode == 1:
                    marker.write_text("one")
                elif mode == 2:
                    marker.write_text("two")
            marker.write_text("common")
        """))
        self.assertEqual(set(hits), {5, 7})
        self.assertTrue(all(f["dataflow"][0]["line"] == 1 and "ложно" in f["message"] for f in hits.values()))

    def test_elif_on_an_independent_condition_keeps_the_geographic_constraint(self):
        hits = actions(scan("""
            if country != "RU":
                pass
            elif enabled:
                marker.write_text("RU only")
        """))
        self.assertEqual(set(hits), {4})
        self.assertEqual(hits[4]["dataflow"][0]["line"], 1)
        self.assertIn("ложно", hits[4]["message"])

    def test_local_network_path_in_json_and_sarif(self):
        code = dedent("""\
            from urllib.request import urlopen as read_url
            def fetch(item):
                return read_url(item)
            def translate(value):
                return fetch(value)
            if lang == "ru":
                value = original
            else:
                value = translate(original)
            marker.write_text(value)
        """)
        report = scanner.build_report("fixture", [("sample.py", code)], [], [], [],
                                      dependency_mode="off", ast_mode="required")
        hits = actions(report["findings"])
        self.assertEqual(set(hits), {9})
        trace = hits[9]["dataflow"]
        self.assertEqual([(t["kind"], t["line"]) for t in trace], [("guard", 6), ("call", 9), ("call", 5), ("sink", 3)])
        self.assertEqual(trace[-1]["message"], "urllib.request.urlopen")
        sarif = report_formats.sarif(report)["runs"][0]["results"]
        result = next(r for r in sarif if r["ruleId"] == "GEO_ACTION")
        locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual([h["location"]["physicalLocation"]["region"]["startLine"] for h in locations], [6, 9, 5, 3])

    def test_untyped_receiver_and_identically_named_functions_are_unresolved(self):
        prefix = 'import requests\ndef translate(x):\n    return requests.get(x)\n'
        for body in (
                'def caller(translate):\n    if lang == "be":\n        translate(value)',
                'def caller():\n    def translate(x): return x\n    if lang == "be": translate(value)',
                'if lang == "ru": other.translate(value)',
                'translate = alternate\nif lang == "ru": translate(value)',
                'if lang == "ru": translate(no_such_keyword=value)',
                'if lang == "ru": translate()',
                'if lang == "ru": context.bot.send_message(chat_id=chat, text="sample")'):
            with self.subTest(body=body):
                self.assertEqual(actions(scan(prefix + body)), {})

    def test_deferred_unreachable_or_unbound_network_does_not_create_a_route(self):
        for definition in (
                'def fetch(requests=fake):\n    return requests.get(url)',
                'def fetch():\n    return\n    requests.get(url)',
                'def fetch():\n    return False and requests.get(url)',
                'def fetch():\n    return requests.get(url) if False else None',
                'def fetch():\n    with managed():\n        return 1\n        requests.get(url)',
                'def fetch():\n    try:\n        return 0\n    finally:\n        pass\n    requests.get(url)',
                'def fetch():\n    later = lambda: requests.get(url)',
                'def fetch():\n    def later(): return requests.get(url)',
                'def fetch():\n    return (requests.get(url) for url in urls)',
                'def fetch():\n    yield requests.get(url)',
                'async def fetch():\n    return requests.get(url)',
                '@decorator\ndef fetch():\n    return requests.get(url)',
                'def fetch():\n    return requests.client().get(url)'):
            with self.subTest(definition=definition):
                self.assertEqual(actions(scan('import requests\n' + definition + '\nif lang == "be": fetch()')), {})
        for prefix in ('', 'import requests\nrequests = stub\n', 'from stub import requests\n',
                       'import requests\nrequests.get = stub\n'):
            with self.subTest(prefix=prefix):
                self.assertEqual(actions(scan(prefix + 'def fetch(): return requests.get(url)\nif lang == "ru": fetch()')), {})

    def test_declaration_order_and_depth_bound(self):
        self.assertEqual(actions(scan("""
            def fetch(): return http.get(url)
            if lang == "ru": fetch()
            import requests as http
        """)), {})
        self.assertEqual(actions(scan("""
            import requests
            def inner(): return requests.get(url)
            def middle(): return inner()
            def outer(): return middle()
            if lang == "ru": outer()
        """)), {})
        code = 'import requests as http\ndef fetch(*, value): return http.get(value)\n'
        for call, expected in [('fetch(value=url)', True), ('fetch(url)', False)]:
            with self.subTest(call=call):
                self.assertEqual(bool(actions(scan(code + 'if lang == "ru":\n' + indent(call, '    ')))), expected)
