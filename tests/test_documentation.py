"""Docs/publication contract: static checks, never execute untrusted code."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    def test_required_documents(self):
        for name in ('README.md', 'LICENSE', 'SECURITY.md', 'docs/USER_GUIDE.md', 'docs/TECHNICAL_REFERENCE.md'):
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file(), name)

    def test_apache_license_complete(self):
        content = (ROOT / 'LICENSE').read_text(encoding='utf-8')
        self.assertIn('Apache License', content)
        self.assertIn('TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION', content)
        self.assertIn('END OF TERMS AND CONDITIONS', content)
        self.assertIn('9. Accepting Warranty or Additional Liability', content)

    def test_local_markdown_links_exist(self):
        docs = ['README.md', 'SECURITY.md', 'docs/USER_GUIDE.md', 'docs/TECHNICAL_REFERENCE.md']
        for rel in docs:
            text = (ROOT / rel).read_text(encoding='utf-8')
            for link in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', text):
                path = link.split('#', 1)[0]
                if not path or path.startswith(('http:', 'https:', 'mailto:')):
                    continue
                with self.subTest(document=rel, link=link):
                    self.assertTrue((ROOT / rel).parent.joinpath(path).exists())

    def test_security_policy_contains_workflow(self):
        p = (ROOT / 'SECURITY.md').read_text(encoding='utf-8')
        for word in ('Supported versions', 'Reporting a vulnerability privately', 'Triage',
                     'Coordinated disclosure', 'maintainer security configuration'):
            self.assertIn(word.lower(), p.lower())
        self.assertIn('reporting has been enabled', p)


if __name__ == '__main__':
    unittest.main()
