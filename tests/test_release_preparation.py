"""Checks public release readiness without making the repository public."""
from __future__ import annotations

from pathlib import Path
import unittest

import protestware_check

ROOT = Path(__file__).resolve().parents[1]

class ReleaseChecks(unittest.TestCase):
    def test_release_version_and_docs(self):
        self.assertGreaterEqual(tuple(map(int, protestware_check.VERSION.split('.'))), (1, 0, 0))
        for name in ('CHANGELOG.md', 'CONTRIBUTING.md', 'LICENSE',
                     'SECURITY.md', 'docs/RELEASE_CHECKLIST.md',
                     'docs/releases/v1.0.0.md', 'scripts/install_gitleaks.sh'):
            self.assertTrue((ROOT / name).is_file(), name)
        changelog = (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8')
        self.assertIn('## [1.0.0]', changelog)
        self.assertIn('release candidate', changelog)

    def test_pinned_checksum_and_history_scope(self):
        sh = (ROOT / 'scripts/install_gitleaks.sh').read_text(encoding='utf-8')
        self.assertIn('8.30.1', sh)
        self.assertIn('551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb', sh)
        self.assertIn('sha256sum --check --status', sh)
        for workflow in ('release.yml', 'secret-history-scan.yml'):
            body = (ROOT / '.github/workflows' / workflow).read_text(encoding='utf-8')
            self.assertIn("--log-opts='--all'", body)
            self.assertIn('> /dev/null 2>&1', body)
            self.assertIn('exit 1', body)

    def test_workflows_avoid_auto_publication(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML optional outside release CI')
        for path in ('secret-history-scan.yml','release.yml'):
            data = yaml.load((ROOT / '.github/workflows' / path).read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
            self.assertIn('on', data)
        release = yaml.load((ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8'),Loader=yaml.BaseLoader)
        self.assertEqual(release['jobs']['release_draft']['needs'], 'verify')
        self.assertIn('contents: write', (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8'))
        self.assertIn('--draft', (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8'))
        scan = yaml.load((ROOT / '.github/workflows/secret-history-scan.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        self.assertEqual(scan['jobs']['history']['permissions'] if 'permissions' in scan['jobs']['history'] else scan['permissions']['contents'], 'read')

if __name__=='__main__':
    unittest.main()
