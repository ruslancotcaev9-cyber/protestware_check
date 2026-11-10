"""Optional pinned-repository static-only integration suite (run on GitHub Actions).

The caller checks out fixed commits in a disposable directory. This script only
reads text and runs parsers; it NEVER executes build scripts from those projects.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import polyglot_ast
import protestware_check as scanner


def find_rules(root: Path, rel: str) -> list[dict]:
    source = (root / rel).read_text(encoding='utf-8', errors='replace')
    findings, diagnostic = polyglot_ast.scan_tree(rel, source, [])
    if diagnostic and not diagnostic.startswith('AST partial '):
        raise AssertionError(f'{rel} AST unavailable: {diagnostic}')
    if diagnostic:
        print(f'PARTIAL_ANALYSIS={diagnostic}')
    return findings


def production_findings(root: Path, directories: tuple[str, ...]) -> list[dict]:
    findings = []
    for folder in directories:
        path = root / folder
        if not path.exists():
            raise AssertionError(f'Missing expected project directory: {path}')
        for f in sorted(path.rglob('*')):
            if not f.is_file() or f.is_symlink() or not scanner.is_scannable(str(f.relative_to(root)), []):
                continue
            if f.stat().st_size > 1_000_000:
                continue
            relative = f.relative_to(root).as_posix()
            content = f.read_text(encoding='utf-8', errors='replace')
            findings.extend(scanner.scan_text(relative, content, [], [], ast_mode='auto'))
    return findings


def main(base: Path) -> int:
    anti = base / 'antiprop_basic'
    fmt = base / 'fmt'
    magic = base / 'magic_enum'
    flood = find_rules(anti, 'scripts/main.js')
    obf = find_rules(anti, 'scripts/invisible.js')
    assert any(x['rule'] == 'NETWORK_FLOOD' and x['severity'] == 'high' for x in flood), 'Anti-Prop flood not detected'
    assert any(x['rule'] == 'OBFUSCATED_JS' for x in obf), 'Anti-Prop obfuscation not detected'
    safe_results = {}
    for name, root, dirs in (('fmtlib/fmt', fmt, ('src', 'include')),
                             ('Neargye/magic_enum', magic, ('include',))):
        findings = production_findings(root, dirs)
        risky = [f for f in findings if f['severity'] == 'high']
        assert not risky, f'{name}: unexpected high-severity finding: {risky[:4]}'
        safe_results[name] = {'findings': len(findings), 'high': len(risky)}
    print('PINNED_REGRESSION=' + json.dumps({
        'Anti-Prop/antiprop_basic': {
            'flood': [f['rule'] for f in flood if f['rule'] == 'NETWORK_FLOOD'],
            'obfuscation': [f['rule'] for f in obf if f['rule'] == 'OBFUSCATED_JS'],
        }, **safe_results}, sort_keys=True))
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python tests/pinned_repository_regressions.py /path/to/checkout-root')
    raise SystemExit(main(Path(sys.argv[1])))
