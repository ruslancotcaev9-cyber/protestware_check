"""Declared package origins. No URL is fetched and no artifact is trusted implicitly."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

PUBLIC_REGISTRIES = {
    'npm': 'https://registry.npmjs.org',
    'pypi': 'https://pypi.org/simple',
    'cargo': 'https://github.com/rust-lang/crates.io-index',
    'composer': 'https://repo.packagist.org',
    'nuget': 'https://api.nuget.org/v3/index.json',
}


def origin(ecosystem: str, raw=None, *, kind: str | None = None, revision=None,
           integrity=None, basis: str = 'lockfile') -> dict:
    result = {'kind': kind or 'unknown', 'basis': basis}
    if isinstance(integrity, str) and integrity:
        result['integrity'] = integrity
    if isinstance(revision, str) and revision:
        result['revision'] = revision
    if not isinstance(raw, str) or not raw:
        return result
    if raw.startswith(('file:', 'link:', 'workspace:', './', '../', '/')) or kind == 'local':
        return {**result, 'kind': 'local', 'url': raw}
    vcs = raw.startswith(('git+', 'git:', 'git@', 'ssh:')) or kind == 'git'
    url = re.sub(r'^(?:git|registry|sparse)\+', '', raw)
    try:
        parts = urlsplit(url)
        if not parts.hostname:
            return {**result, 'kind': 'git' if vcs else kind or 'unknown'}
        port = parts.port
        host = parts.hostname.lower()
        netloc = f'[{host}]' if ':' in host else host
        if port is not None:
            netloc += f':{port}'
        # Credentials and signed query parameters must never appear in reports.
        result['url'] = urlunsplit((parts.scheme, netloc, parts.path, '', ''))
        if vcs and parts.fragment and re.fullmatch(r'[a-fA-F0-9]{7,64}', parts.fragment):
            result.setdefault('revision', parts.fragment)
        result['kind'] = 'git' if vcs else kind or 'url'
        if parts.username or parts.password or port not in (None, 443) or parts.query:
            result['ambiguous'] = True
        if not vcs and public_registry_url(ecosystem, result.get('url', '')) and not result.get('ambiguous'):
            result['kind'] = 'registry'
    except ValueError:
        result['kind'] = 'unknown'
        result['ambiguous'] = True
    return result


def public_registry_url(ecosystem: str, url: str) -> bool:
    if ecosystem not in PUBLIC_REGISTRIES:
        return False
    try:
        parts, public = urlsplit(url), urlsplit(PUBLIC_REGISTRIES[ecosystem])
        return (parts.scheme == 'https' and parts.hostname == public.hostname and
                not parts.username and not parts.password and parts.port in (None, 443) and
                not parts.query and not parts.fragment and
                (parts.path.rstrip('/') == public.path if ecosystem == 'cargo' else True))
    except (ValueError, TypeError):
        return False


def public_origin(ecosystem: str, *, basis: str = 'explicit-coordinate') -> dict:
    return origin(ecosystem, PUBLIC_REGISTRIES.get(ecosystem), kind='registry', basis=basis)


def advisory_origin_matches(package: dict) -> bool:
    value = package.get('origin')
    if not isinstance(value, dict) or value.get('ambiguous'):
        return False
    if package.get('ecosystem') == 'go':
        return value.get('kind') == 'module' and value.get('module') == package.get('name')
    return value.get('kind') == 'registry' and public_registry_url(package.get('ecosystem'), value.get('url', ''))


def origin_key(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def npm_origin(item: dict) -> dict:
    return origin('npm', item.get('resolved'), integrity=item.get('integrity'))


def python_origin(item: dict) -> dict:
    source = item.get('source') or {}
    if isinstance(source, dict):
        if source.get('git') or source.get('type') == 'git':
            return origin('pypi', source.get('git') or source.get('url'), kind='git',
                          revision=source.get('resolved_reference') or source.get('reference'))
        if source.get('registry') or source.get('type') in {'legacy', 'index'}:
            return origin('pypi', source.get('registry') or source.get('url'), kind='registry')
        if source.get('url'):
            return origin('pypi', source['url'])
    vcs = item.get('vcs')
    if isinstance(vcs, dict):
        return origin('pypi', vcs.get('url'), kind='git', revision=vcs.get('commit-id'))
    return origin('pypi', item.get('index'), kind='registry' if item.get('index') else None)
