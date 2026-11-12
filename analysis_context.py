"""Content-addressed review context; no target imports or execution."""
import ast
from functools import lru_cache
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import sys

RULE_FILES = ('protestware_check.py', 'ast_analysis.py', 'python_taint.py', 'polyglot_ast.py',
              'cpp_ast.py', 'js_behavior.py', 'language_analysis.py', 'dependency_analysis.py',
              'package_identity.py', 'threat_intel.py', 'malware_intel.py', 'scan_policy.py',
              'analysis_context.py', 'go_build_info.py', 'go_bindings.py', 'sql_operations.py', 'js_bindings.py',
              'json_contracts.py', 'js_modules.py')
DOCUMENTS = {'.md', '.mdx', '.rst'}


def json_value(value):
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, set):
        return sorted((json_value(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def digest(value):
    return sha256(json.dumps(json_value(value), sort_keys=True, ensure_ascii=True,
                             allow_nan=False, separators=(',', ':')).encode()).hexdigest()


@lru_cache(maxsize=1)
def ruleset_digest():
    root = Path(__file__).resolve().parent
    return digest([(name, sha256((root / name).read_bytes()).hexdigest()) for name in RULE_FILES])


class Collector:
    def __init__(self):
        self.entries = []
        self.python = False

    def add(self, path, content, tree=None):
        if Path(path).suffix.lower() in DOCUMENTS:
            return
        if tree is not None:
            value, kind = ast.dump(tree, include_attributes=False), 'python-ast'
            self.python = True
        else:
            value, kind = content, 'utf8-text'
        self.entries.append((path.replace('\\', '/'), kind, sha256(value.encode('utf-8')).hexdigest()))

    def finish(self, settings, dependencies, *, polyglot=False):
        backends = {}
        if self.python:
            backends['python'] = '.'.join(map(str, sys.version_info[:2]))
        if polyglot:
            for name in ('tree-sitter-language-pack', 'tree-sitter'):
                try:
                    backends[name] = version(name)
                except PackageNotFoundError:
                    backends[name] = 'not-installed'
        identities = [{key: value for key, value in package.items() if key != 'build_context'}
                      for package in dependencies['packages']]
        return {'schema': 1, 'source_digest': digest(sorted(self.entries)), 'source_files': len(self.entries),
                'ruleset_digest': digest({'code': ruleset_digest(), 'backends': backends}),
                'configuration_digest': digest(settings),
                'dependencies_digest': digest({'packages': identities, 'complete': dependencies['summary']['complete'],
                                               'go_profiles': dependencies['summary'].get('go_build_profiles', [])})}


def effective(report, policy, fail_on):
    context = report.get('analysis_context')
    if context is None:
        return None
    return {**context, 'policy_digest': digest({'scan': policy['scan'], 'rules': policy['rules'],
                                              'suppressions': policy['suppressions'], 'fail_on': fail_on,
                                              'require_complete': policy['gate'].get('require_complete', False)})}
