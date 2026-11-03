"""Non-executing, intraprocedural flow analysis of dynamic Python network URLs."""
from __future__ import annotations

import ast
from pathlib import Path
from urllib.parse import urlsplit
import re
from polyglot_ast import Flow

SOURCES = re.compile(r'(?:\b(?:os\.getenv|os\.environ|input|sys\.argv|request\.(?:args|headers|query_params)|'
                     r'geoip\.|geolocation\.|ipinfo\.|ipapi\.|navigator\.geolocation)\b)', re.I)
GEO = re.compile(r'\b(?:geoip|geolocation|ipinfo|ipapi|country)\b', re.I)
NETWORK_CALL = re.compile(r'^(?:(?:requests|httpx|urllib\.request|aiohttp)\.(?:get|post|put|delete|patch|head|request|urlopen)|urlopen)$')
GEO_ENDPOINTS = {'ipapi.co', 'ipinfo.io', 'ip-api.com', 'ipwho.is', 'ipgeolocation.io'}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return (dotted(node.value) + '.' + node.attr).strip('.')
    return ''


class Analyzer:
    def __init__(self, path: str, content: str, allowed: list[str]):
        self.path, self.content, self.allowed = path, content, allowed
        self.lines = content.splitlines()
        self.findings: list[dict] = []
        self.aliases: dict[str, str] = {}
        self.seen = set()

    def resolve(self, name: str) -> str:
        parts = name.split('.')
        return '.'.join([self.aliases.get(parts[0], parts[0]), *parts[1:]])

    def emit(self, rule: str, severity: str, call: ast.Call, detail: str):
        line = call.lineno
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        self.findings.append({'rule': rule, 'category': 'dataflow' if rule == 'TAINT_URL' else 'network',
                              'severity': severity, 'file': self.path, 'line': line,
                              'evidence': (self.lines[line - 1] if line <= len(self.lines) else '')[:240].strip(),
                              'message': detail, 'analysis': 'python-ast-taint'})

    def expr(self, node: ast.AST | None, env: dict[str, Flow]) -> Flow:
        if node is None:
            return Flow()
        if isinstance(node, ast.Constant):
            return Flow(literal=node.value) if isinstance(node.value, str) else Flow()
        if isinstance(node, ast.Name):
            return env.get(node.id, Flow())
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = self.resolve(dotted(node))
            if SOURCES.search(name):
                return Flow(sources=(('geolocation' if GEO.search(name) else 'untrusted-input', node.lineno),))
            base = node.value
            return self.expr(base, env)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expr(node.left, env), self.expr(node.right, env)
            literal = (left.literal + right.literal) if isinstance(left.literal, str) and isinstance(right.literal, str) else None
            return Flow(tuple(sorted(set(left.sources + right.sources))), literal)
        if isinstance(node, ast.JoinedStr):
            vals = [self.expr(value, env) for value in node.values]
            sources = tuple(sorted(set(s for val in vals for s in val.sources)))
            literal = ''.join(val.literal for val in vals) if all(isinstance(v.literal, str) for v in vals) else None
            return Flow(sources, literal)
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, env)
        if isinstance(node, ast.Call):
            name = self.resolve(dotted(node.func))
            if SOURCES.search(name):
                return Flow(sources=(('geolocation' if GEO.search(name) else 'untrusted-input', node.lineno),))
            # Response JSON from an explicitly geo-IP API remains geo-tainted.
            if any(domain in ast.unparse(node).lower() for domain in GEO_ENDPOINTS):
                return Flow(sources=(('geolocation', node.lineno),))
            vals = [self.expr(arg, env) for arg in node.args]
            vals.extend(self.expr(k.value, env) for k in node.keywords)
            if isinstance(node.func, ast.Attribute):
                vals.append(self.expr(node.func.value, env))
            sources = tuple(sorted(set(s for val in vals for s in val.sources)))
            return Flow(sources)
        vals = [self.expr(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return Flow(tuple(sorted(set(s for val in vals for s in val.sources))))

    def call(self, node: ast.Call, env: dict[str, Flow]):
        name = self.resolve(dotted(node.func))
        if not NETWORK_CALL.match(name):
            return
        index = 1 if name.endswith('.request') and len(node.args) > 1 else 0
        arg = node.args[index] if len(node.args) > index else None
        for kw in node.keywords:
            if kw.arg in {'url', 'uri'}:
                arg = kw.value
        if arg is None:
            return
        flow = self.expr(arg, env)
        if flow.sources:
            detail = ', '.join(f'{kind}@{line}' for kind, line in flow.sources[:5])
            self.emit('TAINT_URL', 'medium', node, f'Python AST: {detail} reaches {name} URL')
        elif isinstance(flow.literal, str):
            try:
                u = urlsplit(flow.literal)
                host = u.hostname.lower() if u.hostname and u.scheme in {'http', 'https'} else None
            except ValueError:
                host = None
            if host and not any(host == a or host.endswith('.' + a) for a in self.allowed):
                self.emit('AST_NET_EXTERNAL', 'medium', node, f'Python AST: network request to {host}')

    def suite(self, statements: list[ast.stmt], env: dict[str, Flow]) -> None:
        for node in statements:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.aliases[alias.asname or alias.name.split('.')[0]] = alias.name
                else:
                    for alias in node.names:
                        if node.level == 0:
                            self.aliases[alias.asname or alias.name] = f'{node.module}.{alias.name}'
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.suite(node.body, {})  # new lexical environment
            elif isinstance(node, ast.Assign):
                self.inspect(node.value, env)
                value = self.expr(node.value, env)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
            elif isinstance(node, ast.AnnAssign):
                self.inspect(node.value, env)
                if isinstance(node.target, ast.Name):
                    env[node.target.id] = self.expr(node.value, env)
            elif isinstance(node, ast.AugAssign):
                self.inspect(node.value, env)
                if isinstance(node.target, ast.Name):
                    env[node.target.id] = env.get(node.target.id, Flow()).merge(self.expr(node.value, env))
            elif isinstance(node, ast.If):
                self.inspect(node.test, env)
                left, right = env.copy(), env.copy()
                self.suite(node.body, left)
                self.suite(node.orelse, right)
                for key in set(left) | set(right):
                    env[key] = left.get(key, Flow()).merge(right.get(key, Flow()))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self.inspect(node, env)
                self.suite(node.body, env)
                self.suite(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                self.inspect(node, env)
                self.suite(node.body, env)
            elif isinstance(node, ast.Try):
                self.suite(node.body, env)
                for handler in node.handlers:
                    self.suite(handler.body, env)
                self.suite(node.orelse, env)
                self.suite(node.finalbody, env)
            else:
                self.inspect(node, env)

    def inspect(self, node: ast.AST | None, env: dict[str, Flow]):
        if node is None:
            return
        for x in ast.walk(node):
            if isinstance(x, ast.Call):
                self.call(x, env)


def scan_python_taint(path: str, content: str, allowed_domains: list[str]) -> list[dict] | None:
    if Path(path).suffix != '.py':
        return []
    try:
        tree = ast.parse(content, filename=path)
    except (SyntaxError, ValueError, MemoryError):
        return None
    analyzer = Analyzer(path, content, allowed_domains)
    analyzer.suite(tree.body, {})
    return analyzer.findings
