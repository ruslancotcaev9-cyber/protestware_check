"""Bounded, same-file interprocedural URL provenance for Python.

No input is imported, evaluated or executed. Analysis is conservative: unknown
functions propagate taint, and recursive/unresolved calls have fixed budgets.
"""
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
MAX_CALL_DEPTH = 6
MAX_INVOCATIONS = 200


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return (dotted(node.value) + '.' + node.attr).strip('.')
    return ''


class Analyzer:
    def __init__(self, path: str, content: str, allowed: list[str], tree: ast.Module):
        self.path, self.content, self.allowed = path, content, allowed
        self.lines = content.splitlines()
        self.findings: list[dict] = []
        self.aliases: dict[str, str] = {}
        self.seen: set[tuple[str, int]] = set()
        self.functions = {s.name: s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.active: list[str] = []
        self.return_stack: list[list[Flow]] = []
        self.invocations = 0

    def resolve(self, name: str) -> str:
        parts = name.split('.')
        return '.'.join([self.aliases.get(parts[0], parts[0]), *parts[1:]])

    def emit(self, rule: str, severity: str, call: ast.Call, detail: str, flow: Flow | None = None):
        line = call.lineno
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        entry = {'rule': rule, 'category': 'dataflow' if rule == 'TAINT_URL' else 'network',
                 'severity': severity, 'file': self.path, 'line': line,
                 'evidence': (self.lines[line - 1] if line <= len(self.lines) else '')[:240].strip(),
                 'message': detail, 'analysis': 'python-ast-taint'}
        if flow and flow.sources:
            trace = flow.trace or (('source', flow.sources[0][1], flow.sources[0][0]),)
            entry['dataflow'] = [{'file': self.path, 'line': step_line, 'kind': kind,
                                  'message': msg} for kind, step_line, msg in
                                 (*trace, ('sink', line, self.resolve(dotted(call.func))))]
        self.findings.append(entry)

    def combine(self, vals: list[Flow], literal: str | None = None) -> Flow:
        sources = tuple(sorted({s for val in vals for s in val.sources}))
        trace = next((val.trace for val in vals if val.sources and val.trace), ())
        return Flow(sources, literal, trace)

    def evaluate_function(self, name: str, call: ast.Call, env: dict[str, Flow]) -> Flow:
        fn = self.functions.get(name)
        if not fn or name in self.active or len(self.active) >= MAX_CALL_DEPTH or self.invocations >= MAX_INVOCATIONS:
            # Do not infer cleanliness from an unanalyzable recursive/complex call.
            vals = [self.expr(arg, env) for arg in call.args]
            vals += [self.expr(kw.value, env) for kw in call.keywords]
            return self.combine(vals)
        self.invocations += 1
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        values = [self.expr(arg, env) for arg in call.args]
        keywords = {kw.arg: self.expr(kw.value, env) for kw in call.keywords if kw.arg}
        local: dict[str, Flow] = {}
        for i, param in enumerate(params):
            val = keywords.get(param.arg, values[i] if i < len(values) else Flow())
            local[param.arg] = val.step('call', call.lineno, f'call {name}').step(
                'parameter', fn.lineno, f'{name} parameter {param.arg}')
        if fn.args.vararg:
            local[fn.args.vararg.arg] = self.combine(values[len(params):])
        self.active.append(name)
        self.return_stack.append([])
        try:
            self.suite(fn.body, local)
            returns = self.return_stack[-1]
        finally:
            self.return_stack.pop()
            self.active.pop()
        if not returns:
            return Flow()
        result = returns[0]
        for value in returns[1:]:
            result = result.merge(value)
        return result.step('call-result', call.lineno, f'{name} result')

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
                kind = 'geolocation' if GEO.search(name) else 'untrusted-input'
                return Flow(sources=((kind, node.lineno),), trace=(('source', node.lineno, name),))
            return self.expr(node.value, env)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expr(node.left, env), self.expr(node.right, env)
            lit = left.literal + right.literal if isinstance(left.literal, str) and isinstance(right.literal, str) else None
            return self.combine([left, right], lit)
        if isinstance(node, ast.JoinedStr):
            vals = [self.expr(value, env) for value in node.values]
            lit = ''.join(val.literal for val in vals) if all(isinstance(v.literal, str) for v in vals) else None
            return self.combine(vals, lit)
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, env)
        if isinstance(node, ast.Call):
            name = self.resolve(dotted(node.func))
            if SOURCES.search(name):
                kind = 'geolocation' if GEO.search(name) else 'untrusted-input'
                return Flow(sources=((kind, node.lineno),), trace=(('source', node.lineno, name),))
            if any(domain in ast.unparse(node).lower() for domain in GEO_ENDPOINTS):
                return Flow(sources=(('geolocation', node.lineno),),
                            trace=(('source', node.lineno, 'GeoIP service'),))
            if name in self.functions:
                return self.evaluate_function(name, node, env)
            vals = [self.expr(arg, env) for arg in node.args]
            vals.extend(self.expr(k.value, env) for k in node.keywords)
            if isinstance(node.func, ast.Attribute):
                vals.append(self.expr(node.func.value, env))
            return self.combine(vals)
        vals = [self.expr(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return self.combine(vals)

    def call(self, node: ast.Call, env: dict[str, Flow]):
        name = self.resolve(dotted(node.func))
        if not NETWORK_CALL.fullmatch(name):
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
            self.emit('TAINT_URL', 'medium', node, f'Python AST: {detail} reaches {name} URL', flow)
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
                continue  # Function bodies are inspected with parameter bindings below.
            elif isinstance(node, ast.Assign):
                self.inspect(node.value, env)
                value = self.expr(node.value, env)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value.step('assignment', node.lineno, target.id)
            elif isinstance(node, ast.AnnAssign):
                self.inspect(node.value, env)
                if isinstance(node.target, ast.Name):
                    env[node.target.id] = self.expr(node.value, env).step('assignment', node.lineno, node.target.id)
            elif isinstance(node, ast.AugAssign):
                self.inspect(node.value, env)
                if isinstance(node.target, ast.Name):
                    env[node.target.id] = env.get(node.target.id, Flow()).merge(self.expr(node.value, env)).step(
                        'assignment', node.lineno, node.target.id)
            elif isinstance(node, ast.Return):
                self.inspect(node.value, env)
                if self.return_stack:
                    self.return_stack[-1].append(self.expr(node.value, env).step('return', node.lineno, 'return value'))
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
                name = self.resolve(dotted(x.func))
                if name in self.functions:
                    self.evaluate_function(name, x, env)
                else:
                    self.call(x, env)


def scan_python_taint(path: str, content: str, allowed_domains: list[str]) -> list[dict] | None:
    if Path(path).suffix.lower() != '.py':
        return []
    try:
        tree = ast.parse(content, filename=path)
    except (SyntaxError, ValueError, MemoryError):
        return None
    analyzer = Analyzer(path, content, allowed_domains, tree)
    analyzer.suite(tree.body, {})
    for name, fn in analyzer.functions.items():
        # Search for sources originating inside functions even without a known caller.
        empty = ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=[], keywords=[])
        empty.lineno = fn.lineno
        analyzer.evaluate_function(name, empty, {})
    return analyzer.findings
