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
SENSITIVE_KEY = re.compile(r'(?:^|[_-])(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIALS?|ACCESS_KEY)(?:$|[_-])', re.I)
CREDENTIAL_FILE = re.compile(r'(?:^|/)(?:\.npmrc|\.pypirc|id_(?:rsa|dsa|ed25519|ecdsa)|credentials|secrets?(?:\.[\w-]+)?)$', re.I)
SENSITIVE_KINDS = {'sensitive-environment', 'credential-file'}


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
        self.diagnostics: set[str] = set()

    def resolve(self, name: str) -> str:
        parts = name.split('.')
        return '.'.join([self.aliases.get(parts[0], parts[0]), *parts[1:]])

    def emit(self, rule: str, severity: str, call: ast.Call, detail: str, flow: Flow | None = None):
        line = call.lineno
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        entry = {'rule': rule, 'category': 'dataflow' if rule in {'TAINT_URL', 'SENSITIVE_DATA_SEND'} else 'network',
                 'severity': severity, 'file': self.path, 'line': line,
                 'evidence': (self.lines[line - 1] if line <= len(self.lines) else '')[:240].strip(),
                 'message': detail, 'analysis': 'python-ast-taint'}
        if rule == 'SENSITIVE_DATA_SEND':
            entry['confidence'] = 'medium'
        if flow and flow.sources:
            trace = flow.trace or (('source', flow.sources[0][1], flow.sources[0][0]),)
            entry['dataflow'] = [{'file': self.path, 'line': step_line, 'kind': kind,
                                  'message': msg} for kind, step_line, msg in
                                 (*trace, ('sink', line, self.resolve(dotted(call.func))))]
        self.findings.append(entry)

    def combine(self, vals: list[Flow], literal: str | None = None) -> Flow:
        sources = tuple(sorted({s for val in vals for s in val.sources}))
        trace = next((val.trace for val in vals if val.trace and any(kind in SENSITIVE_KINDS for kind, _ in val.sources)),
                     next((val.trace for val in vals if val.sources and val.trace), ()))
        return Flow(sources, literal, trace)

    def evaluate_function(self, name: str, call: ast.Call, env: dict[str, Flow]) -> Flow:
        fn = self.functions.get(name)
        if not fn or name in self.active or len(self.active) >= MAX_CALL_DEPTH or self.invocations >= MAX_INVOCATIONS:
            if fn:
                reason = ('recursive call' if name in self.active else
                          'call depth limit' if len(self.active) >= MAX_CALL_DEPTH else 'invocation budget')
                self.diagnostics.add(f'Python taint {reason} reached')
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
            return Flow(literal=node.value) if isinstance(node.value, (str, bool)) else Flow()
        if isinstance(node, ast.Name):
            return env.get(node.id, Flow())
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = self.resolve(dotted(node))
            if isinstance(node, ast.Subscript) and self.resolve(dotted(node.value)) == 'os.environ':
                key = node.slice.value if isinstance(node.slice, ast.Constant) else None
                return self.environment_source(node, key, 'os.environ')
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
        if isinstance(node, ast.Lambda):
            return Flow()
        if isinstance(node, ast.IfExp):
            known = self.truth(node.test, env)
            return self.expr(node.body if known else node.orelse, env) if known is not None else self.combine(
                [self.expr(node.body, env), self.expr(node.orelse, env)])
        if isinstance(node, ast.BoolOp):
            values = []
            known_prefix = True
            for expression in node.values:
                value = self.expr(expression, env)
                values.append(value)
                known = self.truth(expression, env)
                if known is not None and known == isinstance(node.op, ast.Or):
                    return value if known_prefix else self.combine(values)
                known_prefix = known_prefix and known is not None
            return values[-1] if known_prefix else self.combine(values)
        if isinstance(node, ast.Call):
            name = self.resolve(dotted(node.func))
            if name in {'os.getenv', 'os.environ.get'}:
                key_node = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg == 'key'), None)
                key = key_node.value if isinstance(key_node, ast.Constant) else None
                return self.environment_source(node, key, name)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'read', 'read_text', 'read_bytes'}:
                base = node.func.value
                if isinstance(base, ast.Call) and self.resolve(dotted(base.func)) in {'open', 'builtins.open', 'pathlib.Path'}:
                    path = base.args[0].value if base.args and isinstance(base.args[0], ast.Constant) else None
                    if isinstance(path, str) and CREDENTIAL_FILE.search(path.replace('\\', '/')):
                        return Flow(sources=(('credential-file', node.lineno),), trace=(('source', node.lineno, 'credential-file read'),))
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

    def environment_source(self, node, key, name):
        kind = 'sensitive-environment' if isinstance(key, str) and SENSITIVE_KEY.search(key) else 'untrusted-input'
        return Flow(sources=((kind, node.lineno),), trace=(('source', node.lineno, f'{name} ({kind})'),))

    def endpoint_host(self, arg, flow):
        address = flow.literal
        if not isinstance(address, str):
            prefix = arg
            while isinstance(prefix, ast.BinOp) and isinstance(prefix.op, ast.Add):
                prefix = prefix.left
            if isinstance(prefix, ast.JoinedStr) and prefix.values:
                prefix = prefix.values[0]
            address = prefix.value if isinstance(prefix, ast.Constant) and isinstance(prefix.value, str) else None
            # A dynamic suffix may change the hostname until the authority has ended.
            if not address or not re.match(r'^https?://[^/]+/', address, re.I):
                return None
        try:
            parsed = urlsplit(address)
            return parsed.hostname.lower() if parsed.hostname and parsed.scheme in {'http', 'https'} else None
        except ValueError:
            return None

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
        host = self.endpoint_host(arg, flow)
        payloads = [flow, *[self.expr(value, env) for value in node.args[index + 1:]]]
        payloads.extend(self.expr(keyword.value, env) for keyword in node.keywords
                        if keyword.arg in {'data', 'json', 'params', 'headers', 'cookies', 'body', 'auth', 'files'})
        sensitive = [value for value in payloads if any(kind in SENSITIVE_KINDS for kind, _ in value.sources)]
        if sensitive and not (host and any(host == domain or host.endswith('.' + domain) for domain in self.allowed)):
            self.emit('SENSITIVE_DATA_SEND', 'high' if host else 'medium', node,
                      f'Python AST: potentially sensitive data reaches {name}; destination {host or "unresolved"}; review authorization',
                      self.combine(sensitive))
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

    def truth(self, node, env):
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name) and env.get(node.id, Flow()).literal is not None:
            return bool(env[node.id].literal)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.truth(node.operand, env)
            return not value if value is not None else None
        if isinstance(node, ast.BoolOp):
            values = [self.truth(value, env) for value in node.values]
            absorbing = isinstance(node.op, ast.Or)
            if absorbing in values:
                return absorbing
            if all(value is not None for value in values):
                return not absorbing
        return None

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
                known = self.truth(node.test, env)
                if known is not None:
                    self.suite(node.body if known else node.orelse, env)
                    continue
                left, right = env.copy(), env.copy()
                self.suite(node.body, left)
                self.suite(node.orelse, right)
                for key in set(left) | set(right):
                    env[key] = left.get(key, Flow()).merge(right.get(key, Flow()))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                header = node.test if isinstance(node, ast.While) else node.iter
                self.inspect(header, env)
                if not isinstance(node, ast.While) or self.truth(node.test, env) is not False:
                    self.suite(node.body, env)
                self.suite(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self.inspect(item.context_expr, env)
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
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                self.inspect(value, env)
                known = self.truth(value, env)
                if known is not None and known == isinstance(node.op, ast.Or):
                    break
            return
        if isinstance(node, ast.IfExp):
            self.inspect(node.test, env)
            known = self.truth(node.test, env)
            for value in ([node.body] if known is True else [node.orelse] if known is False else [node.body, node.orelse]):
                self.inspect(value, env)
            return
        if isinstance(node, ast.Call):
            name = self.resolve(dotted(node.func))
            if name in self.functions:
                self.evaluate_function(name, node, env)
            else:
                self.call(node, env)
        for child in ast.iter_child_nodes(node):
            self.inspect(child, env)


def scan_python_taint(path: str, content: str, allowed_domains: list[str],
                      diagnostics: list[str] | None = None, *, tree: ast.Module | None = None) -> list[dict] | None:
    if Path(path).suffix.lower() != '.py':
        return []
    if tree is None:
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
    if diagnostics is not None:
        diagnostics.extend(sorted(analyzer.diagnostics))
    return analyzer.findings
