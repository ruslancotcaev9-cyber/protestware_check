"""Static syntax-tree based checks and bounded URL provenance tracking.

Input is parsed, never evaluated. Missing grammars produce explicit diagnostics.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import re

GRAMMARS = {'.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp',
            '.h': 'cpp', '.hh': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp',
            '.go': 'go', '.cs': 'csharp', '.js': 'javascript', '.jsx': 'javascript',
            '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript',
            '.tsx': 'tsx', '.sql': 'sql', '.html': 'html', '.htm': 'html',
            '.css': 'css', '.scss': 'scss', '.less': 'less'}
SUPPORTED = set(GRAMMARS) | {'.sass'}
SOURCE_RE = re.compile(r'\b(?:process\.env|os\.Getenv|os\.getenv|Environment\.GetEnvironmentVariable|'
                       r'location\.search|request\.query_params|req\.query|geoip\.lookup|navigator\.geolocation)\b', re.I)
NETWORK_RE = re.compile(r'^(?:fetch|axios(?:\.[\w]+)?|http\.(?:Get|Post|NewRequest)|'
                        r'[\w.]+\.(?:GetAsync|PostAsync|GetStringAsync|SendAsync)|'
                        r'requests\.(?:get|post|request)|httpx\.(?:get|post))\s*\(', re.I)
TARGET_RE = re.compile(r'\b(?:country|countryCode|country_code|geoip|region|locale)\b', re.I)
COUNTRY_RE = re.compile(r'''["'](?:RU|BY|RUS|BLR|Russia|Belarus)["']''', re.I)
URL_RE = re.compile(r'https?://[^\s\'"`<>)}]+', re.I)
VAR_RE = re.compile(r'(?:const|let|var|final|readonly)?\s*(?P<name>[\w$]+)\s*(?::=|=(?!=|>))\s*(?P<value>.+)', re.S)
SOURCE_NODES = {'call_expression', 'invocation_expression', 'member_expression',
                'selector_expression', 'member_access_expression', 'attribute', 'field_expression'}
CALL_NODES = {'call_expression', 'invocation_expression', 'call', 'function_call', 'method_invocation'}
ASSIGN_NODES = {'assignment_expression', 'assignment_statement', 'variable_declarator',
                'short_var_declaration', 'const_spec', 'var_spec', 'init_declarator'}
FUNCTION_DEFS = {'function_declaration', 'method_declaration', 'function_definition'}
SCOPES = {'function_declaration', 'function_definition', 'method_declaration',
          'function_expression', 'arrow_function', 'local_function_statement'}
STRING_NODES = {'string', 'string_literal', 'raw_string_literal', 'interpreted_string_literal',
                'verbatim_string_literal', 'string_value', 'single_quoted_string', 'double_quoted_string'}


@dataclass(frozen=True)
class Flow:
    sources: tuple[tuple[str, int], ...] = ()
    literal: str | None = None
    trace: tuple[tuple[str, int, str], ...] = ()

    def step(self, kind: str, line: int, message: str) -> 'Flow':
        if not self.sources:
            return self
        trace = (*self.trace, (kind, line, message[:120]))
        # Bound reports for generated code and deep wrappers. Preserve the source.
        if len(trace) > 24:
            trace = (trace[0], *trace[-23:])
        return Flow(self.sources, self.literal, trace)

    def merge(self, other: 'Flow') -> 'Flow':
        return Flow(tuple(sorted(set(self.sources + other.sources))),
                    self.literal if self.literal == other.literal else None,
                    self.trace if self.trace else other.trace)


def children(node):
    return list(getattr(node, 'named_children', ()))


def literal(text: str) -> str | None:
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0] and '${' not in text:
        return text[1:-1]
    return None


def hostname(value: str) -> str | None:
    try:
        url = urlsplit(value)
        if url.scheme in {'http', 'https'} and url.hostname:
            return url.hostname.lower()
    except ValueError:
        pass
    return None


def trusted(host: str, allow: list[str]) -> bool:
    return any(host == domain or host.endswith('.' + domain) for domain in allow)


def source_trace(expression: str, line: int) -> tuple[tuple[str, int], ...]:
    if not SOURCE_RE.search(expression):
        return ()
    label = 'geolocation' if re.search(r'geoip|geolocation', expression, re.I) else 'untrusted-input'
    return ((label, line),)


class TreeAnalyzer:
    def __init__(self, path: str, source: str, allow: list[str]):
        self.path, self.source, self.allow = path, source, allow
        self.bytes = source.encode('utf-8')
        self.lines = source.splitlines()
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int]] = set()
        self.budget = 120000
        self.functions = {}
        self.active = []
        self.returns = []
        self.invocations = 0
        self.diagnostics: set[str] = set()

    def raw(self, node) -> str:
        return self.bytes[node.start_byte:node.end_byte].decode('utf-8', 'replace')

    def emit(self, rule: str, category: str, severity: str, node, message: str, flow: Flow | None = None) -> None:
        line = node.start_point[0] + 1
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        excerpt = self.lines[line - 1].strip()[:240] if line <= len(self.lines) else ''
        entry = {'rule': rule, 'category': category, 'severity': severity,
                 'file': self.path, 'line': line, 'evidence': excerpt,
                 'message': message, 'analysis': 'tree-sitter-ast'}
        if flow and flow.sources:
            hops = flow.trace or (('source', flow.sources[0][1], flow.sources[0][0]),)
            entry['dataflow'] = [{'file': self.path, 'line': ln, 'kind': kind, 'message': msg}
                                 for kind, ln, msg in (*hops, ('sink', line, 'network URL'))]
        self.findings.append(entry)

    def index_functions(self, root):
        """Index named functions. Deliberately exclude computed/dynamic dispatch."""
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in FUNCTION_DEFS:
                field = node.child_by_field_name('name') if hasattr(node, 'child_by_field_name') else None
                if field is not None:
                    name = self.raw(field).strip()
                else:
                    text = self.raw(node)[:180]
                    m = re.search(r'\b(?:function|func)\s+([A-Za-z_$][\w$]*)\s*\(', text)
                    name = m.group(1) if m else ''
                if re.fullmatch(r'[A-Za-z_$][\w$]*', name):
                    self.functions.setdefault(name, node)
            stack.extend(reversed(children(node)))

    def function_parameters(self, fn):
        params = fn.child_by_field_name('parameters') if hasattr(fn, 'child_by_field_name') else None
        if params is None:
            params = next((c for c in children(fn) if c.type in {'formal_parameters', 'parameter_list'}), None)
        if params is None:
            return []
        names = []
        for part in children(params):
            if part.type in {'identifier', 'simple_identifier'}:
                names.append(self.raw(part))
                continue
            ident = part.child_by_field_name('name') if hasattr(part, 'child_by_field_name') else None
            if ident is None:
                todo = children(part)
                while todo and ident is None:
                    item = todo.pop(0)
                    if item.type in {'identifier', 'simple_identifier'}:
                        ident = item
                    else:
                        todo[0:0] = children(item)
            if ident is not None:
                names.append(self.raw(ident))
        return names[:20]

    def call_arguments(self, node):
        args = next((c for c in children(node) if c.type in {'arguments', 'argument_list'}), None)
        if args is None and hasattr(node, 'child_by_field_name'):
            args = node.child_by_field_name('arguments')
        return children(args) if args is not None else []

    def evaluate_function(self, name: str, call, state: dict[str, Flow]):
        args = [self.value(arg, state) for arg in self.call_arguments(call)]
        fn = self.functions.get(name)
        if fn is None or name in self.active or len(self.active) >= 6 or self.invocations >= 200:
            if fn is not None:
                reason = ('recursive call' if name in self.active else
                          'call depth limit' if len(self.active) >= 6 else 'invocation budget')
                self.diagnostics.add(f'Tree-sitter taint {reason} reached')
            return self.combine(args)
        self.invocations += 1
        names = self.function_parameters(fn)
        local = {p: (args[i] if i < len(args) else Flow()).step(
                    'call', call.start_point[0] + 1, f'call {name}').step(
                    'parameter', fn.start_point[0] + 1, f'{name} parameter {p}')
                 for i, p in enumerate(names)}
        body = fn.child_by_field_name('body') if hasattr(fn, 'child_by_field_name') else None
        if body is None:
            body = next((c for c in reversed(children(fn)) if c.type in {'block', 'statement_block', 'block_statement'}), None)
        if body is None:
            return self.combine(args)
        self.active.append(name)
        self.returns.append([])
        try:
            self.walk(body, local)
            results = self.returns[-1]
        finally:
            self.returns.pop()
            self.active.pop()
        result = results[0] if len(results) == 1 else self.combine(results)
        return result.step('call-result', call.start_point[0] + 1, f'{name} result')

    @staticmethod
    def combine(flows: list[Flow], literal: str | None = None) -> Flow:
        origin = tuple(sorted(set(src for f in flows for src in f.sources)))
        trace = next((f.trace for f in flows if f.sources and f.trace), ())
        return Flow(origin, literal, trace)

    def value(self, node, state: dict[str, Flow], level: int = 0) -> Flow:
        if level > 40:
            self.diagnostics.add('Tree-sitter taint expression depth limit reached')
            return Flow()
        text = self.raw(node).strip()
        if node.type in STRING_NODES:
            return Flow(literal=literal(text))
        if node.type in {'identifier', 'name', 'simple_identifier', 'variable_name'}:
            return state.get(text, Flow())
        if node.type in CALL_NODES:
            call_text = text[:160]
            m = re.match(r'^([A-Za-z_$][\w$]*)\s*\(', call_text)
            if m and m.group(1) in self.functions:
                return self.evaluate_function(m.group(1), node, state)
        if node.type in SOURCE_NODES:
            origin = source_trace(text[:300], node.start_point[0] + 1)
            if origin:
                return Flow(origin, trace=(('source', node.start_point[0] + 1, text[:120]),))
        parts = [self.value(child, state, level + 1) for child in children(node)]
        sources = tuple(sorted(set(src for part in parts for src in part.sources)))
        if node.type in {'binary_expression', 'additive_expression', 'template_string',
                         'interpolated_string_expression'} and parts and all(p.literal is not None for p in parts):
            return self.combine(parts, ''.join(p.literal or '' for p in parts))
        return self.combine(parts, parts[0].literal if len(parts) == 1 else None)

    def assignment(self, node, state: dict[str, Flow]):
        raw = self.raw(node)
        match = VAR_RE.search(raw)
        if not match:
            return
        name = match.group('name')
        rhs = node.start_byte + len(raw[:match.start('value')].encode('utf-8'))
        elements = [n for n in children(node) if n.end_byte > rhs]
        if elements:
            flow = self.value(elements[-1], state)
        else:
            value = match.group('value').strip().rstrip(';')
            flow = Flow(source_trace(value, node.start_point[0] + 1), literal(value))
            if value in state:
                flow = state[value]
        state[name] = flow.step('assignment', node.start_point[0] + 1, name)

    def sink(self, node, state: dict[str, Flow], branch: bool):
        text = self.raw(node).strip()
        if not NETWORK_RE.match(re.sub(r'^(?:await|return)\s+', '', text)):
            return
        args = [n for n in children(node) if 'argument' in n.type]
        if args:
            args = children(args[0]) or args
        else:
            args = children(node)[1:]
        if not args:
            return
        flow = self.value(args[0], state)
        if flow.sources:
            detail = ', '.join(f'{source}@{line}' for source, line in flow.sources[:5])
            risk = 'high' if branch and any(source == 'geolocation' for source, _ in flow.sources) else 'medium'
            self.emit('TAINT_URL', 'dataflow', risk, node, f'AST: URL depends on {detail}', flow)
        elif flow.literal:
            host = hostname(flow.literal)
            if host and not trusted(host, self.allow):
                self.emit('AST_NET_EXTERNAL', 'network', 'medium', node, f'AST: endpoint {host}')
        else:
            self.emit('AST_NET_DYNAMIC', 'network', 'low', node, 'AST: URL source unresolved')

    def markup(self, node):
        kind, text = node.type, self.raw(node)
        ext = Path(self.path).suffix.lower()
        if ext in {'.html', '.htm'} and kind in {'start_tag', 'self_closing_tag'}:
            if not re.match(r'<\s*(?:script|iframe|link|img|source)\b', text, re.I):
                return
            match = re.search(r'''\b(?:src|href)\s*=\s*(["'])(.*?)\1''', text, re.I | re.S)
            if match:
                host = hostname(match.group(2))
                if host and not trusted(host, self.allow):
                    self.emit('AST_HTML_EXTERNAL', 'network', 'medium', node, f'HTML AST resource {host}')
                elif re.search(r'\{\{|\$\{|<%', match.group(2)):
                    self.emit('AST_HTML_DYNAMIC_URL', 'network', 'low', node, 'HTML AST template URL')
        if ext in {'.css', '.scss', '.less'} and kind in {'declaration', 'property_statement', 'import_statement', 'at_rule', 'function_value', 'call_expression'}:
            if not re.search(r'(?:\burl\s*\(|^\s*@(?:import|use|forward)\b)', text, re.I):
                return
            found = URL_RE.search(text)
            host = hostname(found.group()) if found else None
            if host and not trusted(host, self.allow):
                self.emit('AST_STYLE_EXTERNAL', 'network', 'low', node, f'Style AST resource {host}')
            elif re.search(r'(?:\$[\w-]+|@[\w-]+|\bvar\s*\(|#\{|\$\{)', text):
                self.emit('AST_STYLE_DYNAMIC_URL', 'network', 'low', node, 'Style AST dynamic resource')
        if ext == '.sql' and kind in {'drop_statement', 'delete_statement', 'truncate_statement', 'update_statement',
                                       'statement', 'command', 'ddl_statement', 'dml_statement'}:
            if re.match(r'\s*(?:DROP|TRUNCATE)\s+', text, re.I):
                self.emit('AST_SQL_DESTRUCTIVE', 'database', 'medium', node, 'SQL AST destructive statement')
            elif re.match(r'\s*(?:DELETE\s+FROM|UPDATE\s+\S+\s+SET)\b', text, re.I):
                self.emit('AST_SQL_MODIFY', 'database', 'low', node, 'SQL AST modifying statement')

    def walk(self, node, state: dict[str, Flow], branch=False, counter=None):
        if counter is None:
            counter = [0]
        counter[0] += 1
        if counter[0] > self.budget:
            raise ValueError('AST node budget exceeded')
        kind = node.type
        if kind in SCOPES:
            state = dict(state)
        self.markup(node)
        descendants = children(node)
        if kind in {'if_statement', 'if_expression', 'conditional_expression'} and descendants:
            condition = descendants[0]
            geo = bool(TARGET_RE.search(self.raw(condition)) and COUNTRY_RE.search(self.raw(condition)))
            if geo:
                self.emit('AST_GEO_TARGET', 'geolocation', 'medium', node, 'AST geographic condition')
            self.walk(condition, state, branch, counter)
            copies = []
            for child in descendants[1:]:
                local = dict(state)
                self.walk(child, local, branch or geo, counter)
                copies.append(local)
            for local in copies:
                for key, val in local.items():
                    state[key] = state[key].merge(val) if key in state else val
            return
        if kind in ASSIGN_NODES:
            self.assignment(node, state)
        if kind in {'return_statement'} and self.returns and descendants:
            result = self.value(descendants[0], state).step('return', node.start_point[0] + 1, 'return value')
            self.returns[-1].append(result)
        if kind in CALL_NODES:
            self.sink(node, state, branch)
            call_text = self.raw(node).strip()[:160]
            m = re.match(r'^([A-Za-z_$][\w$]*)\s*\(', call_text)
            if m and m.group(1) in self.functions:
                self.evaluate_function(m.group(1), node, state)
        for child in descendants:
            self.walk(child, state, branch, counter)


def _parser(language):
    try:
        from tree_sitter_language_pack import get_parser, downloaded_languages
    except ImportError as exc:
        raise RuntimeError('install requirements-ast.txt') from exc
    try:
        if language not in downloaded_languages():
            raise RuntimeError(f"grammar {language} is not cached; prefetch it before scanning")
        return get_parser(language)
    except Exception as exc:
        raise RuntimeError(f'grammar {language}: {type(exc).__name__}: {exc}') from exc


def scan_tree(path, content, allow):
    ext = Path(path).suffix.lower()
    if ext == '.sass':
        return scan_sass(path, content, allow), None
    if ext not in GRAMMARS:
        return [], None
    try:
        tree = _parser(GRAMMARS[ext]).parse(content.encode('utf-8'))
        if tree is None:
            return [], f'AST parser returned no tree for {path}'
        if ext in {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx'}:
            from cpp_ast import scan_cpp
            diagnostics = []
            cpp_findings = scan_cpp(path, content, tree.root_node, allow, diagnostics)
            if tree.root_node.has_error and not diagnostics:
                return cpp_findings, f'AST partial syntax recovery: {path}'
            if tree.root_node.has_error:
                diagnostics.append('syntax recovery')
            diag = f"AST partial analysis: {path}: {'; '.join(diagnostics)}" if diagnostics else None
            return cpp_findings, diag
        analyzer = TreeAnalyzer(path, content, allow)
        analyzer.index_functions(tree.root_node)
        analyzer.walk(tree.root_node, {})
        if ext in {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'}:
            from js_behavior import scan_js_behavior
            diagnostics = []
            analyzer.findings.extend(scan_js_behavior(path, content, tree.root_node, diagnostics))
            analyzer.diagnostics.update(diagnostics)
        if ext in {'.html', '.htm'}:
            # Embedded languages have their own syntax trees; byte offsets matter for Unicode.
            raw_data = content.encode('utf-8')
            for match in re.finditer(rb'<(script|style)\b[^>]*>(.*?)</\1\s*>', raw_data, re.I | re.S):
                body = match.group(2).decode('utf-8', errors='replace')
                if not body.strip():
                    continue
                subpath = 'inline.' + ('js' if match.group(1).lower() == b'script' else 'css')
                inner, diagnostic = scan_tree(subpath, body, allow)
                if diagnostic:
                    analyzer.diagnostics.add(f'inline analysis: {diagnostic}')
                before = raw_data[:match.start(2)].count(b'\n')
                for entry in inner:
                    number = before + entry['line']
                    if 0 < number <= len(analyzer.lines):
                        analyzer.findings.append({**entry, 'file': path, 'line': number,
                                                  'evidence': analyzer.lines[number - 1].strip()[:240]})
        if tree.root_node.has_error and not analyzer.diagnostics:
            return analyzer.findings, f'AST partial syntax recovery: {path}'
        if tree.root_node.has_error:
            analyzer.diagnostics.add('syntax recovery')
        if analyzer.diagnostics:
            return analyzer.findings, f"AST partial analysis: {path}: {'; '.join(sorted(analyzer.diagnostics))}"
        return analyzer.findings, None
    except (ValueError, RuntimeError, OSError) as exc:
        return [], f'AST unavailable: {path}: {exc}'


@dataclass
class SassBlock:
    indent: int
    line: int
    text: str
    parent: 'SassBlock | None' = None


def parse_sass(source):
    output, stack = [], []
    for index, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(('//', '/*', '*')):
            continue
        indent = len(line) - len(line.lstrip(' \t'))
        while stack and stack[-1].indent >= indent:
            stack.pop()
        node = SassBlock(indent, index, stripped, stack[-1] if stack else None)
        output.append(node)
        stack.append(node)
    return output


def scan_sass(path, source, allow):
    result = []
    for node in parse_sass(source):
        if not re.search(r'(?:\burl\s*\(|^@(?:import|use|forward)\b)', node.text, re.I):
            continue
        found = URL_RE.search(node.text)
        host = hostname(found.group()) if found else None
        if host and not trusted(host, allow):
            result.append({'rule': 'AST_STYLE_EXTERNAL', 'category': 'network', 'severity': 'low',
                           'file': path, 'line': node.line, 'evidence': node.text[:240],
                           'message': f'Sass syntax-tree remote resource {host}',
                           'analysis': 'sass-indentation-ast'})
    return result
