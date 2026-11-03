"""Static syntax-tree based checks and bounded URL provenance tracking.

Input is parsed, never evaluated. Missing grammars produce explicit diagnostics.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import re

GRAMMARS = {'.go': 'go', '.cs': 'csharp', '.js': 'javascript', '.jsx': 'javascript',
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
SCOPES = {'function_declaration', 'function_definition', 'method_declaration',
          'function_expression', 'arrow_function', 'local_function_statement'}
STRING_NODES = {'string', 'string_literal', 'raw_string_literal', 'interpreted_string_literal',
                'verbatim_string_literal', 'string_value', 'single_quoted_string', 'double_quoted_string'}


@dataclass(frozen=True)
class Flow:
    sources: tuple[tuple[str, int], ...] = ()
    literal: str | None = None

    def merge(self, other: 'Flow') -> 'Flow':
        return Flow(tuple(sorted(set(self.sources + other.sources))),
                    self.literal if self.literal == other.literal else None)


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

    def raw(self, node) -> str:
        return self.bytes[node.start_byte:node.end_byte].decode('utf-8', 'replace')

    def emit(self, rule: str, category: str, severity: str, node, message: str) -> None:
        line = node.start_point[0] + 1
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        excerpt = self.lines[line - 1].strip()[:240] if line <= len(self.lines) else ''
        self.findings.append({'rule': rule, 'category': category, 'severity': severity,
                              'file': self.path, 'line': line, 'evidence': excerpt,
                              'message': message, 'analysis': 'tree-sitter-ast'})

    def value(self, node, state: dict[str, Flow], level: int = 0) -> Flow:
        if level > 40:
            return Flow()
        text = self.raw(node).strip()
        if node.type in STRING_NODES:
            return Flow(literal=literal(text))
        if node.type in {'identifier', 'name', 'simple_identifier', 'variable_name'}:
            return state.get(text, Flow())
        if node.type in SOURCE_NODES:
            origin = source_trace(text[:300], node.start_point[0] + 1)
            if origin:
                return Flow(origin)
        parts = [self.value(child, state, level + 1) for child in children(node)]
        sources = tuple(sorted(set(src for part in parts for src in part.sources)))
        if node.type in {'binary_expression', 'additive_expression', 'template_string',
                         'interpolated_string_expression'} and parts and all(p.literal is not None for p in parts):
            return Flow(sources, ''.join(p.literal or '' for p in parts))
        return Flow(sources, parts[0].literal if len(parts) == 1 else None)

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
        state[name] = flow

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
            self.emit('TAINT_URL', 'dataflow', risk, node, f'AST: URL depends on {detail}')
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
        if kind in CALL_NODES:
            self.sink(node, state, branch)
        for child in descendants:
            self.walk(child, state, branch, counter)


def _parser(language):
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError as exc:
        raise RuntimeError('install requirements-ast.txt') from exc
    try:
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
        analyzer = TreeAnalyzer(path, content, allow)
        analyzer.walk(tree.root_node, {})
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
                    return analyzer.findings, f'AST partial inline syntax: {path}: {diagnostic}'
                before = raw_data[:match.start(2)].count(b'\n')
                for entry in inner:
                    number = before + entry['line']
                    if 0 < number <= len(analyzer.lines):
                        analyzer.findings.append({**entry, 'file': path, 'line': number,
                                                  'evidence': analyzer.lines[number - 1].strip()[:240]})
        if tree.root_node.has_error:
            return analyzer.findings, f'AST partial syntax recovery: {path}'
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
