"""JavaScript/TypeScript AST-based suspicious flood and layered obfuscation signals.

Only inspects parsed syntax and finite local call graphs. No execution, no requests.
Obfuscation is a review indicator, not proof of malware.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

JS_EXTENSIONS = {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'}
CALL_TYPES = {'call_expression', 'optional_call_expression'}
FUNCTION_TYPES = {'function_declaration', 'generator_function_declaration',
                  'function_expression', 'arrow_function', 'method_definition'}
DIRECT_NETWORK = re.compile(
    r'^(?:fetch|(?:window|globalThis)\.fetch|axios(?:\.[A-Za-z]+)?|got(?:\.[A-Za-z]+)?|'
    r'\w+\.(?:fetch|request|post|get))$'
)
UNBOUNDED = re.compile(r'^\s*(?:while\s*\(\s*(?:true|1|!\s*0)\s*\)|for\s*\(\s*;\s*;)', re.I)
# Non-greedy bounded matching is essential on long obfuscated JS source lines.
TABLE = re.compile(r'''["'][^"'\r\n]{200,}["']\s*\.split\s*\(\s*["'][;|]["']\s*\)''')
ROTATE = re.compile(r'\b([A-Za-z_$][\w$]*)\.push\s*\(\s*\1\.shift\s*\(\s*\)\s*\)')
HEX_INDEX = re.compile(r'''\b[A-Za-z_$][\w$]*\s*\(\s*["']0x[0-9a-f]{1,5}["']\s*\)''', re.I)
DYNAMIC_CODE = re.compile(r'\b(?:eval|Function)\s*\(')


def walk_nodes(root, limit=120000):
    stack = [root]
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > limit:
            raise ValueError('JS AST node budget exceeded')
        yield node
        stack.extend(reversed(getattr(node, 'named_children', ())))


@dataclass
class FunctionInfo:
    name: str
    node: object
    body: object


class BehaviorAnalyzer:
    def __init__(self, path: str, content: str):
        self.path, self.content = path, content
        self.source = content.encode('utf-8')
        self.lines = content.splitlines()
        self.functions: dict[str, FunctionInfo] = {}
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int]] = set()

    def raw(self, node):
        return self.source[node.start_byte:node.end_byte].decode('utf-8', 'replace')

    def _body(self, node):
        body = node.child_by_field_name('body') if hasattr(node, 'child_by_field_name') else None
        if body is None:
            body = next((c for c in reversed(node.named_children)
                         if c.type in {'statement_block', 'block', 'expression_statement'}), None)
        return body

    def index(self, root):
        for node in walk_nodes(root):
            if node.type not in FUNCTION_TYPES and node.type != 'variable_declarator':
                continue
            if node.type == 'variable_declarator':
                name = node.child_by_field_name('name')
                value = node.child_by_field_name('value')
                if name is None or value is None or value.type not in FUNCTION_TYPES:
                    continue
                fn = value
            else:
                fn = node
                name = node.child_by_field_name('name')
            if name is not None:
                label = self.raw(name)
                body = self._body(fn)
                if re.fullmatch(r'[A-Za-z_$][\w$]*', label) and body is not None:
                    self.functions.setdefault(label, FunctionInfo(label, fn, body))

    def emit(self, rule, severity, node, message, trace=None):
        line = node.start_point[0] + 1
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        finding = {'rule': rule, 'category': 'network' if rule.startswith('NETWORK_') else 'obfuscation',
                   'severity': severity, 'file': self.path, 'line': line,
                   'evidence': (self.lines[line - 1] if line <= len(self.lines) else '').strip()[:240],
                   'message': message, 'analysis': 'tree-sitter-js-behavior'}
        if trace:
            finding['dataflow'] = [{'file': self.path, 'line': line, 'kind': kind, 'message': desc}
                                   for line, kind, desc in trace]
        self.findings.append(finding)

    def _callee(self, node):
        field = node.child_by_field_name('function') if hasattr(node, 'child_by_field_name') else None
        if field is None:
            field = next(iter(node.named_children), None)
        return self.raw(field).strip() if field is not None else ''

    def network_path(self, body, stack=None, budget=80000):
        """Return a short call path to a real network sink (not arbitrary text)."""
        active = set(stack or ())
        todo = [body]
        count = 0
        while todo:
            node = todo.pop()
            count += 1
            if count > budget:
                return None
            if node is not body and node.type in FUNCTION_TYPES:
                continue  # function declarations are not executed when merely encountered
            if node.type in CALL_TYPES:
                callee = self._callee(node)
                if DIRECT_NETWORK.fullmatch(callee):
                    return [(node.start_point[0] + 1, 'sink', f'network call {callee}')]
                if callee in self.functions and callee not in active and len(active) < 6:
                    other = self.functions[callee]
                    path = self.network_path(other.body, active | {callee}, budget=max(200, budget // 2))
                    if path:
                        return [(node.start_point[0] + 1, 'call', f'call {callee}'), *path]
            todo.extend(reversed(node.named_children))
        return None

    def _is_unbounded(self, node):
        if node.type not in {'while_statement', 'for_statement', 'do_statement'}:
            return False
        # Parse node is a loop; prefix only decides whether its guard is constant.
        return bool(UNBOUNDED.match(self.raw(node)[:90]))

    def scan_flood(self, root):
        for node in walk_nodes(root):
            if not self._is_unbounded(node):
                continue
            body = node.child_by_field_name('body') if hasattr(node, 'child_by_field_name') else None
            if body is None:
                body = next((c for c in reversed(node.named_children) if c.type in {'statement_block', 'block'}), None)
            if body is None:
                continue
            trace = self.network_path(body)
            if trace:
                start = node.start_point[0] + 1
                self.emit('NETWORK_FLOOD', 'high', node,
                          'Unbounded JavaScript/TypeScript loop invokes network requests (possibly via helper); review DoS risk',
                          [(start, 'loop', 'unbounded loop'), *trace])

    def scan_obfuscation(self, root):
        # Only infer layering if multiple independent mechanisms coexist.
        # Parse comments as comments rather than trusting text within comments.
        from language_analysis import mask_comments
        cleaned = mask_comments(self.content, '.js')
        table = bool(TABLE.search(cleaned))
        rotate = bool(ROTATE.search(cleaned))
        hex_refs = len(HEX_INDEX.findall(cleaned[:300000])) >= 6
        single_line = len(self.content) > 3000 and max((len(s) for s in self.lines), default=0) > 3000
        dynamic = bool(DYNAMIC_CODE.search(cleaned))
        signals = [label for label, yes in (('large string table', table),
                                            ('array rotation', rotate),
                                            ('hex-index decoder', hex_refs),
                                            ('single-line density', single_line)) if yes]
        if not ((table and (hex_refs or rotate)) or len(signals) >= 3):
            return
        # Must contain parsed code, not just a single suspicious comment string.
        if not any(n.type in CALL_TYPES for n in walk_nodes(root)):
            return
        risk = 'high' if dynamic and table and hex_refs else 'medium'
        self.emit('OBFUSCATED_JS', risk, root,
                  'Layered JS/TS obfuscation indicators: ' + ', '.join(signals) +
                  '; obfuscation is not proof of malware')


def scan_js_behavior(path: str, content: str, root):
    scanner = BehaviorAnalyzer(path, content)
    scanner.index(root)
    scanner.scan_flood(root)
    scanner.scan_obfuscation(root)
    return scanner.findings
