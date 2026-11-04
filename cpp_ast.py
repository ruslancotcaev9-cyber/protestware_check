"""Conservative C/C++ syntax-tree checks and bounded same-file call reachability.

Never compiles, loads, or executes the untrusted program. A reported path is a
*potential* path under a syntax-level geographic guard, not a proof of runtime
reachability. Virtual dispatch, function pointers, macros and cross-TU linking
are intentionally not resolved.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
from urllib.parse import urlsplit

C_CPP_GRAMMARS = {'.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp',
                  '.h': 'cpp', '.hh': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp'}

# Important: std::remove is an STL algorithm and is NOT a filesystem sink.
DELETE = re.compile(
    r'^(?:(?:std::)?filesystem::(?:remove|remove_all)|'
    r'(?:::)?(?:unlink|unlinkat|rmdir|remove)|'
    r'(?:DeleteFile|RemoveDirectory)(?:A|W)?)$'
)
WRITE = re.compile(
    r'^(?:(?:::)?(?:fopen|freopen|fwrite|rename)|'
    r'(?:std::)?filesystem::(?:rename|copy|copy_file)|'
    r'(?:WriteFile|MoveFile|CopyFile)(?:A|W)?)$'
)
NETWORK = re.compile(
    r'^(?:curl_easy_(?:perform|setopt)|curl_multi_perform|'
    r'(?:[A-Za-z_][\w:]*::)?(?:Get|Post|Send|Request)|'
    r'(?:[A-Za-z_][\w:]*\.)?(?:get|post|request))$'
)
PROCESS = re.compile(
    r'^(?:(?:std::)?system|(?:::)?(?:popen|execl|execv|execve|execvp|posix_spawn)|'
    r'CreateProcess(?:A|W)?|ShellExecute(?:A|W)?)$'
)
DYNAMIC = re.compile(r'^(?:dlopen|LoadLibrary(?:A|W)?|GetProcAddress)$')
GEO_KEY = re.compile(r'\b(?:geoip|geolocation|country(?:_?code)?|region|locale)\b', re.I)
GEO_VALUE = re.compile(r'''["'](?:RU|RUS|BY|BLR|Russia|Belarus)["']''', re.I)
URL = re.compile(r'https?://[^\s"\'<>`\\)]+', re.I)
IDENT = re.compile(r'^[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)*$')
MAX_NODES = 120000
MAX_CALL_DEPTH = 6
MAX_HELPER_EXPANSIONS = 150


def _nodes(node):
    return getattr(node, 'named_children', ())


def _field(node, name):
    return node.child_by_field_name(name) if hasattr(node, 'child_by_field_name') else None


def _line(node):
    return node.start_point[0] + 1


def _domain(value: str) -> str | None:
    try:
        parts = urlsplit(value.rstrip(';,}'))
        return parts.hostname.lower() if parts.scheme in {'https', 'http'} and parts.hostname else None
    except ValueError:
        return None


@dataclass(frozen=True)
class Function:
    name: str
    params: tuple[str, ...]
    body: object
    definition: object


class CppAnalyzer:
    def __init__(self, path: str, source: str, allow: list[str]):
        self.path = path
        self.raw_bytes = source.encode('utf-8')
        self.lines = source.splitlines()
        self.allow = allow
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int]] = set()
        self.count = 0
        self.function_index: dict[str, list[Function]] = defaultdict(list)
        self.expansions = 0
        self.max_nodes = MAX_NODES

    def raw(self, node) -> str:
        return self.raw_bytes[node.start_byte:node.end_byte].decode('utf-8', 'replace')

    def emit(self, rule: str, category: str, severity: str, node, message: str,
             geographic=None, route: tuple[tuple[str, int, str], ...] = ()):  # route is syntactic only
        line = _line(node)
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        entry = {'rule': rule, 'category': category, 'severity': severity,
                 'file': self.path, 'line': line,
                 'evidence': (self.lines[line - 1] if line <= len(self.lines) else '').strip()[:240],
                 'message': message, 'analysis': 'tree-sitter-cpp'}
        if geographic is not None:
            entry['dataflow'] = [
                {'file': self.path, 'line': _line(geographic),
                 'kind': 'condition', 'message': 'RU/BY geographic condition'},
                *({'file': self.path, 'line': ln, 'kind': kind, 'message': msg}
                  for kind, ln, msg in route),
                {'file': self.path, 'line': line, 'kind': 'sink', 'message': 'sensitive operation'},
            ]
            entry['reachability'] = {
                'scope': 'single-file', 'status': 'potentially-reachable',
                'call_depth': sum(kind == 'call' for kind, _, _ in route),
                'path_sensitive': False,
            }
        self.findings.append(entry)

    def _callee(self, node) -> str:
        callee = _field(node, 'function') or next(iter(_nodes(node)), None)
        if callee is None:
            return ''
        raw = self.raw(callee)
        # Strip only simple template instantiations; do not evaluate templates.
        raw = re.sub(r'<[^<>]{0,150}>', '', raw)
        return re.sub(r'\s+', '', raw)

    def _args(self, node):
        args = _field(node, 'arguments') or next((c for c in _nodes(node)
                             if c.type in {'argument_list', 'arguments'}), None)
        return list(_nodes(args)) if args is not None else []

    def _outside_domain(self, text):
        domains = set()
        for candidate in URL.findall(text):
            host = _domain(candidate)
            if host and not any(host == trusted or host.endswith('.' + trusted) for trusted in self.allow):
                domains.add(host)
        return sorted(domains)

    def _function_parts(self, definition) -> Function | None:
        body = _field(definition, 'body')
        dec = _field(definition, 'declarator')
        if body is None or dec is None:
            return None
        # Unwrap pointer/ref declarators and C/C++ function declarators.
        function_dec = dec
        for _ in range(8):
            if function_dec.type == 'function_declarator':
                break
            child = _field(function_dec, 'declarator')
            if child is None:
                child = next((n for n in _nodes(function_dec)
                              if n.type == 'function_declarator'), None)
            if child is None:
                return None
            function_dec = child
        if function_dec.type != 'function_declarator':
            return None
        name_node = _field(function_dec, 'declarator')
        if name_node is None:
            return None
        name = re.sub(r'\s+', '', self.raw(name_node))
        if not IDENT.fullmatch(name):
            return None  # operators, destructors, function pointers and computed calls
        params_node = _field(function_dec, 'parameters')
        if params_node is None:
            params_node = next((n for n in _nodes(function_dec)
                                if n.type == 'parameter_list'), None)
        params = []
        if params_node is not None:
            for p in _nodes(params_node):
                if p.type not in {'parameter_declaration', 'optional_parameter_declaration'}:
                    continue
                decl = _field(p, 'declarator')
                if decl is None:
                    params.append('')  # unnamed parameter still counts toward arity
                    continue
                name_text = self.raw(decl)
                found = re.findall(r'[A-Za-z_]\w*', name_text)
                params.append(found[-1] if found else '')
        return Function(name, tuple(params), body, definition)

    def index_functions(self, root):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'function_definition':
                definition = self._function_parts(node)
                if definition is not None:
                    self.function_index[definition.name].append(definition)
            stack.extend(reversed(_nodes(node)))

    def resolve(self, name: str, arity: int) -> Function | None:
        """Never guess among overloads or different namespaces with same basename."""
        if not IDENT.fullmatch(name):
            return None
        exact = [fn for fn in self.function_index.get(name, ()) if len(fn.params) == arity]
        if len(exact) == 1:
            return exact[0]
        if exact:
            return None
        basename = name.rsplit('::', 1)[-1]
        candidates = [fn for key, definitions in self.function_index.items()
                      if key.rsplit('::', 1)[-1] == basename
                      for fn in definitions if len(fn.params) == arity]
        return candidates[0] if len(candidates) == 1 else None

    def _is_geographic(self, condition, depth=0, active=frozenset()) -> bool:
        """Recognize direct comparison or bounded boolean helper returning it.

        Helper inspection is *not* program execution. An ambiguous helper name
        is never assumed to refer to a particular function.
        """
        if condition is None:
            return False
        text = self.raw(condition)
        if GEO_KEY.search(text) and GEO_VALUE.search(text):
            return True
        if depth >= 3:
            return False
        for node in self._contained_calls(condition):
            name = self._callee(node)
            fn = self.resolve(name, len(self._args(node)))
            if fn is None or fn.name in active:
                continue
            arguments = [self.raw(arg) for arg in self._args(node)]
            # Check *return expressions*, not unrelated literals/comments in helper.
            for ret in self._returns(fn.body):
                expression = self.raw(ret)
                if not GEO_VALUE.search(expression):
                    continue
                if not re.search(r'==|!=|\bstrcmp\s*\(|\.compare\s*\(', expression):
                    continue
                references_geo = bool(GEO_KEY.search(expression))
                references_passed_geo = any(
                    param and re.search(r'\b' + re.escape(param) + r'\b', expression)
                    and GEO_KEY.search(arguments[idx])
                    for idx, param in enumerate(fn.params) if idx < len(arguments)
                )
                if references_geo or references_passed_geo:
                    return True
        return False

    @staticmethod
    def _contained_calls(root):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'call_expression':
                yield node
            stack.extend(reversed(_nodes(node)))

    @staticmethod
    def _returns(root):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'return_statement':
                yield node
            # Do not inspect nested lambda body as the return of the enclosing helper.
            if node is not root and node.type in {'lambda_expression', 'function_definition'}:
                continue
            stack.extend(reversed(_nodes(node)))

    def check_call(self, node, geographic=None, route=()):
        callee = self._callee(node)
        args = self._args(node)
        if not callee:
            return
        if DELETE.fullmatch(callee):
            self.emit('CPP_FS_DELETE', 'filesystem', 'medium', node,
                      f'C/C++ potentially deletes files or directories: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ deletion potentially reachable under geographic condition', geographic, route)
        elif WRITE.fullmatch(callee):
            if callee in {'fopen', 'freopen'}:
                mode_index = 1 if callee == 'fopen' else 2
                if len(args) <= mode_index or not re.search(r'["\'][wax][+btxe]*["\']', self.raw(args[mode_index])):
                    return
            self.emit('CPP_FS_WRITE', 'filesystem', 'low', node,
                      f'C/C++ modifies a file or filesystem object: {callee}')
        if NETWORK.fullmatch(callee):
            if callee.split('::')[-1].split('.')[-1] in {
                    'Get', 'Post', 'Send', 'Request', 'get', 'post', 'request'}:
                if not re.search(r'(?:http|client|session|socket|asio|curl)', callee, re.I):
                    return
            self.emit('CPP_NETWORK', 'network', 'low', node,
                      f'C/C++ network-related API: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ network operation potentially reachable under geographic condition', geographic, route)
            hosts = self._outside_domain(' '.join(self.raw(arg)[:2048] for arg in args))
            if hosts:
                self.emit('CPP_NET_EXTERNAL', 'network', 'medium', node,
                          'C/C++ network call references non-allowlisted host(s): ' + ', '.join(hosts))
        if PROCESS.fullmatch(callee):
            self.emit('CPP_PROCESS', 'process', 'medium', node,
                      f'C/C++ process execution: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ process launch potentially reachable under geographic condition', geographic, route)
        if DYNAMIC.fullmatch(callee):
            self.emit('CPP_DYNAMIC_LOAD', 'obfuscation', 'low', node,
                      f'C/C++ dynamic code loading: {callee}')

    def check_stream(self, node):
        text = self.raw(node)
        if len(text) > 600:
            return
        if re.search(r'\b(?:std::)?(?:basic_ofstream|ofstream|fstream)\s*(?:<[^<>]{0,100}>)?\s+\w+\s*\(', text):
            self.emit('CPP_FS_WRITE', 'filesystem', 'low', node,
                      'C++ output stream may create or write a file')

    def walk(self, node, geographic=None, route=(), active=frozenset()):
        self.count += 1
        if self.count > self.max_nodes:
            raise ValueError(f'C/C++ AST node budget exceeded for {self.path}')
        if node.type == 'function_definition':
            fn = self._function_parts(node)
            # When scanning all definitions independently, maintain the active
            # function set so recursive calls cannot explode the analyzer.
            if fn is not None:
                self.walk(fn.body, geographic, route, active | {fn.name})
                return
        if node.type == 'if_statement':
            condition = _field(node, 'condition')
            consequence = _field(node, 'consequence')
            alternative = _field(node, 'alternative')
            node_children = list(_nodes(node))
            if condition is None and node_children:
                condition = node_children[0]
            geo = condition if condition is not None and self._is_geographic(condition) else None
            if geo is not None:
                self.emit('CPP_GEO_TARGET', 'geolocation', 'medium', node,
                          'C/C++ branch conditional on RU/BY-related geographic value')
            if condition is not None:
                self.walk(condition, geographic, route, active)
            if consequence is not None:
                self.walk(consequence, geo or geographic, route, active)
            if alternative is not None:
                self.walk(alternative, geo or geographic, route, active)
            handled = {(item.start_byte, item.end_byte) for item in (condition, consequence, alternative)
                       if item is not None}
            for child in node_children:
                if (child.start_byte, child.end_byte) not in handled:
                    self.walk(child, geographic, route, active)
            return
        if node.type == 'call_expression':
            self.check_call(node, geographic, route)
            # Only expand callees within a specific geo-conditioned call path.
            # All function definitions get their own ordinary scan independently.
            if geographic is not None and len(route) // 2 < MAX_CALL_DEPTH and self.expansions < MAX_HELPER_EXPANSIONS:
                callee = self._callee(node)
                args = self._args(node)
                fn = self.resolve(callee, len(args))
                if fn is not None and fn.name not in active:
                    self.expansions += 1
                    bridge = (
                        ('call', _line(node), f'call {callee}(' + ', '.join(self.raw(a)[:48] for a in args) + ')'),
                        ('function', _line(fn.definition), f'enter {fn.name}(' + ', '.join(fn.params) + ')'),
                    )
                    self.walk(fn.body, geographic, route + bridge, active | {fn.name})
        if node.type in {'declaration', 'field_declaration'}:
            self.check_stream(node)
        for child in _nodes(node):
            self.walk(child, geographic, route, active)


def scan_cpp(path: str, content: str, root, allowed_domains: list[str]) -> list[dict]:
    analyzer = CppAnalyzer(path, content, allowed_domains)
    analyzer.index_functions(root)
    analyzer.walk(root)
    return analyzer.findings
