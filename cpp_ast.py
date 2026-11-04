"""C/C++ Tree-sitter behavior checks. Never compile or execute untrusted code.

Checks operate on syntax nodes (not loose text) and only raise geography/action
correlation when a sensitive call belongs to a geographic conditional branch.
"""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit

C_CPP_GRAMMARS = {'.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp',
                  '.h': 'cpp', '.hh': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp'}

# Conservative named APIs. std::remove is omitted (algorithm::remove does NOT
# delete filesystem entries); system/process execution is a separate category.
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
URL = re.compile(r'https?://[^\s\"\'<>`\\)]+', re.I)


def _nodes(node):
    return getattr(node, 'named_children', ())


def _domain(value: str) -> str | None:
    try:
        parts = urlsplit(value.rstrip(';,}'))
        return parts.hostname.lower() if parts.scheme in {'https', 'http'} and parts.hostname else None
    except ValueError:
        return None


class CppAnalyzer:
    def __init__(self, path: str, source: str, allow: list[str]):
        self.path = path
        self.raw_bytes = source.encode('utf-8')
        self.lines = source.splitlines()
        self.allow = allow
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int]] = set()
        self.max_nodes = 120000
        self.count = 0

    def raw(self, node):
        return self.raw_bytes[node.start_byte:node.end_byte].decode('utf-8', 'replace')

    def emit(self, rule: str, category: str, severity: str, node, message: str,
             geographic=None):
        line = node.start_point[0] + 1
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        entry = {'rule': rule, 'category': category, 'severity': severity,
                 'file': self.path, 'line': line,
                 'evidence': (self.lines[line - 1] if line <= len(self.lines) else '').strip()[:240],
                 'message': message, 'analysis': 'tree-sitter-cpp'}
        if geographic is not None:
            entry['dataflow'] = [
                {'file': self.path, 'line': geographic.start_point[0] + 1,
                 'kind': 'condition', 'message': 'geographic condition'},
                {'file': self.path, 'line': line, 'kind': 'sink', 'message': 'sensitive operation'},
            ]
        self.findings.append(entry)

    def _is_geographic(self, condition):
        text = self.raw(condition)
        return bool(GEO_KEY.search(text) and GEO_VALUE.search(text))

    def _callee(self, node) -> str:
        callee = node.child_by_field_name('function') if hasattr(node, 'child_by_field_name') else None
        if callee is None:
            callee = next(iter(_nodes(node)), None)
        if callee is None:
            return ''
        raw = self.raw(callee)
        # C++ templates are deliberately not evaluated; strip simple template arguments.
        raw = re.sub(r'<[^<>]{0,150}>', '', raw)
        return re.sub(r'\s+', '', raw)

    def _args(self, node):
        args = node.child_by_field_name('arguments') if hasattr(node, 'child_by_field_name') else None
        if args is None:
            args = next((c for c in _nodes(node) if c.type in {'argument_list', 'arguments'}), None)
        return list(_nodes(args)) if args is not None else []

    def _outside_domain(self, text):
        domains = set()
        for candidate in URL.findall(text):
            host = _domain(candidate)
            if host and not any(host == trusted or host.endswith('.' + trusted) for trusted in self.allow):
                domains.add(host)
        return sorted(domains)

    def check_call(self, node, geographic=None):
        callee = self._callee(node)
        args = self._args(node)
        if not callee:
            return
        if DELETE.fullmatch(callee):
            self.emit('CPP_FS_DELETE', 'filesystem', 'medium', node,
                      f'C/C++ potentially deletes files or directories: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ destructive filesystem operation under a geographic condition', geographic)
        elif WRITE.fullmatch(callee):
            if callee in {'fopen', 'freopen'}:
                mode_index = 1 if callee == 'fopen' else 2
                if len(args) <= mode_index or not re.search(r'["\'][wax][+btxe]*["\']', self.raw(args[mode_index])):
                    return
            self.emit('CPP_FS_WRITE', 'filesystem', 'low', node,
                      f'C/C++ modifies a file or filesystem object: {callee}')
        if NETWORK.fullmatch(callee):
            # Generic .Get() / ::Get() are common collection APIs, not reliable
            # network sinks.  Require a network-related receiver when relevant.
            if callee.split('::')[-1].split('.')[-1] in {
                    'Get', 'Post', 'Send', 'Request', 'get', 'post', 'request'}:
                if not re.search(r'(?:http|client|session|socket|asio|curl)', callee, re.I):
                    return
            self.emit('CPP_NETWORK', 'network', 'low', node,
                      f'C/C++ network-related API: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ network operation under a geographic condition', geographic)
            hosts = self._outside_domain(' '.join(self.raw(arg)[:2048] for arg in args))
            if hosts:
                self.emit('CPP_NET_EXTERNAL', 'network', 'medium', node,
                          'C/C++ network call references non-allowlisted host(s): ' + ', '.join(hosts))
        if PROCESS.fullmatch(callee):
            self.emit('CPP_PROCESS', 'process', 'medium', node,
                      f'C/C++ process execution: {callee}')
            if geographic is not None:
                self.emit('CPP_GEO_ACTION', 'correlation', 'high', node,
                          'C/C++ process launch under a geographic condition', geographic)
        if DYNAMIC.fullmatch(callee):
            self.emit('CPP_DYNAMIC_LOAD', 'obfuscation', 'low', node,
                      f'C/C++ dynamic code loading: {callee}')

    def check_stream(self, node):
        # Class instantiation is not a call_expression in the C++ grammar.
        text = self.raw(node)
        if len(text) > 600:
            return
        if re.search(r'\b(?:std::)?(?:basic_ofstream|ofstream|fstream)\s*(?:<[^<>]{0,100}>)?\s+\w+\s*\(', text):
            self.emit('CPP_FS_WRITE', 'filesystem', 'low', node,
                      'C++ output stream may create or write a file')

    def walk(self, node, geographic=None):
        self.count += 1
        if self.count > self.max_nodes:
            raise ValueError(f'C/C++ AST node budget exceeded for {self.path}')
        if node.type == 'if_statement':
            condition = node.child_by_field_name('condition') if hasattr(node, 'child_by_field_name') else None
            consequence = node.child_by_field_name('consequence') if hasattr(node, 'child_by_field_name') else None
            alternative = node.child_by_field_name('alternative') if hasattr(node, 'child_by_field_name') else None
            node_children = list(_nodes(node))
            if condition is None and node_children:
                condition = node_children[0]
            geo = condition if condition is not None and self._is_geographic(condition) else None
            if geo is not None:
                self.emit('CPP_GEO_TARGET', 'geolocation', 'medium', node,
                          'C/C++ branch conditions behavior on RU/BY-related geographic value')
            if condition is not None:
                self.walk(condition, geographic)
            if consequence is not None:
                self.walk(consequence, geo or geographic)
            if alternative is not None:
                self.walk(alternative, geo or geographic)
            handled = {(item.start_byte, item.end_byte) for item in (condition, consequence, alternative)
                       if item is not None}
            for child in node_children:
                if (child.start_byte, child.end_byte) not in handled:
                    self.walk(child, geographic)
            return
        if node.type == 'call_expression':
            self.check_call(node, geographic)
        if node.type in {'declaration', 'field_declaration'}:
            self.check_stream(node)
        for child in _nodes(node):
            self.walk(child, geographic)


def scan_cpp(path: str, content: str, root, allowed_domains: list[str]) -> list[dict]:
    analyzer = CppAnalyzer(path, content, allowed_domains)
    analyzer.walk(root)
    return analyzer.findings
