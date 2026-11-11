"""Resolve os deletion calls through file imports and lexical Go scopes only.

No target imports, builds or execution. Function-value aliases and cross-file
package declarations are deliberately outside this resolver.
"""

DELETIONS = {'Remove', 'RemoveAll'}
FUNCTIONS = {'function_declaration', 'method_declaration', 'func_literal'}
CONTROL = {'if_statement', 'for_statement', 'expression_switch_statement',
           'type_switch_statement', 'select_statement'}
CASES = {'expression_case', 'type_case', 'default_case', 'communication_case'}


def unquote(value):
    if value.startswith('`') and value.endswith('`'):
        return value[1:-1].replace('\r', '')
    if not value.startswith('"') or not value.endswith('"'):
        return ''
    text, result, index = value[1:-1], [], 0
    escapes = dict(zip('abfnrtv\\"', '\a\b\f\n\r\t\v\\"'))
    while index < len(text):
        char = text[index]
        index += 1
        if char == '\\':
            if index >= len(text):
                return ''
            char = text[index]
            index += 1
            if char in 'xuU':
                size = {'x': 2, 'u': 4, 'U': 8}[char]
                try:
                    char = chr(int(text[index:index + size], 16))
                except (ValueError, OverflowError):
                    return ''
                index += size
            elif char in '01234567':
                try:
                    char = chr(int(char + text[index:index + 2], 8))
                except ValueError:
                    return ''
                index += 2
            else:
                char = escapes.get(char, '')
        result.append(char)
    return ''.join(result)


class Resolver:
    def __init__(self, source):
        self.data = source.encode('utf-8')
        self.imports = {}
        self.dot_os = False
        self.other_dot = False
        self.calls = {}
        self.diagnostics = set()
        self.visits = 0

    def raw(self, node):
        return self.data[node.start_byte:node.end_byte].decode('utf-8', 'replace') if node is not None else ''

    def fields(self, node, field):
        return list(node.children_by_field_name(field))

    def names(self, nodes):
        return [self.raw(node) for node in nodes if node.type in {'identifier', 'type_identifier', 'package_identifier'}]

    def lookup(self, name, scopes):
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        if self.dot_os and name in DELETIONS:
            if self.other_dot:
                self.diagnostics.add('Go binding resolution: ambiguous dot imports')
                return None
            return 'os.' + name
        return None

    def deletion(self, call, scopes):
        function = call.child_by_field_name('function')
        while function is not None and function.type == 'parenthesized_expression' and function.named_child_count == 1:
            function = function.named_children[0]
        if function is None:
            return None
        if function.type == 'identifier':
            target = self.lookup(self.raw(function), scopes)
            return target if target in {'os.Remove', 'os.RemoveAll'} else None
        if function.type == 'selector_expression':
            operand = function.child_by_field_name('operand')
            name = self.raw(function.child_by_field_name('field'))
            if operand is not None and operand.type == 'identifier' and name in DELETIONS and self.lookup(self.raw(operand), scopes) == 'package:os':
                return 'os.' + name
        return None

    def walk(self, node, scopes, depth=0):
        self.visits += 1
        if self.visits > 120000 or depth > 300:
            raise ValueError('Go binding analysis budget exceeded')
        kind = node.type
        if kind in FUNCTIONS:
            scopes = [*scopes, {}]
            for field in ('receiver', 'parameters', 'result', 'type_parameters'):
                container = node.child_by_field_name(field)
                if container is not None:
                    for parameter in container.named_children:
                        for name in self.names(self.fields(parameter, 'name')):
                            scopes[-1][name] = None
            body = node.child_by_field_name('body')
            if body is not None:
                self.walk(body, scopes, depth + 1)
            return
        if kind == 'block' or kind in CONTROL | CASES:
            scopes = [*scopes, {}]
        if kind == 'type_switch_statement':
            alias = node.child_by_field_name('alias')
            if alias is not None:
                for name in self.names(alias.named_children):
                    scopes[-1][name] = None
        if kind in {'short_var_declaration', 'range_clause', 'receive_statement'}:
            right = node.child_by_field_name('right')
            if right is not None:
                self.walk(right, scopes, depth + 1)
            left = node.child_by_field_name('left')
            if left is not None and ':=' in self.data[left.end_byte:right.start_byte if right is not None else node.end_byte].decode('utf-8', 'replace'):
                for name in self.names(left.named_children):
                    scopes[-1][name] = None
            return
        if kind in {'var_spec', 'const_spec', 'type_spec', 'type_alias'}:
            value = node.child_by_field_name('value')
            if value is not None:
                self.walk(value, scopes, depth + 1)
            for name in self.names(self.fields(node, 'name')):
                scopes[-1][name] = None
            return
        if kind == 'call_expression':
            target = self.deletion(node, scopes)
            if target:
                self.calls[node.start_byte] = (node, target)
        for child in node.named_children:
            self.walk(child, scopes, depth + 1)

    def scan(self, root):
        # Imports are file scoped. Top-level declarations shadow unqualified names.
        for declaration in root.named_children:
            if declaration.type == 'import_declaration':
                todo = list(declaration.named_children)
                while todo:
                    node = todo.pop()
                    if node.type != 'import_spec':
                        todo.extend(node.named_children)
                        continue
                    path = unquote(self.raw(node.child_by_field_name('path')))
                    alias = self.raw(node.child_by_field_name('name'))
                    if alias == '.':
                        self.dot_os |= path == 'os'
                        self.other_dot |= path != 'os'
                    elif alias != '_':
                        self.imports[alias or path.rsplit('/', 1)[-1]] = 'package:os' if path == 'os' else None
        globals_ = {}
        for declaration in root.named_children:
            if declaration.type == 'function_declaration':
                globals_[self.raw(declaration.child_by_field_name('name'))] = None
            elif declaration.type in {'var_declaration', 'const_declaration', 'type_declaration'}:
                todo = list(declaration.named_children)
                while todo:
                    node = todo.pop()
                    if node.type in {'var_spec', 'const_spec', 'type_spec', 'type_alias'}:
                        globals_.update(dict.fromkeys(self.names(self.fields(node, 'name'))))
                    else:
                        todo.extend(node.named_children)
        self.walk(root, [self.imports, globals_])
        return self.calls, self.diagnostics


def resolve(source, root):
    return Resolver(source).scan(root)
