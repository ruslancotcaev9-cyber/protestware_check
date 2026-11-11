"""Bounded file-local Node filesystem binding analysis. Never executes source."""
from dataclasses import dataclass
import re

FS, PROMISES, UNKNOWN = 'node:fs', 'node:fs/promises', frozenset({''})
METHODS = {'rm', 'rmSync', 'unlink', 'unlinkSync', 'rmdir', 'rmdirSync'}
PROMISE_METHODS = {'rm', 'unlink', 'rmdir'}
FUNCTIONS = {'function_declaration', 'generator_function_declaration', 'function_expression',
             'generator_function', 'arrow_function', 'method_definition'}
DELETIONS = {FS + '.' + name for name in METHODS} | {PROMISES + '.' + name for name in PROMISE_METHODS}


def string(text):
    if len(text) < 2 or text[0] not in "'\"`" or text[-1] != text[0] or (text[0] == '`' and '${' in text):
        return None
    result, index, text = [], 0, text[1:-1]
    escapes = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f', 'v': '\v', '0': '\0'}
    while index < len(text):
        char = text[index]; index += 1
        if char == '\\':
            if index >= len(text):
                return None
            char = text[index]; index += 1
            if char in {'x', 'u'}:
                size = 2 if char == 'x' else 4
                if char == 'u' and index < len(text) and text[index] == '{':
                    end = text.find('}', index + 1)
                    if end < 0:
                        return None
                    digits = text[index + 1:end]; index = end + 1
                else:
                    digits = text[index:index + size]; index += size
                try:
                    char = chr(int(digits, 16))
                except (ValueError, OverflowError):
                    return None
            else:
                char = escapes.get(char, char)
        result.append(char)
    return ''.join(result)


@dataclass
class State:
    scopes: list
    function: int = 0
    modified: set | None = None

    def __post_init__(self):
        if self.modified is None:
            self.modified = set()

    def copy(self):
        return State([dict(scope) for scope in self.scopes], self.function, set(self.modified))


class Resolver:
    def __init__(self, source):
        self.data = source.encode('utf-8')
        self.calls = {}
        self.visits = 0
        self.diagnostics = set()

    def raw(self, node):
        return self.data[node.start_byte:node.end_byte].decode('utf-8', 'replace') if node is not None else ''

    def lookup(self, name, state):
        return next((scope[name] for scope in reversed(state.scopes) if name in scope), UNKNOWN)

    def property(self, values, key, state):
        results = set()
        for value in values:
            target = (PROMISES if value == FS and key == 'promises' else
                      value + '.' + key if (value == FS and key in METHODS) or (value == PROMISES and key in PROMISE_METHODS) else '')
            if target and any(target == prefix or target.startswith(prefix + '.') for prefix in state.modified):
                target = ''
            results.add(target)
        return frozenset(results) or UNKNOWN

    def value(self, node, state, depth=0):
        if depth > 30:
            self.diagnostics.add('JS filesystem value depth limit reached')
            return UNKNOWN
        if node is None:
            return UNKNOWN
        kind = node.type
        if kind in {'identifier', 'shorthand_property_identifier_pattern'}:
            return self.lookup(self.raw(node), state)
        if kind in {'parenthesized_expression', 'await_expression', 'as_expression', 'satisfies_expression', 'non_null_expression', 'type_assertion'}:
            parts = node.named_children
            return self.value(parts[-1] if kind == 'type_assertion' else parts[0], state, depth + 1) if parts else UNKNOWN
        if kind in {'member_expression', 'subscript_expression'}:
            key = (self.raw(node.child_by_field_name('property')) if kind == 'member_expression' else
                   string(self.raw(node.child_by_field_name('index'))))
            return self.property(self.value(node.child_by_field_name('object'), state, depth + 1), key, state) if key else UNKNOWN
        if kind == 'call_expression':
            function, arguments = node.child_by_field_name('function'), node.child_by_field_name('arguments')
            if self.value(function, state, depth + 1) == frozenset({'global:require'}) and arguments is not None:
                args = arguments.named_children
                module = string(self.raw(args[0])) if len(args) == 1 else None
                if module in {'fs', 'node:fs'}:
                    return frozenset({FS})
                if module in {'fs/promises', 'node:fs/promises'}:
                    return frozenset({PROMISES})
        if kind == 'ternary_expression':
            return self.value(node.child_by_field_name('consequence'), state, depth + 1) | self.value(node.child_by_field_name('alternative'), state, depth + 1)
        return UNKNOWN

    def bind(self, node, values, state, scope=None):
        if node is None:
            return
        kind = node.type
        if kind in {'identifier', 'shorthand_property_identifier_pattern'}:
            name = self.raw(node)
            index = scope if scope is not None else next((i for i in reversed(range(len(state.scopes))) if name in state.scopes[i]), len(state.scopes) - 1)
            state.scopes[index][name] = values
        elif kind == 'object_pattern':
            for child in node.named_children:
                if child.type == 'pair_pattern':
                    key = child.child_by_field_name('key')
                    label = string(self.raw(key)) if key.type == 'string' else self.raw(key)
                    self.bind(child.child_by_field_name('value'), self.property(values, label, state), state, scope)
                elif child.type == 'shorthand_property_identifier_pattern':
                    self.bind(child, self.property(values, self.raw(child), state), state, scope)
                else:
                    self.bind(child, UNKNOWN, state, scope)
        elif kind in {'assignment_pattern', 'object_assignment_pattern'}:
            self.bind(node.child_by_field_name('left'), values | UNKNOWN, state, scope)
        elif kind in {'required_parameter', 'optional_parameter'}:
            self.bind(node.child_by_field_name('pattern') or node.child_by_field_name('name'), values, state, scope)
        elif kind in {'array_pattern', 'rest_pattern'}:
            for child in node.named_children:
                self.bind(child, UNKNOWN, state, scope)

    def predeclare(self, node, state, hoisted=False):
        todo = list(node.named_children)
        while todo:
            child = todo.pop()
            if child.type in FUNCTIONS | {'class_declaration'}:
                if not hoisted:
                    self.bind(child.child_by_field_name('name'), UNKNOWN, state, len(state.scopes) - 1)
                continue
            if child.type == 'variable_declaration' or (not hoisted and child.type == 'lexical_declaration'):
                for declaration in child.named_children:
                    if declaration.type == 'variable_declarator':
                        self.bind(declaration.child_by_field_name('name'), UNKNOWN, state,
                                  state.function if child.type == 'variable_declaration' else len(state.scopes) - 1)
            if hoisted and child.type == 'for_in_statement' and self.raw(child.child_by_field_name('kind')) == 'var':
                self.bind(child.child_by_field_name('left'), UNKNOWN, state, state.function)
            if hoisted or child.type == 'export_statement':
                todo.extend(child.named_children)

    def imports(self, root, state):
        for node in root.named_children:
            if node.type != 'import_statement' or re.match(r'\s*import\s+type\b', self.raw(node)):
                continue
            source = string(self.raw(node.child_by_field_name('source')))
            values = frozenset({FS if source in {'fs', 'node:fs'} else PROMISES}) if source in {'fs', 'node:fs', 'fs/promises', 'node:fs/promises'} else UNKNOWN
            for clause in node.named_children:
                if clause.type != 'import_clause':
                    continue
                for child in clause.named_children:
                    if child.type == 'identifier':
                        self.bind(child, values, state, 0)
                    elif child.type == 'namespace_import':
                        self.bind(child.named_children[-1], values, state, 0)
                    elif child.type == 'named_imports':
                        for spec in child.named_children:
                            if spec.type != 'import_specifier' or re.match(r'type\s+(?!as\b)', self.raw(spec)):
                                continue
                            name = spec.child_by_field_name('name')
                            label = string(self.raw(name)) if name.type == 'string' else self.raw(name)
                            alias = spec.child_by_field_name('alias') or name
                            self.bind(alias, values if label == 'default' else self.property(values, label, state), state, 0)

    @staticmethod
    def merge(destination, branches):
        for index, scope in enumerate(destination.scopes):
            for name in set().union(*(set(branch.scopes[index]) for branch in branches)):
                scope[name] = frozenset().union(*(branch.scopes[index].get(name, UNKNOWN) for branch in branches))
        destination.modified.update(set().union(*(branch.modified for branch in branches)))

    def walk(self, node, state, depth=0):
        self.visits += 1
        if self.visits > 120000 or depth > 250:
            raise ValueError('JS filesystem binding analysis budget exceeded')
        kind = node.type
        if kind in FUNCTIONS:
            state = state.copy()
            state.scopes.append({}); state.function = len(state.scopes) - 1
            self.bind(node.child_by_field_name('name'), UNKNOWN, state, state.function)
            params = node.child_by_field_name('parameters')
            for parameter in params.named_children if params is not None else [node.child_by_field_name('parameter')]:
                self.bind(parameter, UNKNOWN, state, state.function)
            body = node.child_by_field_name('body')
            if body is not None:
                self.predeclare(body, state, hoisted=True)
                self.walk(body, state, depth + 1)
            return
        if kind in {'statement_block', 'catch_clause', 'for_statement', 'for_in_statement', 'switch_body'}:
            state = State([*state.scopes, {}], state.function, state.modified)
            if kind == 'statement_block':
                self.predeclare(node, state)
            if kind == 'catch_clause':
                self.bind(node.child_by_field_name('parameter'), UNKNOWN, state, len(state.scopes) - 1)
        if kind in {'variable_declaration', 'lexical_declaration'}:
            for declaration in node.named_children:
                if declaration.type != 'variable_declarator':
                    continue
                value = declaration.child_by_field_name('value')
                if value is not None:
                    self.walk(value, state, depth + 1)
                    self.bind(declaration.child_by_field_name('name'), self.value(value, state), state,
                              state.function if kind == 'variable_declaration' else len(state.scopes) - 1)
            return
        if kind == 'import_statement':
            return
        if kind == 'if_statement':
            condition = node.child_by_field_name('condition')
            if condition is not None:
                self.walk(condition, state, depth + 1)
            branches = [state.copy(), state.copy()]
            for branch, field in zip(branches, ('consequence', 'alternative')):
                child = node.child_by_field_name(field)
                if child is not None:
                    self.walk(child, branch, depth + 1)
            self.merge(state, branches)
            return
        if kind == 'for_in_statement':
            right, left = node.child_by_field_name('right'), node.child_by_field_name('left')
            target = state.function if self.raw(node.child_by_field_name('kind')) == 'var' else len(state.scopes) - 1
            self.bind(left, UNKNOWN, state, target)
            self.walk(right, state, depth + 1)
            body = node.child_by_field_name('body')
            if body is not None:
                branches = [state.copy(), state.copy()]
                self.walk(body, branches[1], depth + 1)
                self.merge(state, branches)
            return
        if kind in {'for_statement', 'while_statement', 'do_statement'}:
            body = node.child_by_field_name('body')
            for field in ('initializer', 'condition'):
                child = node.child_by_field_name(field)
                if child is not None:
                    self.walk(child, state, depth + 1)
            branches = [state.copy(), state.copy()]
            if body is not None:
                self.walk(body, branches[1], depth + 1)
            increment = node.child_by_field_name('increment')
            if increment is not None:
                self.walk(increment, branches[1], depth + 1)
            self.merge(state, branches)
            return
        if kind in {'assignment_expression', 'augmented_assignment_expression'}:
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            if right is not None:
                self.walk(right, state, depth + 1)
            if left.type in {'member_expression', 'subscript_expression'}:
                values = self.value(left, state) - {''}
                state.modified.update(values)
                if not values and self.value(left.child_by_field_name('object'), state) & {FS, PROMISES}:
                    state.modified.update(self.value(left.child_by_field_name('object'), state) - {''})
                    self.diagnostics.add('JS filesystem computed property write is unresolved')
            else:
                self.bind(left, self.value(right, state) if kind == 'assignment_expression' else UNKNOWN, state)
            return
        if kind == 'update_expression':
            self.bind(node.child_by_field_name('argument'), UNKNOWN, state)
            return
        if kind == 'unary_expression' and self.raw(node.child_by_field_name('operator')) == 'delete':
            argument = node.child_by_field_name('argument')
            state.modified.update(self.value(argument, state) - {''})
            return
        if kind == 'call_expression':
            values = self.value(node.child_by_field_name('function'), state)
            targets = values & DELETIONS
            if targets:
                self.calls[node.start_byte] = (node, sorted(targets), '' in values)
        for child in node.named_children:
            self.walk(child, state, depth + 1)

    def scan(self, root):
        state = State([{'require': frozenset({'global:require'})}])
        self.predeclare(root, state, hoisted=True)
        self.predeclare(root, state)
        self.imports(root, state)
        self.walk(root, state)
        return self.calls, self.diagnostics


def resolve(source, root):
    return Resolver(source).scan(root)
