"""Bounded, selected-file C# filesystem API identities; no compilation or I/O.

This is a syntax/type-declaration model, not Roslyn or runtime dispatch. Only
observed imports, declarations and constructions establish native identities.
"""
from dataclasses import dataclass
import re

STATIC = {'File', 'Directory'}
INSTANCES = {'FileInfo', 'DirectoryInfo'}
TYPES = STATIC | INSTANCES
CLASSES = {'class_declaration', 'struct_declaration', 'interface_declaration',
           'record_declaration', 'enum_declaration'}
FUNCTIONS = {'method_declaration', 'constructor_declaration', 'local_function_statement',
             'lambda_expression', 'anonymous_method_expression', 'accessor_declaration'}


@dataclass(frozen=True)
class Binding:
    kind: str = 'unknown'
    name: str = ''
    trace: tuple = ()

    def step(self, node, kind, message):
        return Binding(self.kind, self.name,
                       (*self.trace, (node.start_point[0] + 1, kind, message))[-12:])


UNKNOWN = Binding()
OTHER = Binding('other')


class Resolver:
    def __init__(self, source, *, max_nodes=120000, max_depth=120, max_context_steps=120000):
        self.data = source.encode('utf-8')
        self.max_nodes, self.max_depth = max_nodes, max_depth
        self.visits = 0
        self.context_steps, self.max_context_steps = 0, max_context_steps
        self.calls, self.diagnostics = {}, set()
        self.usings, self.declared, self.full_types = {}, set(), set()
        self.methods = set()
        self.root = None
        self.file_namespace = ''
        self.generics = {}

    def context_step(self):
        self.context_steps += 1
        if self.context_steps > self.max_context_steps:
            raise ValueError('C# binding context budget exceeded')

    def raw(self, node):
        return self.data[node.start_byte:node.end_byte].decode('utf-8', 'replace') if node is not None else ''

    def name(self, node):
        text = re.sub(r'/\*.*?\*/|//[^\r\n]*', '', self.raw(node), flags=re.S)
        return re.sub(r'\s+', '', text).replace('@', '')

    def namespace(self, node):
        parts = []
        current = node
        while current is not None:
            if current.type == 'namespace_declaration':
                parts.append(self.name(current.child_by_field_name('name')))
            current = current.parent
        if self.file_namespace:
            parts.append(self.file_namespace)
        return '.'.join(reversed(parts))

    def context(self, node):
        owners, generics = [], set()
        current = node
        while current is not None:
            self.context_step()
            if current.type in {'compilation_unit', 'namespace_declaration'}:
                owners.append(current.id)
            generics.update(self.generics.get(current.id, ()))
            current = current.parent
        aliases, imports, static = {}, set(), set()
        for owner in reversed(owners):
            for alias, target, is_static in self.usings.get(owner, []):
                self.context_step()
                if alias:
                    aliases[alias] = target
                elif is_static:
                    static.add(target)
                else:
                    imports.add(target)
        return aliases, imports, static, generics

    def index(self, root):
        self.root = root
        file_scope = next((n for n in root.named_children if n.type == 'file_scoped_namespace_declaration'), None)
        self.file_namespace = self.name(file_scope.child_by_field_name('name')) if file_scope is not None else ''
        todo = [(root, 0)]
        count = 0
        while todo:
            node, depth = todo.pop()
            count += 1
            if count > self.max_nodes or depth > self.max_depth:
                raise ValueError('C# binding index budget exceeded')
            if node.type in CLASSES | FUNCTIONS:
                parameters = next((c for c in node.named_children if c.type == 'type_parameter_list'), None)
                if parameters is not None:
                    self.generics[node.id] = {self.name(p.child_by_field_name('name')) for p in parameters.named_children}
            if node.type in CLASSES:
                name = self.name(node.child_by_field_name('name'))
                self.declared.add(name)
                enclosing, parent = [], node.parent
                while parent is not None:
                    if parent.type in CLASSES:
                        enclosing.append(self.name(parent.child_by_field_name('name')))
                    parent = parent.parent
                self.full_types.add('.'.join(filter(None, (self.namespace(node), *reversed(enclosing), name))))
            elif node.type in {'method_declaration', 'local_function_statement'}:
                self.methods.add(self.name(node.child_by_field_name('name')))
            elif node.type == 'using_directive':
                alias_node = node.child_by_field_name('name')
                target_node = node.named_children[-1] if node.named_children else None
                target = self.name(target_node)
                alias = self.name(alias_node) if alias_node is not None else ''
                owner = node.parent
                while owner is not None and owner.type not in {'compilation_unit', 'namespace_declaration'}:
                    owner = owner.parent
                if owner is not None:
                    self.usings.setdefault(owner.id, []).append((alias, target, bool(re.search(r'\bstatic\b', self.raw(node)))))
            todo.extend((child, depth + 1) for child in reversed(node.named_children))

    def type_binding(self, text, node):
        text = text.rstrip('?')
        aliases, imports, _, generics = self.context(node)
        global_name = text.startswith('global::')
        text = text.removeprefix('global::')
        first = text.split('.')[0]
        if not global_name and (first in generics or first in self.declared):
            return OTHER
        if not global_name and first in aliases:
            target = aliases[first]
            global_name = target.startswith('global::')
            text = target.removeprefix('global::') + text[len(first):]
            if not global_name and text.split('.')[0] in self.declared:
                return OTHER
        if '.' not in text and text in TYPES:
            namespace = self.namespace(node)
            if 'System.IO' in imports or namespace == 'System.IO' or namespace.startswith('System.IO.'):
                text = 'System.IO.' + text
            else:
                return UNKNOWN
        if text.startswith('System.IO.') and text.rsplit('.', 1)[-1] in TYPES:
            if text in self.full_types or 'System' in self.full_types:
                return OTHER
            return Binding('type', text.rsplit('.', 1)[-1]).step(node, 'type', text)
        return OTHER if text and text not in {'var', 'dynamic', 'object'} else UNKNOWN

    @staticmethod
    def lookup(name, scopes):
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return None

    def value(self, node, scopes, fields, level=0):
        if node is None:
            return UNKNOWN
        if level > 40:
            self.diagnostics.add('C# binding expression depth budget exceeded')
            return UNKNOWN
        kind = node.type
        if kind == 'identifier':
            name = self.name(node)
            value = self.lookup(name, scopes)
            return value if value is not None else self.type_binding(name, node)
        if kind == 'object_creation_expression':
            bound = self.type_binding(self.name(node.child_by_field_name('type')), node)
            if bound.kind == 'type' and bound.name in INSTANCES:
                return Binding('instance', bound.name, bound.trace).step(node, 'construction', 'new System.IO.' + bound.name)
            return OTHER if bound.kind == 'other' else UNKNOWN
        if kind == 'cast_expression':
            bound = self.type_binding(self.name(node.child_by_field_name('type')), node)
            return Binding('instance', bound.name, bound.trace) if bound.kind == 'type' and bound.name in INSTANCES else OTHER
        if kind == 'parenthesized_expression' or kind == 'postfix_unary_expression' and self.raw(node).rstrip().endswith('!'):
            return self.value(node.named_children[0], scopes, fields, level + 1) if node.named_children else UNKNOWN
        if kind == 'member_access_expression':
            receiver, name = node.child_by_field_name('expression'), self.name(node.child_by_field_name('name'))
            if self.name(receiver) == 'this':
                return fields.get(name, UNKNOWN)
            text = self.name(node)
            if not text.startswith('global::') and self.lookup(text.split('.')[0], scopes) is not None:
                return UNKNOWN
            return self.type_binding(text, node)
        if kind == 'conditional_expression':
            left = self.value(node.child_by_field_name('consequence'), scopes, fields, level + 1)
            right = self.value(node.child_by_field_name('alternative'), scopes, fields, level + 1)
            return left if (left.kind, left.name) == (right.kind, right.name) else UNKNOWN
        return UNKNOWN

    def declared_binding(self, type_node, node, initializer=None, scopes=(), fields=None):
        text = self.name(type_node)
        if text == 'var':
            value = self.value(initializer, scopes, fields or {})
        else:
            value = self.type_binding(text, type_node or node)
            if value.kind == 'type':
                value = Binding('instance', value.name, value.trace) if value.name in INSTANCES else OTHER
        return value.step(node, 'declaration', self.name(node.child_by_field_name('name')))

    def declarations(self, node, scopes, fields, target):
        type_node = node.child_by_field_name('type')
        for part in node.named_children:
            if part.type != 'variable_declarator':
                continue
            name = self.name(part.child_by_field_name('name'))
            values = part.named_children[1:]
            target[name] = self.declared_binding(type_node, part, values[-1] if values else None, scopes, fields)

    def deletion(self, node, scopes, fields):
        fn = node.child_by_field_name('function')
        if fn is None:
            return
        if fn.type == 'member_access_expression':
            method = self.name(fn.child_by_field_name('name'))
            receiver = fn.child_by_field_name('expression')
            bound = self.value(receiver, scopes, fields)
        elif fn.type == 'conditional_access_expression':
            member = next((c for c in fn.named_children if c.type == 'member_binding_expression'), None)
            method = self.name(member.child_by_field_name('name')) if member is not None else ''
            bound = self.value(fn.child_by_field_name('condition'), scopes, fields)
        elif fn.type == 'identifier' and self.name(fn) == 'Delete':
            if self.lookup('Delete', scopes) is not None or 'Delete' in self.methods:
                return
            _, _, static, _ = self.context(node)
            targets = [t.removeprefix('global::') for t in static if t.removeprefix('global::') in {'System.IO.File', 'System.IO.Directory'}]
            if len(targets) != 1:
                if targets:
                    self.diagnostics.add('C# static Delete imports are ambiguous')
                return
            method = 'Delete'
            bound = self.type_binding(targets[0], node)
        else:
            return
        if method != 'Delete':
            return
        if bound.kind == 'instance' and bound.name in INSTANCES or bound.kind == 'type' and bound.name in STATIC:
            symbol = 'System.IO.' + bound.name + '.Delete'
            self.calls[node.start_byte] = (node, symbol, (*bound.trace, (node.start_point[0] + 1, 'sink', symbol)))
        elif bound.kind == 'unknown':
            self.diagnostics.add(f'C# Delete receiver type is unresolved at line {node.start_point[0] + 1}')

    def walk(self, node, scopes, fields, depth=0):
        self.visits += 1
        if self.visits > self.max_nodes or depth > self.max_depth:
            raise ValueError('C# binding walk budget exceeded')
        kind = node.type
        if kind in CLASSES:
            body = node.child_by_field_name('body')
            local_fields = {}
            if body is not None:
                for member in body.named_children:
                    if member.type == 'field_declaration':
                        for declaration in member.named_children:
                            if declaration.type == 'variable_declaration':
                                self.declarations(declaration, (), {}, local_fields)
                self.walk(body, [local_fields], local_fields, depth + 1)
            return
        if kind in FUNCTIONS:
            local = {}
            parameters = node.child_by_field_name('parameters')
            if parameters is not None:
                if parameters.type in {'identifier', 'implicit_parameter'}:
                    local[self.name(parameters)] = UNKNOWN
                for parameter in parameters.named_children:
                    name = parameter if parameter.type in {'identifier', 'implicit_parameter'} else parameter.child_by_field_name('name')
                    if name is not None:
                        local[self.name(name)] = self.declared_binding(parameter.child_by_field_name('type'), parameter)
            scopes = [*scopes, local]
        elif kind in {'block', 'switch_section', 'for_statement', 'foreach_statement', 'catch_clause', 'using_statement'}:
            scopes = [*scopes, {}]
            if kind == 'foreach_statement':
                name = node.child_by_field_name('left')
                if name is not None:
                    scopes[-1][self.name(name)] = self.declared_binding(node.child_by_field_name('type'), node)
        elif kind == 'variable_declaration' and node.parent.type != 'field_declaration':
            self.declarations(node, scopes, fields, scopes[-1])
        if kind == 'invocation_expression':
            self.deletion(node, scopes, fields)
        for child in node.named_children:
            self.walk(child, scopes, fields, depth + 1)


def resolve(source, root, **limits):
    resolver = Resolver(source, **limits)
    try:
        resolver.index(root)
        resolver.walk(root, [{}], {})
    except ValueError as error:
        resolver.diagnostics.add(str(error))
    return resolver.calls, resolver.diagnostics
