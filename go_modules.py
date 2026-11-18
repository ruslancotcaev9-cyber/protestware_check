"""Bounded Go types/calls in selected package files. No builds, imports or I/O."""
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

import go_bindings

ROOT = ('native', 'os.Root')
FUNCTIONS = go_bindings.FUNCTIONS


def trace(*parts):
    values = tuple(hop for part in parts for hop in part)
    return values if len(values) <= 24 else (values[0], *values[-23:])


@dataclass(frozen=True)
class Value:
    kind: str = 'unknown'
    key: object = None
    route: tuple = ()


UNKNOWN = Value()


class Unit:
    def __init__(self, path, source, tree):
        self.path, self.source, self.tree = path, source, tree
        self.data = source.encode('utf-8')
        self.legacy = go_bindings.Resolver(source)
        self.diagnostics = set()
        self.globals = {}
        clause = next((n for n in tree.root_node.named_children if n.type == 'package_clause'), None)
        package = self.raw(clause.named_children[-1]) if clause is not None and clause.named_children else ''
        tags = tuple(re.sub(r'\s+', ' ', line.strip()) for line in source.splitlines()
                     if re.match(r'\s*//(?:go:build|\s*\+build)\b', line))
        self.group = (str(PurePosixPath(path).parent), package, path.endswith('_test.go'), tags)
        try:
            self.legacy.scan(tree.root_node)
        except ValueError as error:
            self.diagnostics.add(str(error))
        self.diagnostics.update(self.legacy.diagnostics)
        self.imports = {name: Value('package', 'os') if value == 'package:os' else UNKNOWN
                        for name, value in self.legacy.imports.items()}
        if tree.root_node.has_error:
            self.diagnostics.add('Go selected file has syntax recovery')

    def raw(self, node):
        return self.data[node.start_byte:node.end_byte].decode('utf-8', 'replace') if node is not None else ''

    def hop(self, node, kind, message):
        return ((self.path, node.start_point[0] + 1, kind, message),)

    def scopes(self):
        return [self.imports, self.globals]


class Project:
    def __init__(self, files, *, trees=None, max_files=128, max_bytes=10_000_000,
                 max_nodes=500000, max_steps=120000, max_edges=8192, max_summary_steps=20000,
                 max_declarations=4096, strict_paths=True):
        self.units, self.types, self.functions, self.methods = {}, {}, {}, {}
        self.definitions, self.field_cache, self.result_cache = {}, {}, {}
        self.group_diagnostics = defaultdict(set)
        self.global_diagnostics, self.duplicates = set(), set()
        self.observations, self.seeds = defaultdict(dict), defaultdict(dict)
        self.edges, self.dependencies = {}, defaultdict(set)
        self.max_nodes, self.max_steps, self.max_edges = max_nodes, max_steps, max_edges
        self.nodes = self.steps = self.summary_steps = self.bytes = 0
        self.max_summary_steps, self.max_declarations = max_summary_steps, max_declarations
        for path, source in files:
            if PurePosixPath(path).suffix.lower() != '.go':
                continue
            if strict_paths and (not path or str(PurePosixPath(path)) != path or path.startswith('/') or
                    '..' in PurePosixPath(path).parts or '\\' in path or ':' in path or any(ord(c) < 32 for c in path)):
                self.global_diagnostics.add('Go selected path is not canonical')
                continue
            if path in self.units:
                self.duplicates.add(path)
                self.global_diagnostics.add('Go selected path is duplicated')
                continue
            size = len(source.encode('utf-8'))
            if len(self.units) >= max_files or self.bytes + size > max_bytes:
                self.global_diagnostics.add('Go selected file/byte budget exceeded')
                break
            self.bytes += size
            try:
                from polyglot_ast import _parser
                tree = (trees or {}).get(path)
                if tree is None:
                    tree = _parser('go').parse(source.encode('utf-8'))
                self.units[path] = Unit(path, source, tree)
                self.nodes += self.units[path].legacy.visits
                if self.nodes > self.max_nodes:
                    self.global_diagnostics.add('Go selected AST node budget exceeded')
                    break
            except (RuntimeError, ValueError) as error:
                self.global_diagnostics.add('Go parser unavailable: ' + str(error))
        for path in self.duplicates:
            self.units.pop(path, None)
        try:
            self.index()
            for unit in self.units.values():
                Walker(self, unit).scan()
            self.summarize()
        except (ValueError, RecursionError) as error:
            self.global_diagnostics.add(str(error) if not isinstance(error, RecursionError) else 'Go binding nesting budget exceeded')
            self.summaries = dict(self.seeds)

    def step(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise ValueError('Go type/call resolution budget exceeded')

    def visit(self, depth):
        self.nodes += 1
        if self.nodes > self.max_nodes or depth > 120:
            raise ValueError('Go selected AST node/depth budget exceeded')

    def unique(self, mapping, key, value, unit):
        if key in mapping:
            mapping[key] = None
            self.group_diagnostics[unit.group].add('Go selected declarations are duplicated/ambiguous')
        else:
            mapping[key] = value

    def index(self):
        for unit in self.units.values():
            if unit.tree.root_node.has_error:
                continue
            for declaration in unit.tree.root_node.named_children:
                if declaration.type == 'type_declaration':
                    for node in declaration.named_children:
                        if node.type in {'type_spec', 'type_alias'}:
                            key = (unit.group, unit.raw(node.child_by_field_name('name')))
                            self.unique(self.types, key, (unit, node), unit)
                elif declaration.type in {'function_declaration', 'method_declaration'}:
                    identity = (unit.path, declaration.start_byte)
                    self.definitions[identity] = (unit, declaration)
                    if declaration.type == 'function_declaration':
                        self.unique(self.functions, (unit.group, unit.raw(declaration.child_by_field_name('name'))), identity, unit)
                if len(self.types) + len(self.definitions) > self.max_declarations:
                    raise ValueError('Go selected declaration budget exceeded')
        for unit in self.units.values():
            for (group, name), item in self.types.items():
                if group == unit.group:
                    unit.globals[name] = Value('type', (group, name)) if item is not None else UNKNOWN
            for (group, name), item in self.functions.items():
                if group == unit.group:
                    unit.globals[name] = Value('function', item) if item is not None else UNKNOWN
            for declaration in unit.tree.root_node.named_children:
                if declaration.type in {'var_declaration', 'const_declaration'}:
                    for spec in declaration.named_children:
                        for node in spec.children_by_field_name('name'):
                            unit.globals[unit.raw(node)] = UNKNOWN
        for identity, (unit, node) in self.definitions.items():
            if node.type != 'method_declaration':
                continue
            receiver = node.child_by_field_name('receiver')
            parameter = receiver.named_children[0] if receiver is not None and receiver.named_children else None
            type_node = parameter.child_by_field_name('type') if parameter is not None else None
            while type_node is not None and type_node.type in {'pointer_type', 'parenthesized_type'}:
                type_node = type_node.named_children[0]
            if type_node is not None and type_node.type == 'type_identifier':
                name = unit.raw(type_node)
                item = self.types.get((unit.group, name))
                if item is not None and item[1].type == 'type_spec':
                    self.unique(self.methods, ((unit.group, name), unit.raw(node.child_by_field_name('name'))), identity, unit)

    @staticmethod
    def lookup(name, scopes):
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return None

    def type(self, unit, node, scopes=None, *, opaque=False, seen=()):
        self.step()
        if node is None:
            return UNKNOWN
        if len(seen) > 24:
            raise ValueError('Go type alias depth budget exceeded')
        scopes = scopes if scopes is not None else unit.scopes()
        kind = node.type
        if kind in {'pointer_type', 'parenthesized_type'}:
            return self.type(unit, node.named_children[0], scopes, opaque=opaque, seen=seen)
        if kind == 'qualified_type':
            package = self.lookup(unit.raw(node.child_by_field_name('package')), scopes)
            if package == Value('package', 'os') and unit.raw(node.child_by_field_name('name')) == 'Root':
                return Value('value', ROOT, unit.hop(node, 'type', 'os.Root'))
            return UNKNOWN
        if kind not in {'type_identifier', 'identifier'}:
            return UNKNOWN
        name = unit.raw(node)
        bound, key = self.lookup(name, scopes), (unit.group, name)
        if bound is not None and bound.kind != 'type':
            return UNKNOWN
        item = self.types.get(key)
        if item is not None:
            origin, definition = item
            if key in seen:
                self.group_diagnostics[unit.group].add('Go selected type alias cycle')
                return UNKNOWN
            if definition.type == 'type_alias':
                return self.type(origin, definition.child_by_field_name('type'), opaque=opaque, seen=(*seen, key))
            return Value('value', key, unit.hop(node, 'type', name))
        if key in self.types:
            return UNKNOWN
        if name == 'Root' and unit.legacy.dot_os and bound is None:
            if unit.legacy.other_dot:
                self.group_diagnostics[unit.group].add('Go Root dot import is ambiguous')
                return UNKNOWN
            return Value('value', ROOT, unit.hop(node, 'type', 'os.Root'))
        return Value('value', key, unit.hop(node, 'type', name)) if opaque and name[:1].isupper() else UNKNOWN

    def fields(self, key):
        self.step()
        if key not in self.field_cache:
            self.field_cache[key] = {}
            item = self.types.get(key)
            if item is not None:
                unit, node = item
                body = node.child_by_field_name('type')
                if body is not None and body.type == 'struct_type':
                    scopes = unit.scopes()
                    parameters = node.child_by_field_name('type_parameters')
                    if parameters is not None:
                        scopes = [*scopes, {unit.raw(n): UNKNOWN for p in parameters.named_children for n in p.children_by_field_name('name')}]
                    for container in body.named_children:
                        for field in container.named_children:
                            if field.type == 'field_declaration':
                                value = self.type(unit, field.child_by_field_name('type'), scopes, opaque=True)
                                for name in field.children_by_field_name('name'):
                                    self.field_cache[key][unit.raw(name)] = Value(value.kind, value.key, trace(value.route, unit.hop(name, 'field', unit.raw(name))))
        return self.field_cache[key]

    def results(self, identity):
        self.step()
        if identity not in self.result_cache:
            unit, node = self.definitions[identity]
            result = node.child_by_field_name('result')
            parameters = node.child_by_field_name('type_parameters')
            scopes = unit.scopes()
            if parameters is not None:
                scopes = [*scopes, {unit.raw(n): UNKNOWN for p in parameters.named_children for n in p.children_by_field_name('name')}]
            values = []
            if result is not None:
                parts = result.named_children if result.type == 'parameter_list' else [result]
                for part in parts:
                    type_node = part.child_by_field_name('type') if part.type == 'parameter_declaration' else part
                    value = self.type(unit, type_node, scopes, opaque=True)
                    value = Value(value.kind, value.key, trace(value.route, unit.hop(part, 'return-type', unit.raw(type_node))))
                    values.extend([value] * max(1, len(part.children_by_field_name('name'))))
            self.result_cache[identity] = values
        return self.result_cache[identity]

    def edge(self, owner, node, target, route, unit):
        key = (unit.path, node.start_byte)
        if key not in self.edges and len(self.edges) >= self.max_edges:
            raise ValueError('Go selected call edge budget exceeded')
        self.edges[key] = (owner, node, target, route, unit)
        self.dependencies[target].add(key)

    def summarize(self):
        self.summaries = {key: dict(value) for key, value in self.seeds.items()}
        pending, queued = deque(self.edges), set(self.edges)
        while pending:
            key = pending.popleft()
            queued.discard(key)
            self.summary_steps += 1
            if self.summary_steps > self.max_summary_steps:
                self.global_diagnostics.add('Go selected summary budget exceeded')
                break
            owner, node, target, route, unit = self.edges[key]
            for symbol, hops in self.summaries.get(target, {}).items():
                combined = trace(route, hops)
                self.observations[unit.path].setdefault(node.start_byte, (node, symbol, combined))
                summary = self.summaries.setdefault(owner, {})
                if symbol not in summary:
                    summary[symbol] = combined
                    for caller in self.dependencies.get(owner, ()):
                        if caller not in queued:
                            queued.add(caller)
                            pending.append(caller)

    def tree(self, path):
        return self.units[path].tree if path in self.units else None

    def calls(self, path):
        unit = self.units.get(path)
        diagnostics = set(self.global_diagnostics)
        if unit is not None:
            diagnostics.update(unit.diagnostics)
            diagnostics.update(self.group_diagnostics[unit.group])
        return self.observations.get(path, {}), sorted(diagnostics)

    def metadata(self):
        return {'mode': 'selected-go-package', 'files': len(self.units), 'bytes': self.bytes,
                'packages': len({u.group for u in self.units.values()}), 'nodes': self.nodes,
                'resolution_steps': self.steps, 'call_edges': len(self.edges),
                'summary_steps': self.summary_steps,
                'complete': not self.global_diagnostics and not any(self.calls(p)[1] for p in self.units)}


class Walker:
    def __init__(self, project, unit):
        self.p, self.u = project, unit

    def value(self, node, scopes, level=0):
        self.p.step()
        if node is None:
            return UNKNOWN
        if level > 40:
            raise ValueError('Go expression depth budget exceeded')
        kind = node.type
        if kind == 'identifier':
            value = self.p.lookup(self.u.raw(node), scopes)
            return value if value is not None and value.kind == 'value' else UNKNOWN
        if kind in {'parenthesized_expression', 'unary_expression'} and node.named_children:
            return self.value(node.named_children[-1], scopes, level + 1)
        if kind == 'composite_literal':
            return self.p.type(self.u, node.child_by_field_name('type'), scopes)
        if kind == 'type_assertion_expression':
            return self.p.type(self.u, node.child_by_field_name('type'), scopes)
        if kind == 'selector_expression':
            receiver = self.value(node.child_by_field_name('operand'), scopes, level + 1)
            if receiver.kind == 'value' and receiver.key != ROOT:
                field = self.p.fields(receiver.key).get(self.u.raw(node.child_by_field_name('field')))
                if field is not None:
                    return Value(field.kind, field.key, trace(receiver.route, field.route))
            return UNKNOWN
        if kind == 'call_expression':
            values = self.call_results(node, scopes, level + 1)
            return values[0] if len(values) == 1 else UNKNOWN
        return UNKNOWN

    def target(self, function, scopes):
        if function is None:
            return None
        while function.type == 'parenthesized_expression' and function.named_child_count == 1:
            function = function.named_children[0]
        if function.type == 'identifier':
            value = self.p.lookup(self.u.raw(function), scopes)
            return value.key if value is not None and value.kind == 'function' else None
        if function.type == 'selector_expression':
            receiver = self.value(function.child_by_field_name('operand'), scopes)
            if receiver.kind == 'value' and receiver.key != ROOT:
                name = self.u.raw(function.child_by_field_name('field'))
                identity = self.p.methods.get((receiver.key, name))
                if identity is None and name in go_bindings.DELETIONS and receiver.key not in self.p.types:
                    self.u.diagnostics.add('Go selected receiver type/method is missing or has a different package/build scope')
                return identity
        return None

    def call_results(self, node, scopes, level=0):
        function = node.child_by_field_name('function')
        if function is None:
            return []
        if function.type == 'identifier' and self.u.raw(function) == 'new' and self.p.lookup('new', scopes) is None:
            arguments = node.child_by_field_name('arguments')
            if arguments is not None and len(arguments.named_children) == 1:
                arg = arguments.named_children[0]
                value = self.p.type(self.u, arg, scopes)
                if arg.type == 'selector_expression' and self.u.raw(arg.child_by_field_name('field')) == 'Root':
                    package = self.p.lookup(self.u.raw(arg.child_by_field_name('operand')), scopes)
                    if package == Value('package', 'os'):
                        value = Value('value', ROOT, self.u.hop(arg, 'type', 'os.Root'))
                return [value]
        if function.type == 'selector_expression' and self.u.raw(function.child_by_field_name('field')) == 'OpenRoot':
            operand = function.child_by_field_name('operand')
            package = self.p.lookup(self.u.raw(operand), scopes) if operand is not None and operand.type == 'identifier' else None
            receiver = self.value(operand, scopes, level + 1)
            if package == Value('package', 'os') or receiver.key == ROOT:
                return [Value('value', ROOT, self.u.hop(node, 'construction', 'os.OpenRoot')), UNKNOWN]
        identity = self.target(function, scopes)
        return self.p.results(identity) if identity is not None else []

    def record(self, node, scopes, owner):
        direct = self.u.legacy.calls.get(node.start_byte)
        value, symbol = UNKNOWN, direct[1] if direct else None
        fn = node.child_by_field_name('function')
        if fn is not None and fn.type == 'selector_expression':
            value = self.value(fn.child_by_field_name('operand'), scopes)
            name = self.u.raw(fn.child_by_field_name('field'))
            if value.key == ROOT and name in go_bindings.DELETIONS:
                symbol = 'os.Root.' + name
        if symbol:
            route = trace(value.route, self.u.hop(node, 'sink', symbol))
            self.p.observations[self.u.path][node.start_byte] = (node, symbol, route)
            self.p.seeds[owner].setdefault(symbol, route)
        else:
            target = self.target(fn, scopes)
            if target is not None:
                self.p.edge(owner, node, target, trace(value.route, self.u.hop(node, 'call', 'selected Go call')), self.u)

    def declaration(self, node, scopes):
        type_node = node.child_by_field_name('type')
        names = node.children_by_field_name('name')
        if type_node is not None:
            values = [self.p.type(self.u, type_node, scopes)] * len(names)
        else:
            right = node.child_by_field_name('value')
            expressions = right.named_children if right is not None else []
            values = (self.call_results(expressions[0], scopes) if len(expressions) == 1 and expressions[0].type == 'call_expression'
                      else [self.value(part, scopes) for part in expressions])
        for index, name in enumerate(names):
            value = values[index] if index < len(values) else UNKNOWN
            scopes[-1][self.u.raw(name)] = Value(value.kind, value.key, trace(value.route, self.u.hop(name, 'declaration', self.u.raw(name))))

    def walk(self, node, scopes, owner, depth=0):
        self.p.visit(depth)
        kind = node.type
        if kind in FUNCTIONS:
            owner = (self.u.path, node.start_byte)
            scopes = [*scopes, {}]
            generics = node.child_by_field_name('type_parameters')
            if generics is not None:
                for parameter in generics.named_children:
                    for name in parameter.children_by_field_name('name'):
                        scopes[-1][self.u.raw(name)] = UNKNOWN
            signature_scopes = [*scopes[:-1], dict(scopes[-1])]
            for field in ('receiver', 'parameters', 'result'):
                container = node.child_by_field_name(field)
                if container is not None:
                    for parameter in container.named_children:
                        value = self.p.type(self.u, parameter.child_by_field_name('type'), signature_scopes)
                        for name in parameter.children_by_field_name('name'):
                            scopes[-1][self.u.raw(name)] = Value(value.kind, value.key, trace(value.route, self.u.hop(name, 'parameter', self.u.raw(name))))
            body = node.child_by_field_name('body')
            if body is not None:
                self.walk(body, scopes, owner, depth + 1)
            return
        if kind == 'block' or kind in go_bindings.CONTROL | go_bindings.CASES:
            scopes = [*scopes, {}]
        if kind == 'type_switch_statement':
            for field in ('initializer', 'value'):
                part = node.child_by_field_name(field)
                if part is not None:
                    self.walk(part, scopes, owner, depth + 1)
            alias = node.child_by_field_name('alias')
            if alias is not None:
                for name in alias.named_children:
                    scopes[-1][self.u.raw(name)] = UNKNOWN
            for child in node.named_children:
                if child.type in go_bindings.CASES:
                    self.walk(child, scopes, owner, depth + 1)
            return
        if kind in {'short_var_declaration', 'range_clause', 'receive_statement'}:
            right, values = node.child_by_field_name('right'), []
            if right is not None:
                self.walk(right, scopes, owner, depth + 1)
                if kind == 'short_var_declaration':
                    expressions = right.named_children
                    values = (self.call_results(expressions[0], scopes) if len(expressions) == 1 and expressions[0].type == 'call_expression'
                              else [self.value(part, scopes) for part in expressions])
            left = node.child_by_field_name('left')
            if left is not None and ':=' in self.u.data[left.end_byte:right.start_byte if right is not None else node.end_byte].decode('utf-8', 'replace'):
                for index, name in enumerate(left.named_children):
                    if name.type == 'identifier' and self.u.raw(name) not in scopes[-1]:
                        value = values[index] if index < len(values) else UNKNOWN
                        scopes[-1][self.u.raw(name)] = Value(value.kind, value.key, trace(value.route, self.u.hop(name, 'declaration', self.u.raw(name))))
            return
        if kind in {'var_spec', 'const_spec', 'type_spec', 'type_alias'}:
            value = node.child_by_field_name('value')
            if value is not None:
                self.walk(value, scopes, owner, depth + 1)
            if kind == 'var_spec':
                self.declaration(node, scopes)
            else:
                for name in node.children_by_field_name('name'):
                    scopes[-1][self.u.raw(name)] = self.u.globals.get(self.u.raw(name), UNKNOWN) if kind in {'type_spec', 'type_alias'} else UNKNOWN
            return
        if kind == 'call_expression':
            self.record(node, scopes, owner)
        for child in node.named_children:
            self.walk(child, scopes, owner, depth + 1)

    def scan(self):
        self.walk(self.u.tree.root_node, self.u.scopes(), (self.u.path, 'global'))
