"""One-hop C# method summaries in selected sibling files. No builds or filesystem lookup."""
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

from csharp_bindings import Binding, CLASSES, FUNCTIONS, Resolver


def enclosing(node, kinds):
    parent = node.parent
    while parent is not None and parent.type not in kinds:
        parent = parent.parent
    return parent


def modifiers(node):
    return {child.text for child in node.named_children if child.type == 'modifier'}


@dataclass
class Method:
    unit: 'Unit'
    node: object
    owner: str
    namespace: str
    receiver: str | None
    eligible: bool
    public: bool
    static: bool
    partial_owner: bool
    sink: tuple | None = None


class Unit(Resolver):
    def __init__(self, project, path, source, tree):
        super().__init__(source)
        self.project, self.path, self.tree = project, path, tree
        self.directory = str(PurePosixPath(path).parent)
        self.index(tree.root_node)
        self.class_keys = {}
        self.method_defs = {}
        self.links = {}

    def qualified(self, text, node):
        text = text.rstrip('?')
        if not re.fullmatch(r'(?:global::)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', text):
            return None
        aliases, imports, _, generics = self.context(node)
        first = text.split('.')[0]
        if first in generics or first in {'var', 'dynamic', 'object', 'void'}:
            return None
        if first in aliases:
            text = aliases[first] + text[len(first):]
        if text.startswith('global::') or '.' in text:
            return text.removeprefix('global::')
        namespace = self.namespace(node)
        local = '.'.join(filter(None, (namespace, text)))
        types = self.project.known[self.directory]
        if local in types:
            return local
        matches = {prefix + '.' + text for prefix in imports if prefix + '.' + text in types}
        if len(matches) > 1:
            return None
        return next(iter(matches), local)

    def declared_binding(self, type_node, node, initializer=None, scopes=(), fields=None):
        value = super().declared_binding(type_node, node, initializer, scopes, fields)
        if value.kind in {'other', 'unknown'} and type_node is not None:
            name = self.qualified(self.name(type_node), node)
            if name:
                return Binding('selected-instance', name).step(node, 'declaration', name)
        return value

    def value(self, node, scopes, fields, level=0):
        value = super().value(node, scopes, fields, level)
        if node is not None and value.kind in {'other', 'unknown'} and node.type in {
                'object_creation_expression', 'cast_expression'}:
            name = self.qualified(self.name(node.child_by_field_name('type')), node)
            if name:
                return Binding('selected-instance', name).step(node, 'type', name)
        return value

    def deletion(self, node, scopes, fields):
        super().deletion(node, scopes, fields)
        fn = node.child_by_field_name('function')
        if fn is None:
            return
        if fn.type == 'member_access_expression':
            name = self.name(fn.child_by_field_name('name'))
            receiver = fn.child_by_field_name('expression')
        elif fn.type == 'identifier':
            name, receiver = self.name(fn), None
            if self.lookup(name, scopes) is not None or name in self.local_methods:
                return
        else:
            return
        if (self.directory, name) not in self.project.names:
            return
        owner = enclosing(node, CLASSES)
        key = self.class_keys.get(owner.id) if owner is not None else None
        if not key:
            return
        if receiver is None or receiver.type == 'this':
            binding = None
        else:
            binding = self.value(receiver, scopes, fields)
        self.project.record_call(self, node, name, key, receiver, binding)


class Project:
    def __init__(self, files, *, max_files=128, max_bytes=10_000_000, max_nodes=400_000,
                 max_methods=8192, max_calls=16384, max_candidates=64):
        from polyglot_ast import _parser
        self.units = {}
        self.known = defaultdict(set)
        self.parts = defaultdict(list)
        self.nonmethods = set()
        self.members = defaultdict(list)
        self.extensions = defaultdict(list)
        self.names = set()
        self.pending = []
        self.blocked = set()
        self.problem = None
        self.max_calls, self.max_candidates = max_calls, max_candidates
        size = nodes = 0
        try:
            parser = _parser('csharp')
            for path, source in files:
                p = PurePosixPath(path)
                if p.suffix.lower() != '.cs':
                    continue
                if (p.is_absolute() or '..' in p.parts or str(p) != path or '\\' in path or ':' in path
                        or any(ord(ch) < 32 for ch in path) or path in self.units):
                    raise ValueError('C# selected path is ambiguous or invalid')
                data = source.encode()
                size += len(data)
                if len(self.units) >= max_files or size > max_bytes:
                    raise ValueError('C# selected file/byte budget exceeded')
                tree = parser.parse(data)
                nodes += tree.root_node.descendant_count
                if nodes > max_nodes:
                    raise ValueError('C# selected AST node budget exceeded')
                unit = Unit(self, path, source, tree)
                self.units[path] = unit
                self.known[unit.directory].update(unit.full_types)
                if tree.root_node.has_error:
                    self.blocked.add(unit.directory)
            count = 0
            for unit in self.units.values():
                for cls in unit.class_nodes:
                    if enclosing(cls, CLASSES) is not None:
                        continue
                    ns = unit.namespace(cls)
                    key = '.'.join(filter(None, (ns, unit.name(cls.child_by_field_name('name')))))
                    unit.class_keys[cls.id] = key
                    self.parts[unit.directory, key].append((cls, modifiers(cls)))
                    body = cls.child_by_field_name('body')
                    for method in body.named_children if body is not None else ():
                        if method.type in {'field_declaration', 'event_field_declaration'}:
                            for declaration in method.named_children:
                                for var in declaration.named_children:
                                    if var.type == 'variable_declarator':
                                        self.nonmethods.add((unit.directory, key, unit.name(var.child_by_field_name('name'))))
                        elif method.type in {'property_declaration', 'event_declaration'}:
                            self.nonmethods.add((unit.directory, key, unit.name(method.child_by_field_name('name'))))
                        elif method.type == 'method_declaration':
                            count += 1
                            if count > max_methods:
                                raise ValueError('C# selected method budget exceeded')
                            self.index_method(unit, cls, key, ns, method)
            for unit in self.units.values():
                # Conservatively respect selected sibling declarations that shadow System.IO.
                for full in self.known[unit.directory]:
                    unit.declared.add(full.rsplit('.', 1)[-1])
                unit.full_types.update(self.known[unit.directory])
                unit.walk(unit.tree.root_node, [{}], {})
                for sink, symbol, trace in unit.calls.values():
                    method = enclosing(sink, FUNCTIONS)
                    definition = unit.method_defs.get(method.id) if method is not None else None
                    if definition is not None and definition.sink is None and not unit.diagnostics:
                        definition.sink = (symbol, trace)
            for call in self.pending:
                self.link(*call)
        except (RuntimeError, RecursionError, ValueError) as error:
            self.problem = f'C# project analysis incomplete: {error}'
        self.pending.clear()

    def index_method(self, unit, cls, owner, namespace, node):
        name = unit.name(node.child_by_field_name('name'))
        params = node.child_by_field_name('parameters')
        params = [p for p in params.named_children if p.type == 'parameter'] if params else []
        ext = bool(params and b'this' in modifiers(params[0]))
        receiver = unit.qualified(unit.name(params[0].child_by_field_name('type')), params[0]) if ext else None
        mods = modifiers(node)
        cls_mods = modifiers(cls)
        eligible = (len(params) == int(ext) and (not ext or b'static' in mods and
                    bool(cls_mods & {b'static', b'partial'})) and
                    not mods.intersection({b'virtual', b'override', b'abstract', b'extern'}) and
                    not any(c.type == 'type_parameter_list' for c in (*node.named_children, *cls.named_children)))
        method = Method(unit, node, owner, namespace, receiver, eligible,
                        bool(mods & {b'public', b'internal'}), b'static' in mods, b'partial' in modifiers(cls))
        unit.method_defs[node.id] = method
        self.names.add((unit.directory, name))
        self.members[unit.directory, owner, name].append(method)
        if ext:
            self.extensions[unit.directory, name].append(method)

    def record_call(self, unit, node, name, owner, receiver, binding):
        if len(self.pending) >= self.max_calls:
            raise ValueError('C# selected call budget exceeded')
        self.pending.append((unit, node, name, owner, receiver, binding))

    def link(self, unit, node, name, owner, receiver, binding):
        directory = unit.directory
        if directory in self.blocked:
            return
        if binding is None:
            candidates = self.members.get((directory, owner, name), ())
            parts = self.parts[directory, owner]
            if len(parts) < 2 or not all(b'partial' in mods for _, mods in parts):
                return
        else:
            candidates = self.extensions.get((directory, name), ())
            if not candidates:
                return
            if len(candidates) > self.max_candidates:
                raise ValueError('C# selected candidate budget exceeded')
            _, imports, _, _ = unit.context(node)
            namespace = unit.namespace(node)
            candidates = [m for m in candidates if (m.public or m.owner == owner) and
                          (m.namespace == namespace or m.namespace in imports)]
            if not any(m.sink and m.unit is not unit for m in candidates):
                return
            if binding.kind != 'selected-instance':
                if binding.kind == 'unknown' and any(m.sink for m in candidates):
                    unit.diagnostics.add(f'C# extension receiver unresolved at line {node.start_point[0]+1}')
                return
            member = (directory, binding.name, name)
            if self.members.get(member) or member in self.nonmethods:
                return  # A selected instance member takes precedence over an extension.
            candidates = [m for m in candidates if m.receiver == binding.name and
                          (binding.name in self.known[directory] or owner == m.owner and m.partial_owner)]
            parts = self.parts.get((directory, binding.name), ())
            if any(any(c.type == 'base_list' for c in part.named_children) for part, _ in parts):
                if any(m.sink for m in candidates):
                    unit.diagnostics.add('C# inherited receiver members are unresolved')
                return
        if len(candidates) > self.max_candidates:
            raise ValueError('C# selected candidate budget exceeded')
        if not any(m.sink for m in candidates):
            return
        if len(candidates) != 1:
            unit.diagnostics.add(f'C# method candidates ambiguous at line {node.start_point[0]+1}')
            return
        method = candidates[0]
        if method.unit is unit:
            return
        args = node.child_by_field_name('arguments')
        owner_parts = self.parts[directory, method.owner]
        if any(b'file' in mods for _, mods in owner_parts) or (
                len(owner_parts) > 1 and not all(b'partial' in mods for _, mods in owner_parts)):
            return
        if not method.eligible or args is None or any(c.type == 'argument' for c in args.named_children):
            unit.diagnostics.add(f'C# wrapper signature unresolved at line {node.start_point[0]+1}')
            return
        if binding is None and (method.receiver or receiver is not None and method.static):
            return
        symbol, native = method.sink
        route = [(unit.path, line, kind, message) for line, kind, message in (binding.trace if binding else ())]
        route.append((unit.path, node.start_point[0]+1, 'call', name))
        route.append((method.unit.path, method.node.start_point[0]+1, 'definition', method.owner + '.' + name))
        route.extend((method.unit.path, line, kind, message) for line, kind, message in native)
        unit.links[node.start_byte] = (node, symbol, route)

    def tree(self, path):
        unit = self.units.get(path)
        return unit.tree if unit is not None else None

    def calls(self, path):
        unit = self.units.get(path)
        if self.problem or unit is None:
            return {}, {self.problem or 'C# project file unavailable'}
        diagnostics = set(unit.diagnostics)
        if unit.directory in self.blocked:
            diagnostics.add('C# project links unavailable after syntax recovery')
        native = {pos: (node, symbol, [(path, line, kind, msg) for line, kind, msg in hops])
                  for pos, (node, symbol, hops) in unit.calls.items()}
        return {**native, **unit.links}, diagnostics
