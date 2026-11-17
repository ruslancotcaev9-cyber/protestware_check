"""Bounded static JS/TS module links over selected text only. Never loads code."""
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re

from js_bindings import Resolver, State, UNKNOWN, FS, PROMISES, PROCESS, MODULES, METHODS, PROMISE_METHODS, EXEC_METHODS, FUNCTIONS, DELETIONS, string

SUFFIXES = {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'}
TYPESCRIPT = {'.ts', '.tsx'}


def step(path, node, kind, message):
    return (path, node.start_point[0] + 1, kind, message[:160])


def trace_dict(items):
    bounded = items if len(items) <= 24 else (*items[:23], items[-1])
    return [{'file': path, 'line': line, 'kind': kind, 'message': message} for path, line, kind, message in bounded]


@dataclass
class Unit:
    path: str
    source: str
    tree: object = None
    state: object = None
    exports: dict = field(default_factory=dict)
    stars: list = field(default_factory=list)
    cjs: object = None
    module_object: object = None
    mutable: set = field(default_factory=set)
    diagnostics: set = field(default_factory=set)
    events: list = field(default_factory=list)
    invalid_exports: bool = False
    esm: bool = False


class Project:
    def __init__(self, files, *, max_modules=256, max_bytes=10_000_000,
                 max_nodes=500_000, max_edges=2048, max_depth=24, max_contexts=2048):
        self.units, self.refs, self.ref_keys, self.objects, self.functions = {}, {}, {}, {}, {}
        self.queue, self.edges = deque(), defaultdict(set)
        self.max_nodes, self.max_edges, self.max_depth, self.max_contexts = max_nodes, max_edges, max_depth, max_contexts
        self.nodes = self.contexts = 0
        self.resolutions = 0
        self.global_diagnostics = set()
        self.effect_cache, self.results_cache = {}, {}
        self.invalid_objects = set()
        total = 0
        for path, source in files:
            if PurePosixPath(path).suffix.lower() not in SUFFIXES or path.endswith('.d.ts'):
                continue
            if not self.canonical(path):
                self.global_diagnostics.add('JS module input path is not canonical inside the project')
                continue
            if path in self.units:
                self.global_diagnostics.add('JS module input path is duplicated')
                continue
            size = len(source.encode('utf-8'))
            if len(self.units) >= max_modules or total + size > max_bytes:
                self.global_diagnostics.add('JS module file/byte budget exceeded')
                break
            total += size
            self.units[path] = Unit(path, source)
        self.bytes = total
        try:
            from polyglot_ast import _parser, GRAMMARS
            for unit in self.units.values():
                try:
                    unit.tree = _parser(GRAMMARS[PurePosixPath(unit.path).suffix.lower()]).parse(unit.source.encode('utf-8'))
                    if unit.tree is None:
                        raise RuntimeError('no syntax tree')
                    if unit.tree.root_node.has_error:
                        unit.diagnostics.add('JS module syntax recovery')
                    worker = Worker(self, unit)
                    worker.index()
                except (ValueError, RuntimeError, OSError, RecursionError):
                    unit.diagnostics.add('JS module indexing unavailable or budget exceeded')
            while self.queue:
                identifier = self.queue.popleft()
                function = self.functions[identifier]
                unit = self.units[function['path']]
                try:
                    Worker(self, unit, identifier).function_body(function)
                except (ValueError, RuntimeError, RecursionError):
                    unit.diagnostics.add('JS module function indexing budget exceeded')
            self.check_import_cycles()
            # Finish bounded summaries before scan_text records per-file completeness.
            for path in self.units:
                self.calls(path)
        except (ValueError, RuntimeError, RecursionError):
            self.global_diagnostics.add('JS module analysis budget exceeded')

    @staticmethod
    def canonical(path):
        return (isinstance(path, str) and 0 < len(path) <= 4096 and
                not any(ord(c) < 32 for c in path) and not any(c in path for c in '\\:') and
                not path.startswith('/') and '..' not in PurePosixPath(path).parts and
                str(PurePosixPath(path)) == path)

    def ref(self, kind, *values):
        key = (kind, *values)
        if key not in self.ref_keys:
            if len(self.refs) >= 20000:
                raise ValueError('JS symbolic value budget exceeded')
            identifier = '@' + str(len(self.refs))
            self.ref_keys[key] = identifier
            self.refs[identifier] = key
        return self.ref_keys[key]

    def alias(self, values, route):
        return frozenset({self.ref('alias', tuple(sorted(values)), tuple(route))})

    def property(self, values, key):
        return frozenset({self.ref('property', tuple(sorted(values)), key)}) if key else UNKNOWN

    def module(self, unit, specifier, node, *, require=False):
        if specifier in MODULES:
            value = MODULES[specifier] if require else self.ref('native-namespace', MODULES[specifier])
            return self.alias({value}, (step(unit.path, node, 'import', specifier),))
        if not specifier or not specifier.startswith(('./', '../')):
            return UNKNOWN
        if any(c in specifier for c in '\\:%?#') or any(ord(c) < 32 for c in specifier):
            unit.diagnostics.add('JS local module specifier is unsupported')
            return UNKNOWN
        parts = list(PurePosixPath(unit.path).parent.parts)
        for part in specifier.split('/'):
            if part in ('', '.'):
                continue
            if part == '..':
                if not parts:
                    unit.diagnostics.add('JS local module reference escapes the selected project')
                    return UNKNOWN
                parts.pop()
            else:
                parts.append(part)
        target = '/'.join(parts)
        suffix = PurePosixPath(target).suffix.lower()
        if suffix and suffix not in SUFFIXES:
            return UNKNOWN
        candidates = {target} if suffix else set()
        is_ts = PurePosixPath(unit.path).suffix.lower() in TYPESCRIPT
        if is_ts and suffix == '.js':
            candidates.update(target[:-len(suffix)] + ext for ext in ('.ts', '.tsx'))
        if not suffix and (require or is_ts):
            extensions = {'.js', '.jsx', '.ts', '.tsx'} if is_ts else {'.js'}
            candidates.update(target + ext for ext in extensions)
            candidates.update(target + '/index' + ext for ext in extensions)
        found = sorted(candidates.intersection(self.units))
        if len(found) != 1:
            unit.diagnostics.add('JS local module is absent from selected files or ambiguous')
            return UNKNOWN
        target = found[0]
        self.edges[unit.path].add(target)
        if sum(map(len, self.edges.values())) > self.max_edges:
            raise ValueError('JS import edge budget exceeded')
        value = self.ref('require' if require else 'namespace', target)
        return self.alias({value}, (step(unit.path, node, 'import', specifier),))

    def function(self, unit, node, state):
        identifier = self.ref('function', unit.path, node.start_byte)
        if identifier not in self.functions:
            self.functions[identifier] = {'path': unit.path, 'node': node,
                                          'scopes': list(state.scopes), 'events': [], 'defaults': []}
            self.queue.append(identifier)
        return identifier

    def resolve(self, values, bindings=None, seen=(), route=()):
        bindings = bindings or {}
        output = []
        for value in values:
            self.resolutions += 1
            if self.resolutions > 200000:
                self.global_diagnostics.add('JS symbolic resolution work budget exceeded')
                break
            if value in seen or len(seen) >= self.max_depth * 3:
                if value in self.refs:
                    self.global_diagnostics.add('JS symbolic resolution cycle/depth limit reached')
                continue
            item = self.refs.get(value)
            if item is None or item[0] in {'function', 'object', 'module-object'}:
                output.append((value, route))
                continue
            kind = item[0]
            visited = (*seen, value)
            if kind == 'alias':
                output.extend(self.resolve(item[1], bindings, visited, (*route, *item[2])))
            elif kind == 'parameter':
                output.extend(self.resolve(bindings.get(value, UNKNOWN), bindings, visited, route))
            elif kind == 'binding':
                unit, name = self.units[item[1]], item[2]
                if name in unit.mutable:
                    unit.diagnostics.add('JS mutable export identity is unresolved')
                elif unit.state is not None:
                    output.extend(self.resolve(unit.state.scopes[0].get(name, UNKNOWN), bindings, visited, route))
            elif kind == 'require':
                unit = self.units[item[1]]
                if unit.esm:
                    unit.diagnostics.add('JS require of an ESM source module is unsupported')
                elif not unit.invalid_exports:
                    output.extend(self.resolve(unit.cjs or UNKNOWN, bindings, visited, route))
            elif kind in {'namespace', 'native-namespace'}:
                output.append((value, route))
            elif kind == 'property':
                for base, hops in self.resolve(item[1], bindings, visited, route):
                    output.extend(self.get_property(base, item[2], bindings, visited, hops))
        return output[:32]

    def get_property(self, base, key, bindings, seen, route):
        item = self.refs.get(base)
        if item and item[0] == 'native-namespace':
            return [(item[1], route)] if key == 'default' else self.get_property(item[1], key, bindings, seen, route)
        if base in (FS, PROMISES, PROCESS):
            target = (PROMISES if base == FS and key == 'promises' else
                      base + '.' + key if (base == FS and key in METHODS) or
                      (base == PROMISES and key in PROMISE_METHODS) or (base == PROCESS and key in EXEC_METHODS) else '')
            return [(target, route)]
        if item and item[0] == 'namespace':
            unit = self.units[item[1]]
            if unit.invalid_exports:
                return []
            if key in unit.exports:
                return self.resolve(unit.exports[key], bindings, seen, route)
            if unit.cjs and not unit.esm:
                if key == 'default':
                    return self.resolve(unit.cjs, bindings, seen, route)
                return [result for value, hops in self.resolve(unit.cjs, bindings, seen, route)
                        for result in self.get_property(value, key, bindings, seen, hops)]
            if key != 'default':
                matches = [self.resolve(self.property(values, key), bindings, seen, route) for values in unit.stars]
                matches = [[entry for entry in found if entry[0]] for found in matches]
                matches = [found for found in matches if found]
                if len(matches) > 1:
                    unit.diagnostics.add('JS star export identity is ambiguous')
                    return []
                return matches[0] if matches else []
        if item and item[0] in {'object', 'module-object'} and base not in self.invalid_objects:
            return self.resolve(self.objects[base].get(key, UNKNOWN), bindings, seen, route)
        return []

    def effects(self, values, arguments, bindings=None, active=()):
        bindings = bindings or {}
        found = {}
        for value, route in self.resolve(values, bindings):
            if value in DELETIONS:
                found.setdefault(value, route)
            elif value in self.functions:
                function = self.functions[value]
                unit = self.units[function['path']]
                parameters = function.get('parameters', [])
                incoming = dict(bindings)
                for index, token in enumerate(parameters):
                    source = arguments[index] if index < len(arguments) else function['defaults'][index]
                    incoming[token] = frozenset().union(*(self.alias({v}, hops) if hops else {v}
                                                         for v, hops in self.resolve(source, bindings))) or UNKNOWN
                key = (value, tuple(sorted((token, tuple(sorted(vals))) for token, vals in incoming.items())))
                if key in active or len(active) >= self.max_depth:
                    unit.diagnostics.add('JS module call recursion/depth limit reached')
                    continue
                if key not in self.effect_cache:
                    self.contexts += 1
                    if self.contexts > self.max_contexts:
                        self.global_diagnostics.add('JS module call context budget exceeded')
                        continue
                    effects = {}
                    for event in function['events']:
                        for symbol, hops in self.event_effects(event, incoming, (*active, key)).items():
                            effects.setdefault(symbol, hops)
                    self.effect_cache[key] = effects
                declaration = step(unit.path, function['node'], 'call', 'local function wrapper')
                for symbol, hops in self.effect_cache[key].items():
                    found.setdefault(symbol, (*route, declaration, *hops))
        return found

    def event_effects(self, event, bindings=None, active=()):
        unit, node, callee, args, blocked = event
        effects = self.effects(callee, args, bindings, active)
        return {symbol: (step(unit.path, node, 'call', symbol), *hops,
                         *((step(unit.path, node, 'sink', symbol),) if not hops or hops[-1][2] != 'sink' else ()))
                for symbol, hops in effects.items()
                if not any(symbol == prefix or symbol.startswith(prefix + '.') for prefix in blocked)}

    def check_import_cycles(self):
        done = set()
        def walk(path, active):
            if path in active:
                for name in active[active.index(path):]:
                    self.units[name].diagnostics.add('JS local import cycle is unresolved')
                return
            if path in done:
                return
            if len(active) >= self.max_depth:
                self.units[path].diagnostics.add('JS import depth limit reached')
                return
            for child in sorted(self.edges[path]):
                walk(child, (*active, path))
            done.add(path)
        for path in self.units:
            walk(path, ())

    def diagnostics(self, path):
        result = set(self.global_diagnostics)
        todo, seen = [path], set()
        while todo:
            current = todo.pop()
            if current in seen or current not in self.units:
                continue
            seen.add(current)
            result.update(self.units[current].diagnostics)
            todo.extend(self.edges[current])
        return result

    def tree(self, path):
        unit = self.units.get(path)
        return unit.tree if unit is not None else None

    def calls(self, path):
        if path not in self.results_cache:
            output = {}
            unit = self.units.get(path)
            if unit:
                events = [*unit.events, *(event for fn in self.functions.values() if fn['path'] == path for event in fn['events'])]
                for event in events:
                    try:
                        effects = self.event_effects(event)
                    except (ValueError, RecursionError):
                        self.global_diagnostics.add('JS module call analysis budget exceeded')
                        break
                    if effects:
                        node = event[1]
                        symbol = sorted(effects)[0]
                        route = effects[symbol]
                        output[node.start_byte] = (node, symbol, trace_dict(route))
            self.results_cache[path] = output
        return self.results_cache[path], self.diagnostics(path)

    def metadata(self):
        return {'mode': 'selected-text-only', 'modules': len(self.units), 'bytes': self.bytes,
                'import_edges': sum(map(len, self.edges.values())), 'function_contexts': self.contexts,
                'complete': not self.global_diagnostics and not any(u.diagnostics for u in self.units.values())}


class Worker(Resolver):
    def __init__(self, project, unit, owner=None):
        super().__init__(unit.source)
        self.project, self.unit, self.owner = project, unit, owner

    def lookup(self, name, state):
        if self.owner is not None and name in self.unit.mutable and not any(name in scope for scope in state.scopes[1:]):
            return UNKNOWN
        return super().lookup(name, state)

    def property(self, values, key, state):
        if not key:
            return UNKNOWN
        # Local object property reads snapshot the value at the source location.
        output = set()
        for value in values:
            if value in self.project.objects and value not in self.project.invalid_objects:
                output.update(self.project.objects[value].get(key, UNKNOWN))
            else:
                output.update(self.project.property({value}, key))
        return frozenset(output) or UNKNOWN

    def value(self, node, state, depth=0):
        if depth > 30:
            self.unit.diagnostics.add('JS module value depth limit reached')
            return UNKNOWN
        if node is None:
            return UNKNOWN
        if node.type in FUNCTIONS:
            return frozenset({self.project.function(self.unit, node, state)})
        if node.type in {'true', 'false'}:
            return frozenset({'bool:' + node.type})
        if node.type == 'shorthand_property_identifier':
            return self.lookup(self.name(node), state)
        if node.type == 'object':
            identifier = self.project.ref('object', self.unit.path, node.start_byte)
            if identifier not in self.project.objects:
                fields = {}
                for child in node.named_children:
                    if child.type == 'pair':
                        key = child.child_by_field_name('key')
                        label = string(self.raw(key)) if key.type == 'string' else self.name(key)
                        if key.type not in {'property_identifier', 'identifier', 'string', 'number'}:
                            self.project.invalid_objects.add(identifier)
                            self.unit.diagnostics.add('JS object spread/computed member identity is unresolved')
                            continue
                        fields[label] = self.value(child.child_by_field_name('value'), state, depth + 1)
                    elif child.type == 'shorthand_property_identifier':
                        fields[self.name(child)] = self.lookup(self.name(child), state)
                    elif child.type == 'method_definition':
                        key = child.child_by_field_name('name')
                        if key is not None and key.type in {'property_identifier', 'identifier', 'string'}:
                            label = string(self.raw(key)) if key.type == 'string' else self.name(key)
                            fields[label] = UNKNOWN if re.match(r'\s*(?:get|set)\s', self.raw(child)) else self.value(child, state, depth + 1)
                        else:
                            self.project.invalid_objects.add(identifier)
                            self.unit.diagnostics.add('JS object spread/computed member identity is unresolved')
                    elif child.type == 'spread_element':
                        self.project.invalid_objects.add(identifier)
                        self.unit.diagnostics.add('JS object spread/computed member identity is unresolved')
                self.project.objects[identifier] = fields
            return frozenset({identifier})
        if node.type == 'call_expression':
            function, arguments = node.child_by_field_name('function'), node.child_by_field_name('arguments')
            if self.value(function, state, depth + 1) == frozenset({'global:require'}) and arguments is not None:
                args = arguments.named_children
                specifier = string(self.raw(args[0])) if len(args) == 1 else None
                return self.project.module(self.unit, specifier, node, require=True)
            # Function return values/factories are deliberately not inferred.
            return UNKNOWN
        return super().value(node, state, depth)

    def predeclare(self, node, state, hoisted=False):
        super().predeclare(node, state, hoisted)
        if not hoisted:
            for child in node.named_children:
                declaration = child.child_by_field_name('declaration') if child.type == 'export_statement' else child
                if declaration is not None and declaration.type in FUNCTIONS:
                    self.bind(declaration.child_by_field_name('name'), self.value(declaration, state), state, len(state.scopes) - 1)

    def imports(self, root, state):
        for node in root.named_children:
            if node.type != 'import_statement' or re.match(r'\s*import\s+type\b', self.raw(node)):
                continue
            source = string(self.raw(node.child_by_field_name('source')))
            runtime = [clause for clause in node.named_children if clause.type == 'import_clause']
            if runtime and all(child.type == 'named_imports' and all(re.match(r'type\s+(?!as\b)', self.raw(spec)) for spec in child.named_children) for clause in runtime for child in clause.named_children):
                continue
            values = self.project.module(self.unit, source, node)
            for clause in runtime:
                for child in clause.named_children:
                    if child.type == 'identifier':
                        self.bind(child, self.property(values, 'default', state), state, 0)
                    elif child.type == 'namespace_import':
                        self.bind(child.named_children[-1], values, state, 0)
                    elif child.type == 'named_imports':
                        for spec in child.named_children:
                            if spec.type != 'import_specifier' or re.match(r'type\s+(?!as\b)', self.raw(spec)):
                                continue
                            name = spec.child_by_field_name('name')
                            key = string(self.raw(name)) if name.type == 'string' else self.name(name)
                            self.bind(spec.child_by_field_name('alias') or name, self.property(values, key, state), state, 0)

    def index(self):
        root = self.unit.tree.root_node
        self.unit.esm = any(node.type in {'import_statement', 'export_statement'} for node in root.named_children)
        exports = self.project.ref('object', self.unit.path, 'exports')
        module = self.project.ref('module-object', self.unit.path)
        self.project.objects[exports] = {}
        self.project.objects[module] = {'exports': frozenset({exports})}
        self.unit.cjs, self.unit.module_object = frozenset({exports}), module
        state = State([{'require': frozenset({'global:require'}), 'exports': frozenset({exports}), 'module': frozenset({module})}])
        self.unit.state = state
        self.predeclare(root, state, hoisted=True)
        self.predeclare(root, state)
        self.imports(root, state)
        for node in root.named_children:
            declaration = node.child_by_field_name('declaration') if node.type == 'export_statement' else node
            if declaration is not None and declaration.type in {'variable_declaration', 'lexical_declaration'} and not self.raw(declaration).lstrip().startswith('const '):
                for child in declaration.named_children:
                    if child.type == 'variable_declarator' and child.child_by_field_name('name').type == 'identifier':
                        self.unit.mutable.add(self.name(child.child_by_field_name('name')))
            self.walk(node, state)

    def function_body(self, function):
        node = function['node']
        state = State([dict(scope) for scope in function['scopes']])
        state.scopes.append({}); state.function = len(state.scopes) - 1
        self.bind(node.child_by_field_name('name'), {self.owner}, state, state.function)
        params = node.child_by_field_name('parameters')
        parameters = params.named_children if params is not None else [node.child_by_field_name('parameter')]
        tokens, defaults = [], []
        for index, parameter in enumerate(parameters):
            if parameter is None or parameter.type == 'comment':
                continue
            token = self.project.ref('parameter', self.owner, index)
            tokens.append(token)
            target = parameter
            if target.type in {'required_parameter', 'optional_parameter'}:
                default_node = target.child_by_field_name('value')
                target = target.child_by_field_name('pattern') or target.child_by_field_name('name')
            else:
                default_node = None
            default = self.value(default_node, state) if default_node is not None else UNKNOWN
            if target is not None and target.type == 'assignment_pattern':
                default = self.value(target.child_by_field_name('right'), state)
                target = target.child_by_field_name('left')
            self.bind(target, {token}, state, state.function)
            defaults.append(default)
        function['parameters'], function['defaults'] = tokens, defaults
        body = node.child_by_field_name('body')
        if body is not None:
            self.predeclare(body, state, hoisted=True)
            self.walk(body, state)

    def export(self, node, state):
        if re.match(r'\s*export\s+type\b', self.raw(node)):
            return
        declaration, value = node.child_by_field_name('declaration'), node.child_by_field_name('value')
        source = node.child_by_field_name('source')
        is_default = bool(re.match(r'\s*export\s+default\b', self.raw(node)))
        if declaration is not None:
            self.walk(declaration, state)
            if is_default:
                self.unit.exports['default'] = self.value(declaration, state)
            else:
                names = []
                if declaration.type in FUNCTIONS:
                    names = [declaration.child_by_field_name('name')]
                elif declaration.type in {'variable_declaration', 'lexical_declaration'}:
                    names = [item.child_by_field_name('name') for item in declaration.named_children if item.type == 'variable_declarator']
                for name in names:
                    if name is not None and name.type == 'identifier':
                        self.unit.exports[self.name(name)] = self.project.alias({self.project.ref('binding', self.unit.path, self.name(name))}, (step(self.unit.path, node, 'export', self.name(name)),))
        elif value is not None:
            self.walk(value, state)
            self.unit.exports['default'] = self.value(value, state)
        else:
            provider = self.project.module(self.unit, string(self.raw(source)), node) if source is not None else None
            clause = next((child for child in node.named_children if child.type == 'export_clause'), None)
            namespace = next((child for child in node.named_children if child.type == 'namespace_export'), None)
            if clause is not None:
                for spec in clause.named_children:
                    if spec.type != 'export_specifier' or re.match(r'type\s+(?!as\b)', self.raw(spec)):
                        continue
                    name = spec.child_by_field_name('name')
                    alias = spec.child_by_field_name('alias') or name
                    values = self.property(provider, self.name(name), state) if provider is not None else {self.project.ref('binding', self.unit.path, self.name(name))}
                    self.unit.exports[self.name(alias)] = self.project.alias(values, (step(self.unit.path, node, 'export', self.name(alias)),))
            elif namespace is not None and provider is not None:
                self.unit.exports[self.name(namespace.named_children[-1])] = provider
            elif provider is not None:
                self.unit.stars.append(provider)

    def walk(self, node, state, depth=0):
        if node is None:
            return
        self.project.nodes += 1
        if self.project.nodes > self.project.max_nodes or depth > 250:
            raise ValueError('JS project node/depth budget exceeded')
        kind = node.type
        if kind in FUNCTIONS:
            self.project.function(self.unit, node, state)
            return
        if kind == 'export_statement' and self.owner is None and node.parent.type == 'program':
            self.export(node, state)
            return
        if kind == 'statement_block':
            state = State([*state.scopes, {}], state.function, state.modified)
            self.predeclare(node, state)
            for child in node.named_children:
                self.walk(child, state, depth + 1)
                if child.type in {'return_statement', 'throw_statement'}:
                    break
            return
        if kind in {'if_statement', 'while_statement'}:
            condition = node.child_by_field_name('condition')
            value = self.value(condition, state)
            if value in (frozenset({'bool:true'}), frozenset({'bool:false'})):
                self.walk(condition, state, depth + 1)
                if kind == 'if_statement':
                    self.walk(node.child_by_field_name('consequence' if 'bool:true' in value else 'alternative'), state, depth + 1)
                elif 'bool:true' in value:
                    self.walk(node.child_by_field_name('body'), state, depth + 1)
                return
        if kind == 'binary_expression':
            operator = self.raw(node.child_by_field_name('operator'))
            left = node.child_by_field_name('left')
            value = self.value(left, state)
            if (operator == '&&' and value == frozenset({'bool:false'})) or (operator == '||' and value == frozenset({'bool:true'})):
                self.walk(left, state, depth + 1)
                return
        if kind in {'assignment_expression', 'augmented_assignment_expression', 'update_expression'} or (
                kind == 'unary_expression' and self.raw(node.child_by_field_name('operator')) == 'delete'):
            left = node.child_by_field_name('left') or node.child_by_field_name('argument')
            right = node.child_by_field_name('right')
            if left is not None and left.type in {'member_expression', 'subscript_expression'}:
                if right is not None:
                    self.walk(right, state, depth + 1)
                obj = self.value(left.child_by_field_name('object'), state)
                key = self.name(left.child_by_field_name('property')) if left.type == 'member_expression' else string(self.raw(left.child_by_field_name('index')))
                for target in obj:
                    if target in self.project.objects:
                        if self.owner is None and node.parent.type == 'expression_statement' and node.parent.parent.type == 'program' and key:
                            values = self.value(right, state) if kind == 'assignment_expression' else UNKNOWN
                            if target == self.unit.module_object or target == self.project.ref('object', self.unit.path, 'exports'):
                                values = self.project.alias(values, (step(self.unit.path, node, 'export', key),))
                            self.project.objects[target][key] = values
                            if target == self.unit.module_object and key == 'exports':
                                self.unit.cjs = values
                        else:
                            self.project.invalid_objects.add(target)
                            self.unit.invalid_exports = True
                            self.unit.diagnostics.add('JS conditional/function object export mutation is unresolved')
                    else:
                        resolved = [v for v, _ in self.project.resolve(obj)]
                        native = [v if v in {FS, PROMISES, PROCESS} else self.project.refs[v][1]
                                  for v in resolved if v in {FS, PROMISES, PROCESS} or
                                  self.project.refs.get(v, ('',))[0] == 'native-namespace']
                        if native:
                            state.modified.update(v + '.' + key if key else v for v in native)
                            self.unit.invalid_exports = True
                            self.unit.diagnostics.add('JS native module property mutation is unresolved across files')
                return
        if kind == 'call_expression':
            args = node.child_by_field_name('arguments')
            event = (self.unit, node, self.value(node.child_by_field_name('function'), state),
                     [self.value(child, state) for child in args.named_children] if args is not None else [], frozenset(state.modified))
            (self.unit.events if self.owner is None else self.project.functions[self.owner]['events']).append(event)
        super().walk(node, state, depth)
        self.unit.diagnostics.update(self.diagnostics)
