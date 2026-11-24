"""Resolve short paths from Python calls to explicitly imported network operations."""
from __future__ import annotations

import ast
from collections import defaultdict
from inspect import Parameter, Signature
from typing import NamedTuple


NETWORK_APIS = {f"{module}.{method}" for module in ("requests", "httpx")
                for method in ("get", "post", "put", "delete", "patch", "request", "head")}
NETWORK_APIS.update({"urllib.request.urlopen", "aiohttp.request"})
DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def scope_nodes(body):
    """Walk one lexical scope. Nested definitions bind names but have separate bodies."""
    pending = list(body)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, DEFINITIONS):
            # Defaults, decorators and bases can bind a name in the containing scope.
            pending.extend(child for child in ast.iter_child_nodes(node) if not isinstance(child, ast.stmt))
        elif isinstance(node, ast.Lambda):
            pending.extend(node.args.defaults)
            pending.extend(value for value in node.args.kw_defaults if value is not None)
        else:
            pending.extend(ast.iter_child_nodes(node))


def imports(node):
    for alias in node.names:
        if isinstance(node, ast.Import):
            root = alias.name.split(".")[0]
            yield alias.asname or root, alias.name if alias.asname else root
        else:
            yield alias.asname or alias.name, None if node.level else f"{node.module}.{alias.name}"


def bound_names(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        yield node.id
    elif isinstance(node, DEFINITIONS):
        yield node.name
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from (name for name, _ in imports(node))
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
        yield node.name
    elif isinstance(node, ast.MatchMapping) and node.rest:
        yield node.rest
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from node.names


def dotted_reference(node):
    """An attribute chain with a name at its root, without calls or subscripts."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return (node.id, *reversed(parts)) if isinstance(node, ast.Name) else ()


def signature(args):
    """Build a signature from syntax only. Defaults are placeholders."""
    params = []
    positional = [*args.posonlyargs, *args.args]
    required = len(positional) - len(args.defaults)
    for i, arg in enumerate(positional):
        kind = Parameter.POSITIONAL_ONLY if i < len(args.posonlyargs) else Parameter.POSITIONAL_OR_KEYWORD
        params.append(Parameter(arg.arg, kind, default=Parameter.empty if i < required else None))
    if args.vararg:
        params.append(Parameter(args.vararg.arg, Parameter.VAR_POSITIONAL))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        params.append(Parameter(arg.arg, Parameter.KEYWORD_ONLY, default=Parameter.empty if default is None else None))
    if args.kwarg:
        params.append(Parameter(args.kwarg.arg, Parameter.VAR_KEYWORD))
    return Signature(params)


class Route(NamedTuple):
    steps: tuple[tuple[int, str], ...]
    available: tuple[int, int]   # Latest module declaration needed at a top-level call.


class LocalNetworkCalls:
    """Use unique module bindings. Keep one direct sink or one intermediate call."""

    def __init__(self, tree):
        self.module = tree
        self.symbols = {}
        self.declared = {}
        self.locals = {}
        self.functions = {}
        self.direct = {}
        self.edges = defaultdict(list)
        self.guarded = []
        top = set(tree.body)
        blocked = set()
        for node in scope_nodes(tree.body):
            if node in top and isinstance(node, ast.FunctionDef) and not node.decorator_list:
                bindings = [(node.name, node)]
            elif node in top and isinstance(node, (ast.Import, ast.ImportFrom)):
                bindings = imports(node)
            else:
                blocked.update(bound_names(node))
                continue
            for name, value in bindings:
                if value is None or name == "*" or (name in self.symbols and self.symbols[name] != value):
                    blocked.add(name)
                self.symbols[name] = value
                self.declared[name] = min(self.declared.get(name, (node.lineno, node.col_offset)),
                                          (node.lineno, node.col_offset))
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                blocked.update(node.names)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                ref = dotted_reference(node)
                if ref:
                    blocked.add(ref[0])
        if "*" in blocked:
            self.symbols.clear()
        for name in blocked:
            self.symbols.pop(name, None)
        for fn in self.symbols.values():
            if not isinstance(fn, ast.FunctionDef):
                continue
            names = {arg.arg for arg in ast.iter_child_nodes(fn.args) if isinstance(arg, ast.arg)}
            generator = False
            for node in scope_nodes(fn.body):
                names.update(bound_names(node))
                if isinstance(node, (ast.Yield, ast.YieldFrom)):
                    generator = True
            self.locals[fn] = names
            if not generator:
                try:
                    self.functions[fn] = signature(fn.args)
                except ValueError:
                    pass  # ast.parse also accepts some invalid parameter lists.

    def observe(self, scope, call, guard, network):
        if scope is not self.module and scope not in self.functions:
            return
        ref = dotted_reference(call.func)
        if not ref or ref[0] not in self.symbols or ref[0] in self.locals.get(scope, ()):
            return
        origin = self.symbols[ref[0]]
        declared = self.declared[ref[0]]
        if scope is self.module and (call.lineno, call.col_offset) <= declared:
            return
        if isinstance(origin, str):
            target = ".".join((origin, *ref[1:]))
            if network and scope in self.functions and target in NETWORK_APIS:
                self.direct.setdefault(scope, Route(((call.lineno, target),), declared))
        elif len(ref) == 1 and origin in self.functions and origin is not scope:
            keywords = {kw.arg: None for kw in call.keywords}
            if (None in keywords or len(keywords) != len(call.keywords)
                    or any(isinstance(a, ast.Starred) for a in call.args)):
                return
            try:
                self.functions[origin].bind(*([None] * len(call.args)), **keywords)
            except TypeError:
                return
            if guard is not None:
                self.guarded.append((scope, call, guard, origin))
            if scope in self.functions:
                self.edges[scope].append((call, origin))

    def paths(self):
        routes = self.direct.copy()
        for fn, edges in self.edges.items():
            if fn in routes:
                continue
            for call, inner in edges:
                if inner in self.direct:
                    tail = self.direct[inner]
                    steps = ((call.lineno, inner.name), *tail.steps)
                    routes[fn] = Route(steps, max(self.declared[inner.name], tail.available))
                    break
        for scope, call, guard, fn in self.guarded:
            route = routes.get(fn)
            if route and (scope is not self.module or (call.lineno, call.col_offset) > route.available):
                yield call, guard, ((call.lineno, fn.name), *route.steps)
