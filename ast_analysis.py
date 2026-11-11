"""Python AST heuristics: no imports or execution of inspected source code."""
from __future__ import annotations

import ast
from pathlib import Path
from urllib.parse import urlparse

GEO_COUNTRIES = {"RU", "RUS", "BY", "BLR", "RUSSIA", "BELARUS", "РОССИЯ", "РОССИИ", "БЕЛАРУСЬ"}
GEO_WORDS = ("country", "region", "geoip", "geolocation", "locale", "location", "ipapi", "ipinfo")
GEO_HOSTS = {"ip-api.com", "ipapi.co", "ipinfo.io", "ipwho.is", "ipgeolocation.io", "freegeoip.app"}
NETWORK_FUNCTIONS = {"get", "post", "put", "delete", "patch", "request", "head", "urlopen"}
DELETE_CALLS = {"os.remove", "os.unlink", "shutil.rmtree", "pathlib.Path.unlink", "pathlib.Path.rmdir"}
WRITE_CALLS = {"os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copyfile",
               "pathlib.Path.write_text", "pathlib.Path.write_bytes", "pathlib.Path.rename", "pathlib.Path.replace"}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and all(isinstance(x, ast.Constant) and isinstance(x.value, str) for x in node.values):
        return "".join(x.value for x in node.values)
    return None


class Analyzer(ast.NodeVisitor):
    def __init__(self, path: str, content: str, allowed_domains: list[str]):
        self.path = path
        self.content = content
        self.lines = content.splitlines()
        self.allowed = allowed_domains
        self.aliases: dict[str, str] = {}
        self.geo_flags: set[str] = set()
        self.constants: dict[str, bool] = {}
        self.geo_conditions: list[int] = []
        self.findings: list[dict] = []
        self._seen: set[tuple[str, int]] = set()

    def add(self, rule: str, category: str, severity: str, node: ast.AST, message: str):
        line = getattr(node, "lineno", 1)
        key = (rule, line)
        if key in self._seen:
            return
        self._seen.add(key)
        excerpt = ast.get_source_segment(self.content, node)
        evidence = (excerpt or (self.lines[line - 1] if 0 < line <= len(self.lines) else "")).strip()
        self.findings.append({"rule": rule, "category": category, "severity": severity,
                              "file": self.path, "line": line, "evidence": evidence[:240],
                              "message": message, "analysis": "ast"})

    def resolve(self, name: str) -> str:
        parts = name.split(".")
        if parts and parts[0] in self.aliases:
            return ".".join((self.aliases[parts[0]], *parts[1:]))
        return name

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Local Boolean aliases/imports must not contaminate unrelated functions.
        aliases, flags, constants, conditions = self.aliases, self.geo_flags, self.constants, self.geo_conditions
        self.aliases, self.geo_flags, self.constants, self.geo_conditions = aliases.copy(), set(), {}, []
        try:
            self.generic_visit(node)
        finally:
            self.aliases, self.geo_flags, self.constants, self.geo_conditions = aliases, flags, constants, conditions

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        aliases, flags, constants, conditions = self.aliases, self.geo_flags, self.constants, self.geo_conditions
        self.aliases, self.geo_flags, self.constants, self.geo_conditions = aliases.copy(), set(), {}, []
        try:
            self.generic_visit(node)
        finally:
            self.aliases, self.geo_flags, self.constants, self.geo_conditions = aliases, flags, constants, conditions

    def visit_Import(self, node: ast.Import):
        for item in node.names:
            if item.asname:
                self.aliases[item.asname] = item.name
            else:
                self.aliases[item.name.split(".")[0]] = item.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.level:
            return
        module = node.module or ""
        for item in node.names:
            if item.name != "*":
                self.aliases[item.asname or item.name] = f"{module}.{item.name}"

    def truth(self, node: ast.AST) -> bool | None:
        """Only fold literal truth values and their Boolean aliases; never eval."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.truth(node.operand)
            return not value if value is not None else None
        if isinstance(node, ast.BoolOp):
            values = [self.truth(value) for value in node.values]
            absorbing = isinstance(node.op, ast.Or)
            if absorbing in values:
                return absorbing
            if all(value is not None for value in values):
                return not absorbing
        return None

    def bindings(self, target: ast.AST, value: ast.AST | None):
        if isinstance(target, ast.Name):
            yield target.id, (self.is_geo_condition(value) if value is not None else False), (
                self.truth(value) if value is not None else None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) else [None] * len(target.elts)
            for child, assigned in zip(target.elts, values):
                yield from self.bindings(child, assigned)
        elif isinstance(target, ast.Starred):
            yield from self.bindings(target.value, None)

    def assign(self, targets: list[ast.AST], value: ast.AST | None):
        # Snapshot all RHS facts before assignment (including a, b = b, a).
        bindings = [binding for target in targets for binding in self.bindings(target, value)]
        if value is not None:
            self.visit(value)
        for name, geographic, constant in bindings:
            self.geo_flags.discard(name)
            self.constants.pop(name, None)
            self.aliases.pop(name, None)
            if geographic:
                self.geo_flags.add(name)
            if constant is not None:
                self.constants[name] = constant

    def visit_Assign(self, node: ast.Assign):
        self.assign(node.targets, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self.assign([node.target], node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.assign([node.target], node.value)

    def visit_AugAssign(self, node: ast.AugAssign):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.constants.pop(node.target.id, None)
            if self.is_geo_condition(node.value):
                self.geo_flags.add(node.target.id)

    def visit_Delete(self, node: ast.Delete):
        self.assign(node.targets, None)

    def is_geo_condition(self, test: ast.AST) -> bool:
        if self.truth(test) is not None:
            return False
        if isinstance(test, ast.Name) and test.id in self.geo_flags:
            return True
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.is_geo_condition(test.operand)
        if isinstance(test, ast.BoolOp):
            return any(self.is_geo_condition(v) for v in test.values)
        if not isinstance(test, ast.Compare):
            return False
        nodes = [test.left, *test.comparators]
        country_present = any(isinstance(x, ast.Constant) and isinstance(x.value, str) and
                              x.value.upper() in GEO_COUNTRIES for n in nodes for x in ast.walk(n))
        if not country_present:
            return False
        for node in nodes:
            for item in ast.walk(node):
                if isinstance(item, ast.Name) and any(w in item.id.lower() for w in GEO_WORDS):
                    return True
                if isinstance(item, ast.Attribute) and any(w in item.attr.lower() for w in GEO_WORDS):
                    return True
                if isinstance(item, ast.Constant) and isinstance(item.value, str) and (
                        any(w in item.value.lower() for w in GEO_WORDS) or
                        any(h in item.value.lower() for h in GEO_HOSTS)):
                    return True
        return False

    def classify(self, node: ast.Call) -> tuple[str, str, str, str] | None:
        raw = dotted(node.func)
        name = self.resolve(raw)
        last = name.split(".")[-1]
        # Modules are resolved for imported aliases; object method calls remain heuristic.
        if name in DELETE_CALLS or (last in {"unlink", "rmdir"} and isinstance(node.func, ast.Attribute)):
            return "FS_DELETE", "filesystem", "medium", "Потенциальное удаление файла или каталога"
        if name in WRITE_CALLS or (last in {"write_text", "write_bytes"} and isinstance(node.func, ast.Attribute)):
            return "FS_WRITE", "filesystem", "low", "Запись или изменение файла"
        if name in {"builtins.open", "io.open", "open"}:
            mode = literal(node.args[1]) if len(node.args) > 1 else None
            for item in node.keywords:
                if item.arg == "mode":
                    mode = literal(item.value)
            if mode and any(x in mode for x in ("w", "a", "x", "+")):
                return "FS_WRITE", "filesystem", "low", "Открытие файла для записи"
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            nested = node.args[0] if node.args else None
            if nested is not None and any(
                isinstance(x, ast.Call) and any(w in self.resolve(dotted(x.func)).lower()
                                                  for w in ("b64decode", "atob", "fromcharcode", "decode"))
                for x in ast.walk(nested)
            ):
                return "OBF_DECODE_EXEC", "obfuscation", "high", "Выполнение динамически декодируемого выражения"
            return "OBF_DYNAMIC_EXEC", "obfuscation", "medium", "Динамическое исполнение выражения"
        if (name.startswith(("requests.", "httpx.", "urllib.request.", "aiohttp.")) and
                last in NETWORK_FUNCTIONS) or name in {"urllib.request.urlopen", "urlopen"}:
            address = literal(node.args[0]) if node.args else None
            for item in node.keywords:
                if item.arg in {"url", "uri"}:
                    address = literal(item.value)
            if address:
                try:
                    host = (urlparse(address).hostname or "").lower()
                except ValueError:
                    host = ""
                if host and any(host == d or host.endswith("." + d) for d in GEO_HOSTS):
                    return "NET_GEO_API", "geolocation", "medium", "Сетевой вызов к сервису IP-геолокации"
                if host and not any(host == d or host.endswith("." + d) for d in self.allowed):
                    return "NET_EXTERNAL", "network", "medium", f"Сетевой вызов к домену вне allowlist: {host}"
            return "NET_DYNAMIC", "network", "low", "Сетевой endpoint не может быть определён статически"
        return None

    def visit_Call(self, node: ast.Call):
        classified = self.classify(node)
        if classified:
            self.add(*classified[:3], node, classified[3])
            if self.geo_conditions and classified[0] in {"FS_DELETE", "FS_WRITE", "NET_EXTERNAL", "NET_DYNAMIC", "NET_GEO_API"}:
                severity = "high" if classified[0] == "FS_DELETE" else "medium"
                self.add("GEO_ACTION", "correlation", severity, node,
                         f"AST: {classified[0]} находится в ветви географического условия (строка {self.geo_conditions[-1]})")
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        self.visit(node.test)
        known = self.truth(node.test)
        if known is not None:
            for statement in node.body if known else node.orelse:
                self.visit(statement)
            return
        geographic = self.is_geo_condition(node.test)
        if geographic:
            self.add("GEO_TARGET", "geolocation", "medium", node,
                     "AST: условное ветвление по географическому признаку RU/BY")
        original = self.aliases.copy(), self.geo_flags.copy(), self.constants.copy()
        branches = []
        for suite in (node.body, node.orelse):
            self.aliases, self.geo_flags, self.constants = (value.copy() for value in original)
            if geographic:
                self.geo_conditions.append(node.lineno)
            try:
                for statement in suite:
                    self.visit(statement)
                branches.append((self.aliases, self.geo_flags, self.constants))
            finally:
                if geographic:
                    self.geo_conditions.pop()
        left, right = branches
        self.aliases = {key: value for key, value in left[0].items() if right[0].get(key) == value}
        self.geo_flags = left[1] | right[1]
        self.constants = {key: value for key, value in left[2].items() if key in right[2] and right[2][key] == value}


def scan_python(path: str, content: str, allowed_domains: list[str], *, tree: ast.Module | None = None) -> list[dict] | None:
    """Returns None if syntax is invalid; callers may use legacy heuristics."""
    if Path(path).suffix.lower() != ".py":
        return []
    if tree is None:
        try:
            tree = ast.parse(content, filename=path)
        except (SyntaxError, ValueError, MemoryError):
            return None
    analyzer = Analyzer(path, content, allowed_domains)
    analyzer.visit(tree)
    return analyzer.findings
