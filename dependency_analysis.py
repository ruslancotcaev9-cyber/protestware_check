"""Static software supply-chain inventory: never installs or executes dependencies.

Read exact package identities from ecosystem lockfiles, optionally enrich their
source-repository URLs via fixed, official registry endpoints. Unlocked metadata
resolution is best-effort and explicitly marked non-reproducible.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import json
import re
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from typing import Any

import threat_intel

MAX_RESPONSE_BYTES = 1_500_000
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PYPI_NORMALIZE = re.compile(r"[-_.]+")
PIN_RE = re.compile(r"^\s*([A-Za-z0-9][\w.-]*)(?:\[[^]]+\])?\s*={2,3}\s*([^\s;#]+)")
NPM_VERSION = re.compile(r"^(?:@([^/]+)/)?([^@/]+)@(.+)$")
GO_MODULE = re.compile(r"^github\.com/([^/]+)/([^/]+)(?:/|$)", re.I)


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    manifest: str
    source: str
    depth: int = -1
    direct: bool = False
    repository: str | None = None
    requested: str = ""
    via: set[str] = field(default_factory=set)
    dependents: dict[str, str] = field(default_factory=dict)
    qualifiers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"ecosystem": self.ecosystem, "name": self.name,
                "version": self.version, "manifest": self.manifest,
                "source": self.source, "depth": self.depth if self.depth >= 0 else None,
                "direct": self.direct, "repository": self.repository,
                "requested": self.requested, "via": sorted(self.via)[:12],
                "qualifiers": self.qualifiers}


class RegistryError(Exception):
    """No trusted registry metadata was retrieved."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise RegistryError("Registry redirected request; cross-host redirects are disabled")


def official_json(url: str) -> dict[str, Any]:
    """A read-only, single-hop JSON request to an official, fixed registry host."""
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in {
        "registry.npmjs.org", "pypi.org", "crates.io", "repo.packagist.org"
    } or parts.port not in (None, 443) or parts.username or parts.password:
        raise RegistryError("Unapproved registry URL")
    opener = build_opener(NoRedirect())
    try:
        with opener.open(Request(url, headers={"User-Agent": "protestware-check/0.3",
                                               "Accept": "application/json"}), timeout=12) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise RegistryError("Registry metadata exceeds size limit")
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise RegistryError("Registry metadata is not a JSON object")
            return obj
    except (HTTPError, URLError, OSError, TimeoutError, ValueError) as err:
        raise RegistryError(f"Registry metadata unavailable: {type(err).__name__}") from err


def normalize(ecosystem: str, name: str) -> str:
    return PYPI_NORMALIZE.sub("-", name).lower() if ecosystem == "pypi" else name.lower()


def repo_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str):
        return None
    names = threat_intel.github_refs(value)
    return sorted(names)[0] if names else None


def npm_name(location: str) -> str:
    parts = location.split("node_modules/")
    return parts[-1].strip("/") if len(parts) > 1 else ""


def roots_for(manifests: dict[str, str], names: tuple[str, ...]) -> list[tuple[str, str]]:
    return [(path, contents) for path, contents in sorted(manifests.items())
            if path.rsplit("/", 1)[-1].lower() in names]


def manifest_dir(path: str) -> str:
    return path.rpartition("/")[0]


def sibling(path: str, basename: str) -> str:
    folder = manifest_dir(path)
    return f"{folder}/{basename}" if folder else basename


class Inventory:
    def __init__(self, manifests: dict[str, str], *, mode: str,
                 max_packages: int = 2000, max_depth: int = 12, max_requests: int = 300):
        self.manifests = manifests
        self.mode = mode
        self.max_packages = max_packages
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.packages: dict[tuple[str, str, str, str], Package] = {}
        self.warnings: list[str] = []
        self.partial = False
        self.requests = 0
        self.cache: dict[tuple[str, str, str], dict] = {}
        self.source_files: set[str] = set()
        self.unlocked_specs: dict[tuple[str, str, str], str] = {}

    def warn(self, text: str) -> None:
        self.partial = True
        if len(self.warnings) < 100:
            self.warnings.append(text)

    def add(self, pkg: Package) -> Package | None:
        key = (pkg.ecosystem, normalize(pkg.ecosystem, pkg.name), pkg.version, pkg.manifest)
        if key in self.packages:
            old = self.packages[key]
            old.direct |= pkg.direct
            old.via.update(pkg.via)
            old.depth = min(v for v in (old.depth, pkg.depth) if v >= 0) if (old.depth >= 0 or pkg.depth >= 0) else -1
            if not old.repository:
                old.repository = pkg.repository
            return old
        if len(self.packages) >= self.max_packages:
            self.warn(f"Package limit ({self.max_packages}) exceeded; inventory truncated")
            return None
        if pkg.depth > self.max_depth:
            self.warn(f"Depth limit ({self.max_depth}) reached for {pkg.ecosystem}:{pkg.name}")
            return None
        self.packages[key] = pkg
        return pkg

    def read_json(self, path: str) -> Any:
        try:
            return json.loads(self.manifests[path])
        except (ValueError, TypeError) as err:
            self.warn(f"Malformed JSON: {path} ({type(err).__name__})")
            return None

    def read_toml(self, path: str) -> Any:
        try:
            return tomllib.loads(self.manifests[path])
        except (ValueError, TypeError) as err:
            self.warn(f"Malformed TOML: {path} ({type(err).__name__})")
            return None

    def package_json(self, path: str) -> dict[str, str]:
        package_path = sibling(path, "package.json")
        if package_path not in self.manifests:
            return {}
        doc = self.read_json(package_path)
        if not isinstance(doc, dict):
            return {}
        deps: dict[str, str] = {}
        for key in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
            if isinstance(doc.get(key), dict):
                deps.update({k: str(v) for k, v in doc[key].items() if isinstance(k, str)})
        return deps

    def npm_locks(self) -> None:
        used: set[str] = set()
        paths = roots_for(self.manifests, ("npm-shrinkwrap.json", "package-lock.json"))
        for path, _ in paths:
            root = manifest_dir(path)
            if root in used:  # npm-shrinkwrap has precedence, sort below enforces it
                continue
            shrink = sibling(path, "npm-shrinkwrap.json")
            if path != shrink and shrink in self.manifests:
                continue
            used.add(root)
            data = self.read_json(path)
            if not isinstance(data, dict):
                continue
            self.source_files.add(path)
            declared = self.package_json(path)
            if isinstance(data.get("packages"), dict):
                packages = data["packages"]
                root_meta = packages.get("", {})
                if isinstance(root_meta, dict):
                    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                        if isinstance(root_meta.get(field), dict):
                            declared.update({k: str(v) for k, v in root_meta[field].items()})
                for location, value in packages.items():
                    if not location or not isinstance(value, dict) or value.get("link"):
                        continue
                    name = str(value.get("name") or npm_name(location))
                    version = value.get("version")
                    if not name or not isinstance(version, str):
                        self.warn(f"Unresolved npm lock entry: {path}:{location}")
                        continue
                    raw_repo = value.get("repository") or value.get("resolved")
                    pkg = Package("npm", name, version, path, "lockfile",
                                  direct=name in declared and location == "node_modules/" + name,
                                  requested=declared.get(name, ""), repository=repo_from_value(raw_repo))
                    # Optional and peer dependencies may legitimately be absent in a platform-specific install.
                    if isinstance(value.get("dependencies"), dict):
                        pkg.dependents.update(value["dependencies"])
                    self.add(pkg)
                # Resolve npm's lockfile paths using Node's nearest node_modules lookup.
                # Do not mistake packages appearing far apart in the file for parent-child edges.
                self.link_npm_graph(path, packages, declared)
            elif isinstance(data.get("dependencies"), dict):
                def visit(nodes: dict, parent: str, depth: int) -> None:
                    for name, value in nodes.items():
                        if not isinstance(value, dict):
                            continue
                        version = value.get("version")
                        if not isinstance(version, str):
                            self.warn(f"Missing npm v1 lock version for {name}")
                            continue
                        location = f"{parent}/{name}" if parent else name
                        record = self.add(Package("npm", name, version, path, "lockfile", depth,
                                     direct=not parent and name in declared,
                                     requested=declared.get(name, ""),
                                     repository=repo_from_value(value.get("resolved")),
                                     via={parent} if parent else set()))
                        if record is None:
                            continue
                        nested = value.get("dependencies")
                        if isinstance(nested, dict):
                            visit(nested, location, depth + 1)
                visit(data["dependencies"], "", 1)
            else:
                self.warn(f"Unsupported npm lock format: {path}")
        # A project with package.json but without a lockfile may be expanded online.
        for path, _ in roots_for(self.manifests, ("package.json",)):
            if manifest_dir(path) in used or sibling(path, "pnpm-lock.yaml") in self.manifests:
                continue
            manifest = self.read_json(path)
            if not isinstance(manifest, dict):
                continue
            self.source_files.add(path)
            for name, spec in self.package_json(path).items():
                if not isinstance(spec, str):
                    continue
                repo = repo_from_value(spec)
                if repo:
                    self.add(Package("npm", name, "", path, "manifest", 0, True, repo, spec))
                else:
                    self.unlocked_specs[("npm", name, path)] = spec
                    if self.mode == "registry":
                        self.add(Package("npm", name, "", path, "manifest", 0, True, requested=spec))
                    else:
                        self.warn(f"No npm lockfile for {path}; dependency {name} cannot be enumerated")

    def link_npm_graph(self, manifest: str, locked: dict, declared: dict[str, str]) -> None:
        indexed: dict[str, Package] = {}
        for location, info in locked.items():
            if not location or not isinstance(info, dict) or info.get("link"):
                continue
            name = str(info.get("name") or npm_name(location))
            version = info.get("version")
            key = ("npm", normalize("npm", name), version, manifest)
            if key in self.packages:
                indexed[location] = self.packages[key]

        def closest(parent: str, name: str) -> str | None:
            search = parent
            while True:
                candidate = f"{search}/node_modules/{name}" if search else f"node_modules/{name}"
                if candidate in indexed:
                    return candidate
                if not search:
                    return None
                # Node only searches ancestors, not adjacent package directories.
                if "/node_modules/" in search:
                    search = search.rsplit("/node_modules/", 1)[0]
                elif search.startswith("node_modules/"):
                    search = ""
                else:
                    search = search.rsplit("/", 1)[0] if "/" in search else ""

        queue = deque()
        for name in declared:
            key = closest("", name)
            if key:
                pkg = indexed[key]
                pkg.direct = True
                pkg.depth = 1
                queue.append(key)
            else:
                self.warn(f"npm dependency missing from lockfile {manifest}: {name}")
        if not declared and indexed:
            self.warn(f"npm lockfile {manifest} has no root dependency declarations; ancestry unknown")
        while queue:
            current = queue.popleft()
            parent = indexed[current]
            if parent.depth >= self.max_depth:
                self.warn(f"npm depth limit at {parent.name} in {manifest}")
                continue
            for dependency in parent.dependents:
                loc = closest(current, dependency)
                if loc is None:
                    self.warn(f"npm lockfile missing {dependency}, required by {parent.name}")
                    continue
                child = indexed[loc]
                child.via.add(f"{parent.name}@{parent.version}")
                if child.depth < 0 or child.depth > parent.depth + 1:
                    child.depth = parent.depth + 1
                    queue.append(loc)
        # Unreachable entries can be platform variants, workspace packages, or stale data.
        # Keep their identities but never claim they are necessarily installed.
        for location, pkg in indexed.items():
            if pkg.depth < 0:
                pkg.qualifiers.append("lockfile-unreachable-or-conditional")

    def pnpm_locks(self) -> None:
        """Read pnpm v6-v9 installed versions, including snapshot dependency edges."""
        for path, content in roots_for(self.manifests, ("pnpm-lock.yaml",)):
            if sibling(path, "package-lock.json") in self.manifests or sibling(path, "npm-shrinkwrap.json") in self.manifests:
                self.warn(f"Multiple npm-family locks in {manifest_dir(path) or '.'}; select the authoritative one")
            try:
                import yaml
            except ImportError:
                self.warn(f"PyYAML is required to read {path}; install requirements-resolver.txt")
                continue
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                self.warn(f"Malformed pnpm lockfile: {path}")
                continue
            if not isinstance(data, dict):
                self.warn(f"Invalid pnpm lock document: {path}")
                continue
            self.source_files.add(path)
            packages = data.get("packages", {})
            snapshots = data.get("snapshots", {})
            if not isinstance(packages, dict):
                self.warn(f"No pnpm package graph in {path}")
                continue
            indexed: dict[tuple[str, str], Package] = {}
            for key, info in packages.items():
                if not isinstance(key, str):
                    continue
                hit = re.fullmatch(r"/?(@[^/]+/[^@]+|[^@/]+)@([^()]+)(?:\(.*\))?", key)
                if not hit or not isinstance(info, dict):
                    continue
                name, version = hit.group(1), hit.group(2)
                repository = repo_from_value(info.get("repository"))
                res = info.get("resolution", {})
                if not repository and isinstance(res, dict):
                    repository = repo_from_value(res.get("tarball"))
                pkg = self.add(Package("npm", name, version, path, "lockfile", repository=repository))
                if pkg:
                    indexed[(name, version)] = pkg
            # pnpm snapshots include resolved dependency references, even with peer suffixes.
            deps_by_name: dict[tuple[str, str], dict[str, str]] = {}
            for selector, value in {**packages, **(snapshots if isinstance(snapshots, dict) else {})}.items():
                if not isinstance(selector, str) or not isinstance(value, dict):
                    continue
                match = re.match(r"^/?(@[^/]+/[^@]+|[^@/]+)@([^()]+)", selector)
                if match:
                    deps = {}
                    for kind in ("dependencies", "optionalDependencies"):
                        if isinstance(value.get(kind), dict):
                            deps.update({n: str(ref.get("version", "") if isinstance(ref, dict) else ref)
                                         for n, ref in value[kind].items()})
                    deps_by_name[(match.group(1), match.group(2))] = deps
            importers = data.get("importers", {})
            if not isinstance(importers, dict):
                importers = {}
            queue = deque()
            for importer in importers.values():
                if not isinstance(importer, dict):
                    continue
                for key in ("dependencies", "devDependencies", "optionalDependencies"):
                    deps = importer.get(key, {})
                    if not isinstance(deps, dict):
                        continue
                    for name, value in deps.items():
                        version = str(value.get("version", "") if isinstance(value, dict) else value)
                        version = version.split("(", 1)[0]
                        candidate = indexed.get((name, version))
                        if candidate:
                            candidate.depth, candidate.direct = 1, True
                            queue.append(candidate)
            while queue:
                parent = queue.popleft()
                if parent.depth >= self.max_depth:
                    self.warn(f"pnpm depth limit at {parent.name}@{parent.version}")
                    continue
                for name, raw in deps_by_name.get((parent.name, parent.version), {}).items():
                    version = raw.split("(", 1)[0]
                    child = indexed.get((name, version))
                    if child:
                        child.via.add(f"{parent.name}@{parent.version}")
                        if child.depth < 0 or child.depth > parent.depth + 1:
                            child.depth = parent.depth + 1
                            queue.append(child)
                    else:
                        self.warn(f"pnpm unresolved {name}@{version} required by {parent.name}")
            for pkg in indexed.values():
                if pkg.depth < 0:
                    pkg.qualifiers.append("lockfile-unreachable-or-conditional")

    def python_locks(self) -> None:
        locked_roots: set[str] = set()
        for path, _ in roots_for(self.manifests, ("uv.lock", "poetry.lock", "pylock.toml")):
            data = self.read_toml(path)
            if not isinstance(data, dict):
                continue
            self.source_files.add(path)
            locked_roots.add(manifest_dir(path))
            entries = data.get("package" if not path.endswith("pylock.toml") else "packages")
            if not isinstance(entries, list):
                self.warn(f"Unknown Python lock structure in {path}")
                continue
            direct = self.python_project_specs(sibling(path, "pyproject.toml"))
            for item in entries:
                if not isinstance(item, dict):
                    continue
                name, version = item.get("name"), item.get("version")
                if not isinstance(name, str):
                    continue
                source = item.get("source", {})
                if isinstance(source, dict) and ("editable" in source or "directory" in source or "virtual" in source):
                    continue
                raw_repo = (source.get("git") or (source.get("url") if source.get("type") == "git" else None)
                            if isinstance(source, dict) else None)
                if not raw_repo:
                    vcs = item.get("vcs", {})
                    raw_repo = vcs.get("url") if isinstance(vcs, dict) else None
                pkg = Package("pypi", name, str(version or ""), path, "lockfile", 0 if normalize("pypi", name) in direct else -1,
                              direct=normalize("pypi", name) in direct,
                              repository=repo_from_value(raw_repo), requested=direct.get(normalize("pypi", name), ""))
                if version is None and not raw_repo:
                    self.warn(f"Unknown version for Python lock package {name} in {path}")
                self.add(pkg)
            self.link_python_lock(path, entries, direct)
        for path, _ in roots_for(self.manifests, ("pyproject.toml",)):
            specs = self.python_project_specs(path)
            if not specs:
                continue
            self.source_files.add(path)
            if manifest_dir(path) in locked_roots:
                continue
            for name, spec in specs.items():
                self.add_python_requirement(name, spec, path, direct=True)
        for path in sorted(self.manifests):
            if not threat_intel.REQUIREMENTS_NAME.fullmatch(path.rsplit("/", 1)[-1]):
                continue
            self.source_files.add(path)
            for line in self.manifests[path].splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if line.lstrip().startswith("-"):
                    if line.lstrip().startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
                        self.warn(f"Included requirements/constraints not expanded: {path}")
                    continue
                match = PIN_RE.match(line)
                if match:
                    self.add(Package("pypi", match.group(1), match.group(2), path,
                                     "requirements", 0, requested=f"=={match.group(2)}"))
                elif "github.com" not in line and line.strip():
                    self.add_python_requirement(None, line.strip(), path, direct=False)

    def link_python_lock(self, manifest: str, entries: list, direct: dict[str, str]) -> None:
        """Use explicit uv/Poetry/PEP751 edges, not textual source-line proximity."""
        by_name: dict[str, list[Package]] = {}
        edges: dict[str, set[str]] = {}
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            normalized = normalize("pypi", item["name"])
            key = ("pypi", normalized, str(item.get("version") or ""), manifest)
            pkg = self.packages.get(key)
            if pkg is None:
                continue
            by_name.setdefault(normalized, []).append(pkg)
            dependencies = item.get("dependencies") or {}
            children: set[str] = set()
            if isinstance(dependencies, list):  # uv: [{name="...", version=...}]
                for value in dependencies:
                    if isinstance(value, dict) and isinstance(value.get("name"), str):
                        children.add(normalize("pypi", value["name"]))
            elif isinstance(dependencies, dict):  # Poetry: {certifi = "^2024.1"}
                children.update(normalize("pypi", name) for name in dependencies)
            edges.setdefault(normalized, set()).update(children)
        queue = deque()
        for name in direct:
            for pkg in by_name.get(name, []):
                pkg.direct = True
                pkg.depth = 1
                queue.append(pkg)
            if name not in by_name:
                self.warn(f"Python dependency missing from lock {manifest}: {name}")
        seen: set[tuple[str, str]] = set()
        while queue:
            parent = queue.popleft()
            if (parent.name, parent.version) in seen:
                continue
            seen.add((parent.name, parent.version))
            for name in sorted(edges.get(normalize("pypi", parent.name), set())):
                for child in by_name.get(name, []):
                    child.via.add(f"{parent.name}@{parent.version}")
                    if parent.depth >= self.max_depth:
                        self.warn(f"Python dependency depth limit reached at {parent.name}")
                        continue
                    if child.depth < 0 or child.depth > parent.depth + 1:
                        child.depth = parent.depth + 1
                        queue.append(child)
                if name not in by_name:
                    self.warn(f"Python lock {manifest} has no record for dependency {name}")
        # Lockfiles may contain OS variants and dev/optional groups not reached from
        # default project dependencies. Retain those entries without falsely implying install.
        for item in by_name.values():
            for pkg in item:
                if pkg.depth < 0:
                    pkg.qualifiers.append("lockfile-unreachable-or-conditional")

    def python_project_specs(self, path: str) -> dict[str, str]:
        if path not in self.manifests:
            return {}
        data = self.read_toml(path)
        if not isinstance(data, dict):
            return {}
        output: dict[str, str] = {}
        proj = data.get("project", {})
        if isinstance(proj, dict):
            for spec in proj.get("dependencies", []) or []:
                if isinstance(spec, str):
                    name = re.match(r"^\s*([a-zA-Z][\w.-]*)", spec)
                    if name:
                        output[normalize("pypi", name.group(1))] = spec
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        if isinstance(poetry, dict):
            for name, spec in (poetry.get("dependencies", {}) or {}).items():
                if name.lower() == "python":
                    continue
                output[normalize("pypi", name)] = str(spec) if isinstance(spec, str) else ""
        return output

    def add_python_requirement(self, name: str | None, raw: str, path: str, *, direct: bool) -> None:
        repo = repo_from_value(raw)
        found = re.match(r"^\s*([A-Za-z][\w.-]*)(?:\[([^]]+)\])?\s*(.*)$", raw)
        if not found and not name:
            self.warn(f"Unsupported Python requirement in {path}")
            return
        package_name = name or found.group(1)
        requested = raw if raw != "*" else ""
        pinned = PIN_RE.match(raw)
        version = pinned.group(2) if pinned else ""
        pkg = Package("pypi", package_name, version, path,
                      "manifest", 0 if direct else -1, direct, repo, requested)
        if found and found.group(2):
            pkg.qualifiers = [s.strip() for s in found.group(2).split(",")]
        self.add(pkg)
        if not version and not repo and self.mode != "registry":
            self.warn(f"Unpinned Python dependency {package_name} in {path}; requires --dependencies registry or a lockfile")

    def other_locks(self) -> None:
        for path, _ in roots_for(self.manifests, ("cargo.lock",)):
            obj = self.read_toml(path)
            if not isinstance(obj, dict):
                continue
            self.source_files.add(path)
            for pkg in obj.get("package", []):
                if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                    continue
                source = str(pkg.get("source", ""))
                repo = repo_from_value(source) if source.startswith("git+") else None
                self.add(Package("cargo", pkg["name"], str(pkg.get("version", "")), path,
                                 "lockfile", repository=repo))
        for path, _ in roots_for(self.manifests, ("composer.lock",)):
            obj = self.read_json(path)
            if not isinstance(obj, dict):
                continue
            self.source_files.add(path)
            for key in ("packages", "packages-dev"):
                for pkg in obj.get(key, []):
                    if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                        continue
                    source = pkg.get("source", {})
                    self.add(Package("composer", pkg["name"], str(pkg.get("version", "")),
                                     path, "lockfile", repository=repo_from_value(source)))
        go_direct: dict[str, set[str]] = {}
        for go_path, text in roots_for(self.manifests, ("go.mod",)):
            root = manifest_dir(go_path)
            direct = set()
            block = False
            for line in text.splitlines():
                line = line.split("//", 1)[0].strip()
                if line == "require (":
                    block = True
                    continue
                if line == ")" and block:
                    block = False
                    continue
                if block or line.startswith("require "):
                    fields = line.removeprefix("require ").split()
                    if len(fields) >= 2 and fields[1].startswith("v"):
                        direct.add(fields[0])
            go_direct[root] = direct
            self.source_files.add(go_path)
            if sibling(go_path, "go.sum") not in self.manifests:
                self.warn(f"go.mod {go_path} has no go.sum; full transitive module list unavailable")
                for name in direct:
                    matched = GO_MODULE.match(name)
                    repo = f"{matched.group(1)}/{matched.group(2)}".lower() if matched else None
                    self.add(Package("go", name, "", go_path, "manifest", 1, True, repo))
        for path, text in self.manifests.items():
            if path.rsplit("/", 1)[-1] != "go.sum":
                continue
            self.source_files.add(path)
            for line in text.splitlines():
                fields = line.split()
                if len(fields) < 2 or not fields[1].startswith("v"):
                    continue
                mod, ver = fields[0], fields[1].removesuffix("/go.mod")
                repo_match = GO_MODULE.match(mod)
                repo = (f"{repo_match.group(1)}/{repo_match.group(2)}".lower() if repo_match else None)
                direct = mod in go_direct.get(manifest_dir(path), set())
                self.add(Package("go", mod, ver, path, "lockfile", 1 if direct else -1,
                                 direct=direct, repository=repo))

    def registry_get(self, ecosystem: str, name: str, version: str) -> dict:
        key = (ecosystem, normalize(ecosystem, name), version)
        if key in self.cache:
            return self.cache[key]
        if self.requests >= self.max_requests:
            raise RegistryError(f"Registry request limit ({self.max_requests}) exceeded")
        if ecosystem == "npm":
            segment = quote(name, safe="")
            url = f"https://registry.npmjs.org/{segment}/{quote(version, safe='')}" if version else f"https://registry.npmjs.org/{segment}"
        elif ecosystem == "pypi":
            segment = quote(normalize(ecosystem, name), safe="")
            url = f"https://pypi.org/pypi/{segment}/{quote(version, safe='')}/json" if version else f"https://pypi.org/pypi/{segment}/json"
        elif ecosystem == "cargo":
            url = f"https://crates.io/api/v1/crates/{quote(name, safe='')}"
        elif ecosystem == "composer":
            url = f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json"
        else:
            raise RegistryError("No official registry resolver for ecosystem")
        self.requests += 1
        obj = official_json(url)
        self.cache[key] = obj
        return obj

    def choose_version(self, ecosystem: str, name: str, spec: str) -> str:
        """Select a best-effort version for an unlocked requirement, never promise a lock."""
        if ecosystem == "npm":
            try:
                from semantic_version import NpmSpec, Version
            except ImportError as err:
                raise RegistryError("Install requirements-resolver.txt for npm range parsing") from err
            pack = self.registry_get("npm", name, "")
            tags = pack.get("dist-tags", {})
            if isinstance(tags, dict) and spec in tags:
                return str(tags[spec])
            try:
                criterion = NpmSpec(spec or "*")
                versions = []
                for raw in pack.get("versions", {}):
                    try:
                        version_obj = Version(raw)
                        if not version_obj.prerelease or "-" in spec:
                            versions.append(version_obj)
                    except ValueError:
                        continue
                found = [v for v in versions if criterion.match(v)]
                if found:
                    return str(max(found))
            except (ValueError, TypeError) as err:
                raise RegistryError(f"Unsupported npm version range {spec!r}") from err
            raise RegistryError(f"No npm version matches {spec!r}")
        if ecosystem == "pypi":
            try:
                from packaging.specifiers import SpecifierSet
                from packaging.version import Version
            except ImportError as err:
                raise RegistryError("Install requirements-resolver.txt for Python PEP 440 parsing") from err
            project = self.registry_get("pypi", name, "")
            constraint = spec.strip()
            try:
                from packaging.requirements import Requirement
                parsed = Requirement(constraint)
                if normalize("pypi", parsed.name) == normalize("pypi", name):
                    constraint = str(parsed.specifier)
            except ValueError:
                pass
            if constraint in ("*", "", "latest"):
                constraint = ""
            try:
                selector = SpecifierSet(constraint)
                candidates = []
                for version, releases in project.get("releases", {}).items():
                    try:
                        ver = Version(version)
                    except ValueError:
                        continue
                    if selector.contains(ver) and isinstance(releases, list) and any(not r.get("yanked") for r in releases if isinstance(r, dict)):
                        candidates.append(ver)
                if candidates:
                    return str(max(candidates))
            except (ValueError, TypeError) as err:
                raise RegistryError(f"Unsupported PyPI version specifier {spec!r}") from err
            raise RegistryError(f"No PyPI version matches {spec!r}")
        raise RegistryError("Unsupported ecosystem")

    def registry_expand(self) -> None:
        """Enrich pinned packages and expand unlocked graphs; no install/build scripts."""
        queue = deque((key, pkg.depth if pkg.depth >= 0 else 0)
                      for key, pkg in self.packages.items())
        visited: set[tuple[str, str, str, tuple[str, ...]]] = set()
        while queue:
            key, depth = queue.popleft()
            pkg = self.packages.get(key)
            if pkg is None:
                continue
            if pkg.ecosystem not in {"npm", "pypi", "cargo", "composer"}:
                continue
            if not pkg.version and pkg.repository:
                continue  # Git dependency identity, without registry version
            if not pkg.version:
                try:
                    pkg.version = self.choose_version(pkg.ecosystem, pkg.name, pkg.requested)
                    pkg.source = "registry-selected"
                except RegistryError as err:
                    self.warn(f"Cannot resolve {pkg.ecosystem}:{pkg.name}: {err}")
                    continue
            unique = (pkg.ecosystem, normalize(pkg.ecosystem, pkg.name), pkg.version)
            if (*unique, tuple(sorted(pkg.qualifiers))) in visited:
                continue
            visited.add((*unique, tuple(sorted(pkg.qualifiers))))
            try:
                obj = self.registry_get(pkg.ecosystem, pkg.name, pkg.version if pkg.ecosystem not in {"cargo", "composer"} else "")
                if pkg.ecosystem == "npm":
                    source = obj.get("repository")
                    deps = obj.get("dependencies", {})
                    metadata = obj
                elif pkg.ecosystem == "pypi":
                    metadata = obj.get("info", {})
                    urls = metadata.get("project_urls") or {}
                    source = next((url for kind, url in urls.items()
                                   if re.search(r"source|repository|code|homepage", kind, re.I) and repo_from_value(url)), None) if isinstance(urls, dict) else None
                    source = source or metadata.get("home_page")
                    deps = metadata.get("requires_dist")
                    if deps is None and pkg.source != "lockfile":
                        self.warn(f"PyPI Requires-Dist metadata missing for {pkg.name}@{pkg.version}")
                    deps = deps or []
                elif pkg.ecosystem == "cargo":
                    metadata = obj.get("crate", {})
                    source = metadata.get("repository")
                    deps = None
                else:
                    metadata = obj.get("packages", {}).get(pkg.name, [])
                    match = next((item for item in metadata if item.get("version") == pkg.version), None)
                    source = match.get("source", {}) if match else None
                    deps = None
                if not pkg.repository:
                    pkg.repository = repo_from_value(source)
                if pkg.ecosystem in {"cargo", "composer"}:
                    continue
                if pkg.source == "lockfile":
                    continue  # Lock inventory already includes entire closure; enrichment only.
                if depth >= self.max_depth:
                    self.warn(f"Dependency depth limit reached at {pkg.ecosystem}:{pkg.name}")
                    continue
                child_specs: list[tuple[str, str, list[str]]] = []
                if pkg.ecosystem == "npm" and isinstance(deps, dict):
                    child_specs = [(n, v, []) for n, v in deps.items() if isinstance(v, str)]
                elif pkg.ecosystem == "pypi" and isinstance(deps, list):
                    try:
                        from packaging.requirements import Requirement
                        from packaging.markers import default_environment
                    except ImportError as err:
                        raise RegistryError("Install requirements-resolver.txt for PEP 508 markers") from err
                    for text in deps:
                        if not isinstance(text, str):
                            continue
                        try:
                            requirement = Requirement(text)
                            environments = ["", *pkg.qualifiers]
                            if requirement.marker and not any(requirement.marker.evaluate({**default_environment(), "extra": extra}) for extra in environments):
                                continue
                            if requirement.url:
                                repo = repo_from_value(requirement.url)
                                if repo:
                                    self.add(Package("pypi", requirement.name, "", pkg.manifest,
                                               "registry-selected", depth + 1, repository=repo,
                                               requested=requirement.url, via={pkg.name}))
                                else:
                                    self.warn(f"Non-index Python requirement URL for {requirement.name} cannot be resolved")
                                continue
                            child_specs.append((requirement.name, str(requirement.specifier), list(requirement.extras)))
                        except (ValueError, TypeError) as err:
                            self.warn(f"Invalid Requires-Dist for {pkg.name}: {type(err).__name__}")
                for name, spec, extras in child_specs:
                    if not name or not isinstance(spec, str):
                        continue
                    child = Package(pkg.ecosystem, name, "", pkg.manifest,
                                    "registry-selected", depth + 1, requested=spec,
                                    via={f"{pkg.name}@{pkg.version}"}, qualifiers=extras)
                    # Resolve immediately to prevent mutation of dictionary key / duplicates.
                    try:
                        if repo := repo_from_value(spec):
                            child.repository = repo
                        else:
                            child.version = self.choose_version(child.ecosystem, child.name, child.requested)
                    except RegistryError as err:
                        self.warn(f"Unresolved child {name} of {pkg.name}: {err}")
                        continue
                    if self.add(child) is not None:
                        for k, v in self.packages.items():
                            if v is child:
                                queue.append((k, depth + 1))
                                break
            except (RegistryError, AttributeError, TypeError, KeyError, ValueError) as err:
                self.warn(f"Registry enrichment failed for {pkg.ecosystem}:{pkg.name}@{pkg.version}: {err}")

    def add_explicit(self, identifiers: list[str]) -> None:
        for spec in identifiers:
            match = re.fullmatch(r"(npm|pypi|cargo|composer):(.+?)(?:@([^@]+))?", spec)
            if not match:
                raise ValueError(f"--package must be ecosystem:name@version (npm, pypi, cargo, composer): {spec}")
            eco, name, requested = match.groups()
            if eco == "npm":
                good = re.fullmatch(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+", name)
            elif eco == "composer":
                good = re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", name)
            else:
                good = NAME_RE.fullmatch(name)
            if not good:
                raise ValueError(f"Malformed --package name: {name}")
            if requested and not re.fullmatch(r"[A-Za-z0-9.^~*<>=!|+ _,-]+", requested):
                raise ValueError(f"Malformed --package version constraint: {requested}")
            self.add(Package(eco, name, requested or "", "(package)",
                             "manifest" if not requested else "explicit", 0, True,
                             requested=requested or ""))
            if not requested and self.mode == "lock":
                self.warn(f"Unpinned explicit package {spec}: registry mode required")

    def analyze(self, explicit_packages: list[str] | None = None) -> dict:
        if self.mode == "off":
            return {"mode": "off", "packages": [], "references": [], "summary": {"count": 0, "complete": False}}
        self.npm_locks()
        self.pnpm_locks()
        self.python_locks()
        self.other_locks()
        # Do not silently call unsupported lock formats complete.
        for path in self.manifests:
            if path.rsplit("/", 1)[-1].lower() in {"yarn.lock", "pipfile.lock", "gemfile.lock"}:
                self.warn(f"Lock format not yet resolved into package graph: {path}")
        self.add_explicit(explicit_packages or [])
        if self.mode == "registry":
            self.registry_expand()
        packages = sorted(self.packages.values(), key=lambda p: (p.ecosystem, p.name, p.version, p.manifest))
        references: list[tuple[str, str, int, str]] = []
        for pkg in packages:
            if pkg.repository:
                references.append((pkg.repository, pkg.manifest, 0,
                                   f"{pkg.ecosystem}:{pkg.name}@{pkg.version or 'unknown'} -> {pkg.repository}"))
        # A lockfile can prove identities, but not every package can be mapped to a source repo.
        # 'complete' means no input/limit/metadata errors, NOT that all repositories are known.
        if self.mode == "registry" and any(pkg.source == "registry-selected" for pkg in packages):
            self.warn("Unlocked registry-selected versions are approximate; no global backtracking resolver is used")
        counts = Counter(pkg.ecosystem for pkg in packages)
        return {"mode": self.mode,
                "packages": [pkg.as_dict() for pkg in packages],
                "references": references,
                "summary": {"count": len(packages), "ecosystems": dict(sorted(counts.items())),
                            "identified_repositories": len(references), "registry_requests": self.requests,
                            "complete": not self.partial, "manifests": sorted(self.source_files),
                            "warnings": self.warnings}}


def analyze_dependencies(manifests: dict[str, str], *, mode: str = "lock",
                         max_packages: int = 2000, max_depth: int = 12,
                         max_requests: int = 300,
                         explicit_packages: list[str] | None = None) -> dict:
    if mode not in {"off", "lock", "registry"}:
        raise ValueError("Invalid dependency analysis mode")
    return Inventory(manifests, mode=mode, max_packages=max_packages,
                     max_depth=max_depth, max_requests=max_requests).analyze(explicit_packages)
