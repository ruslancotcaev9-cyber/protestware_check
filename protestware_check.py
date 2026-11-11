#!/usr/bin/env python3
"""Non-executing heuristic scanner for potentially harmful protestware patterns."""

from __future__ import annotations

import argparse
import ast
import safe_io
import scan_policy
import analysis_context
import go_build_info
from hashlib import sha256
from advisory_cache import AdvisoryCache

import ast_analysis
import threat_intel
import dependency_analysis
import language_analysis
import report_formats
import malware_intel
import polyglot_ast
import python_taint
from scan_coverage import Coverage
import base64
import fnmatch
import io
import json
import os
from pathlib import Path
import re
import sys
import tokenize
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request

VERSION = "1.3.0"
DEFAULT_MAX_BYTES = 1_000_000
CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs",
    ".java", ".kt", ".rb", ".php", ".sh", ".bash", ".ps1", ".cs", ".c",
    ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".swift", ".lua", ".pl", ".r",
    ".sql", ".html", ".htm", ".css", ".sass", ".scss", ".less",
}
TEXT_SUFFIXES = CODE_SUFFIXES | {".md", ".mdx", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".xml"}
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".tox", ".mypy_cache",
}
EXCLUDED_GLOBS = {"*.min.js", "*.map", "*.lock", "package-lock.json", "yarn.lock"}
POLITICAL_TERMS = (
    "fuck russia", "russia is a terrorist state", "russia is an aggressor",
    "boycott russia", "stop russian aggression", "sanctions against russia",
    "россия — агрессор", "россия - агрессор", "россия страна-агрессор",
    "россия — государство-террорист", "бойкот россии", "санкции против россии",
)
GEO_HOSTS = {"ip-api.com", "ipapi.co", "ipinfo.io", "ipwho.is", "ipgeolocation.io", "freegeoip.app"}
GEO_TOKEN = re.compile(r"\b(?:country(?:_?code)?|countryCode|region|geoip|geolocation|locale|location)\b", re.I)
RU_TOKEN = re.compile(r"(?<![\w])(?:['\"](?:RU|RUS|BY|BLR|Russia|Belarus)['\"]|Russia|Belarus|Россия|России|Беларусь)(?![\w])", re.I)
GEO_DISCOVERY = re.compile(r"\b(?:navigator\.geolocation|geoip\.lookup|GeoIP2?\s*\(|geoip2\.database|ipwhois\.)", re.I)
CONDITION = re.compile(r"\b(?:if|elif|case|switch)\b|\?\s*", re.I)
COMPARISON = re.compile(r"===?|!==?|\bin\b|\.includes\s*\(|\.startswith\s*\(|\.contains\s*\(", re.I)
NETWORK = re.compile(
    r"\b(?:fetch\s*\(|axios(?:\.[a-z]+)?\s*\(|got\s*\(|requests?\.(?:get|post|put|delete|request)\s*\("
    r"|httpx\.(?:get|post|put|delete|request|Client|AsyncClient)\s*\(|urllib\.request\.urlopen\s*\("
    r"|https?\.(?:get|request)\s*\(|curl\s+|wget\s+)", re.I,
)
FS_DELETE = re.compile(
    r"(?:\bos\.(?:remove|unlink)\s*\(|shutil\.rmtree\s*\(|\.unlink\s*\(|"
    r"fs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(|"
    r"rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+|Remove-Item\b|del\s+/[fq])", re.I,
)
FS_WRITE = re.compile(
    r"(?:\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync)\s*\("
    r"|\.write_(?:text|bytes)\s*\(|os\.(?:replace|rename)\s*\(|shutil\.(?:move|copy|copyfile)\s*\("
    r"|open\s*\([^\n]{0,120},\s*['\"][wax]['\"])", re.I,
)
DECODE_EXEC = re.compile(
    r"\b(?:eval|exec|Function)\s*\([^\n]{0,160}(?:atob\s*\(|b64decode\s*\(|fromCharCode\s*\()", re.I,
)
DYNAMIC_EVAL = re.compile(r"\b(?:eval|exec)\s*\(", re.I)
CHARCODE = re.compile(r"\b(?:String\.fromCharCode|atob|base64\.b64decode)\s*\(", re.I)
LONG_BASE64 = re.compile(r"['\"][A-Za-z0-9+/]{160,}={0,2}['\"]")
URL = re.compile(r"https?://[^\s\"'<>`\\)]+", re.I)
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3}


class ScanError(Exception):
    """Source or configuration could not be scanned completely."""


def github_coordinates(value: str) -> tuple[str, str]:
    """Restrict remote input to github.com OWNER/REPO or the same HTTPS URL."""
    if value.startswith("https://"):
        parts = urlparse(value)
        if parts.hostname != "github.com" or parts.port not in (None, 443) or parts.username or parts.password:
            raise ScanError("Only https://github.com/OWNER/REPO URLs are supported")
        value = parts.path.strip("/")
        if parts.query or parts.fragment:
            raise ScanError("GitHub URLs must not contain query parameters or fragments")
    pieces = value.split("/")
    if len(pieces) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in pieces):
        raise ScanError("Repository must be OWNER/REPO or https://github.com/OWNER/REPO")
    owner, repo = pieces
    repo = repo.removesuffix(".git")
    if not repo or owner in {".", ".."} or repo in {".", ".."}:
        raise ScanError("Invalid GitHub repository identifier")
    return owner, repo


def api_json(url: str, token: str | None) -> dict[str, Any]:
    parts = urlparse(url)
    if (parts.scheme != "https" or parts.hostname != "api.github.com"
            or parts.port not in (None, 443) or parts.username or parts.password):
        raise ScanError("Unapproved GitHub API URL")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "protestware-check/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with safe_io.open_https(Request(url, headers=headers), timeout=20) as response:
            raw = response.read(16_000_001)
        if len(raw) > 16_000_000:
            raise ScanError("GitHub API response exceeds size limit")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ScanError("GitHub API response is not an object")
        return result
    except HTTPError as err:
        raise ScanError(f"GitHub API returned HTTP {err.code}; check access, rate limit or ref") from err
    except (URLError, OSError, ValueError, RecursionError) as err:
        raise ScanError(f"GitHub API request failed: {type(err).__name__}") from err


def selection_reason(path: str, extra_exclude: list[str], profile: str = "source", *, directory=False) -> str | None:
    if profile not in {"source", "artifact"}:
        raise ValueError("Unknown scan profile")
    excluded_dirs = EXCLUDED_DIRS - ({"dist", "build", ".next", "node_modules"} if profile == "artifact" else set())
    if any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(Path(path).name, p)
           or (directory and fnmatch.fnmatch(path + "/", p))
           for p in extra_exclude):
        return "user_exclude"
    if any(part in excluded_dirs for part in Path(path).parts):
        return "default_directory"
    if directory:
        return None
    if threat_intel.is_manifest(path):
        return None
    if any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(Path(path).name, p)
           for p in EXCLUDED_GLOBS - ({"*.min.js"} if profile == "artifact" else set())):
        return "default_pattern"
    if Path(path).suffix.lower() not in TEXT_SUFFIXES and Path(path).name not in {"Dockerfile", "Makefile"}:
        return "unsupported_extension"
    return None


def is_scannable(path: str, extra_exclude: list[str], profile: str = "source") -> bool:
    return selection_reason(path, extra_exclude, profile) is None


def iter_local(root: Path, max_bytes: int, exclude: list[str], warnings: list[str],
               coverage: Coverage | None = None, profile: str = "source") -> Iterable[tuple[str, str]]:
    if not root.is_dir() or root.is_symlink():
        raise ScanError("--path must point to a real directory (not a symlink)")
    def walk_error(error):
        raise ScanError(f"Cannot traverse source directory: {type(error).__name__}")
    if os.name == "posix":
        walk = os.fwalk(root, follow_symlinks=False, onerror=walk_error)
    else:
        walk = ((base, dirs, files, None) for base, dirs, files in
                os.walk(root, followlinks=False, onerror=walk_error))
    for base, dirs, files, directory_fd in walk:
        retained = []
        for directory in sorted(dirs):
            actual = Path(base, directory)
            relative = actual.relative_to(root).as_posix()
            reason = "symlink" if actual.is_symlink() else selection_reason(relative, exclude, profile, directory=True)
            if reason:
                if coverage is not None:
                    coverage.record(relative, reason, directory=True)
            else:
                retained.append(directory)
        dirs[:] = retained
        for filename in sorted(files):
            actual = Path(base, filename)
            relative = actual.relative_to(root).as_posix()
            reason = "symlink" if actual.is_symlink() else selection_reason(relative, exclude, profile)
            if reason:
                if coverage is not None:
                    coverage.record(relative, reason)
                continue
            try:
                content = safe_io.read_regular(filename if directory_fd is not None else actual,
                                               max_bytes, dir_fd=directory_fd)
            except ValueError:
                warnings.append(f"Skipped oversized file: {relative}")
                if coverage is not None:
                    coverage.record(relative, "oversized")
                continue
            except OSError as err:
                warnings.append(f"Could not read {relative}: {type(err).__name__}")
                if coverage is not None:
                    coverage.record(relative, "read_error")
                continue
            if b"\x00" in content:
                if coverage is not None:
                    coverage.record(relative, "binary", size=len(content))
                continue
            if coverage is not None:
                coverage.record(relative, "scanned", size=len(content))
                coverage.raw_hashes[relative] = sha256(content).hexdigest()
            yield relative, content.decode("utf-8-sig", errors="replace")


def iter_github(repo: str, ref: str | None, max_bytes: int, exclude: list[str], warnings: list[str],
                coverage: Coverage | None = None, profile: str = "source") -> Iterable[tuple[str, str]]:
    owner, name = github_coordinates(repo)
    token = os.environ.get("GITHUB_TOKEN")
    prefix = f"https://api.github.com/repos/{owner}/{name}"
    metadata = api_json(prefix, token)
    branch = ref or metadata.get("default_branch")
    if not branch:
        raise ScanError("Repository has no default branch")
    if coverage is not None:
        commit = api_json(f"{prefix}/commits/{quote(branch, safe='')}", token)
        resolved = commit.get("sha")
        if not isinstance(resolved, str) or not re.fullmatch(r"[a-f0-9]{40}", resolved):
            raise ScanError("GitHub did not resolve the requested ref to a commit")
        coverage.resolved_commit = resolved
        branch = resolved
    tree = api_json(f"{prefix}/git/trees/{quote(branch, safe='')}?recursive=1", token)
    if tree.get("truncated"):
        raise ScanError("GitHub tree was truncated; refusing to report partial results")
    if not isinstance(tree.get("tree"), list):
        raise ScanError("Invalid GitHub tree response")
    if coverage is not None:
        coverage.resolved_tree = tree.get("sha")
    for item in sorted(tree["tree"], key=lambda obj: obj.get("path", "")):
        path = item.get("path", "")
        if item.get("type") == "commit" and coverage is not None:
            coverage.record(path, "submodule")
        if item.get("type") != "blob":
            continue
        reason = "symlink" if item.get("mode") == "120000" else selection_reason(path, exclude, profile)
        if reason:
            if coverage is not None:
                coverage.record(path, reason)
            continue
        if item.get("size", 0) > max_bytes:
            warnings.append(f"Skipped oversized file: {path}")
            if coverage is not None:
                coverage.record(path, "oversized")
            continue
        sha = item.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            warnings.append(f"Missing blob SHA: {path}")
            if coverage is not None:
                coverage.record(path, "invalid_blob")
            continue
        blob = api_json(f"{prefix}/git/blobs/{sha}", token)
        if blob.get("encoding") != "base64":
            warnings.append(f"Unsupported blob encoding: {path}")
            if coverage is not None:
                coverage.record(path, "invalid_blob")
            continue
        try:
            raw = base64.b64decode(blob["content"], validate=False)
        except (KeyError, TypeError, ValueError) as err:
            raise ScanError(f"Invalid blob content: {path}") from err
        if len(raw) > max_bytes:
            warnings.append(f"Skipped oversized blob: {path}")
            if coverage is not None:
                coverage.record(path, "oversized")
            continue
        if coverage is not None:
            coverage.record(path, "binary" if b"\x00" in raw else "scanned", size=len(raw))
        if b"\x00" not in raw:
            yield path, raw.decode("utf-8-sig", errors="replace")


def domain_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == candidate or host.endswith("." + candidate) for candidate in allowed)


def finding(rule: str, category: str, severity: str, path: str, line: int, snippet: str, message: str) -> dict[str, Any]:
    return {"rule": rule, "category": category, "severity": severity,
            "file": path, "line": line, "evidence": snippet.strip()[:240], "message": message}



def python_code_only_lines(content: str) -> list[str]:
    """Mask Python literals/comments while preserving source line numbers and columns."""
    lines = content.splitlines()
    output = [list(line) for line in lines]
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type not in (tokenize.STRING, tokenize.COMMENT):
                continue
            (start_row, start_col), (end_row, end_col) = token.start, token.end
            for row in range(start_row - 1, min(end_row, len(output))):
                left = start_col if row == start_row - 1 else 0
                right = end_col if row == end_row - 1 else len(output[row])
                for column in range(left, min(right, len(output[row]))):
                    output[row][column] = " "
    except (tokenize.TokenError, IndentationError):
        return lines  # Incomplete sources still get best-effort scanning.
    return ["".join(line) for line in output]


def scan_text(path: str, content: str, political_terms: list[str], allowed_domains: list[str],
              ast_mode: str = "auto", ast_warnings: list[str] | None = None,
              ast_stats: dict[str, int] | None = None, context=None) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    lines = content.splitlines()
    suffix = Path(path).suffix.lower()
    code_lines = (python_code_only_lines(content) if suffix == ".py"
                  else language_analysis.mask_comments(content, suffix).splitlines())
    code = Path(path).suffix.lower() in CODE_SUFFIXES or Path(path).name in {"Dockerfile", "Makefile"}
    for i, line in enumerate(lines):
        n = i + 1
        lower = line.casefold()
        if any(term in lower for term in political_terms):
            output.append(finding("POLITICAL_RU", "context", "info", path, n, line,
                                  "Политический текст об РФ: контекстный сигнал, не доказательство вредоносности"))
        if not code:
            continue
        visible = code_lines[i]
        nearby = " ".join(lines[max(0, i - 2):i + 1])
        nearby_code = " ".join(code_lines[max(0, i - 2):i + 1])
        if GEO_TOKEN.search(nearby_code) and RU_TOKEN.search(nearby) and CONDITION.search(nearby_code) and COMPARISON.search(nearby_code):
            # Anchor to a source line, not every subsequent line.
            if GEO_TOKEN.search(visible) or RU_TOKEN.search(line):
                output.append(finding("GEO_TARGET", "geolocation", "medium", path, n, line,
                                      "Условие, связанное с географией и RU/BY; требуется проверить ветвление"))
        if GEO_DISCOVERY.search(visible):
            output.append(finding("GEO_DISCOVERY", "geolocation", "low", path, n, line,
                                  "Обнаружено получение географических данных пользователя"))
        if NETWORK.search(visible):
            hosts: set[str] = set()
            for address in URL.findall(" ".join(lines[i:i + 2])):
                try:
                    parsed = urlparse(address.rstrip(".,;"))
                    if parsed.hostname:
                        hosts.add(parsed.hostname.lower())
                except ValueError:
                    continue
            unexpected = sorted(h for h in hosts if not domain_allowed(h, allowed_domains))
            if unexpected:
                output.append(finding("NET_EXTERNAL", "network", "medium", path, n, line,
                                      "Сетевой вызов к домену вне allowlist: " + ", ".join(unexpected)))
            elif not hosts:
                output.append(finding("NET_DYNAMIC", "network", "low", path, n, line,
                                      "Сетевой вызов: endpoint определяется динамически или не указан рядом"))
            if any(domain_allowed(h, sorted(GEO_HOSTS)) for h in hosts):
                output.append(finding("NET_GEO_API", "geolocation", "medium", path, n, line,
                                      "Обращение к известному сервису IP-геолокации"))
        if FS_DELETE.search(visible):
            output.append(finding("FS_DELETE", "filesystem", "medium", path, n, line,
                                  "Потенциально удаляющая операция с файловой системой"))
        if FS_WRITE.search(visible) or (re.search(r"\bopen\s*\(", visible) and re.search(r"\bopen\s*\([^\n]{0,120},\s*['\"][wax]['\"]", line)):
            output.append(finding("FS_WRITE", "filesystem", "low", path, n, line,
                                  "Операция записи или перемещения файлов: проверить назначение и путь"))
        if DECODE_EXEC.search(visible):
            output.append(finding("OBF_DECODE_EXEC", "obfuscation", "high", path, n, line,
                                  "Исполнение динамически декодируемого кода"))
        elif DYNAMIC_EVAL.search(visible):
            output.append(finding("OBF_DYNAMIC_EXEC", "obfuscation", "medium", path, n, line,
                                  "Динамическое исполнение кода требует ревью"))
        elif CHARCODE.search(visible) or LONG_BASE64.search(line):
            output.append(finding("OBF_ENCODING", "obfuscation", "low", path, n, line,
                                  "Возможное сокрытие строк или полезной нагрузки"))
    # Prefer AST control-flow correlation for syntactically valid Python: not line proximity.
    python_tree = None
    if suffix == ".py" and ast_mode != "off":
        try:
            python_tree = ast.parse(content, filename=path)
        except (SyntaxError, ValueError, MemoryError):
            pass
    ast_findings = ast_analysis.scan_python(path, content, allowed_domains, tree=python_tree) if python_tree is not None else None
    if context is not None:
        context.add(path, content, python_tree)
    if suffix == '.py' and ast_mode == 'off' and ast_stats is not None:
        ast_stats['disabled'] = ast_stats.get('disabled', 0) + 1
    if suffix == ".py" and ast_findings is None and ast_mode != "off":
        if ast_mode == "required":
            raise ScanError(f"Invalid Python syntax prevents AST analysis: {path}")
        if ast_stats is not None:
            ast_stats["degraded"] = ast_stats.get("degraded", 0) + 1
        if ast_warnings is not None:
            ast_warnings.append(f"AST diagnostic {path}: invalid Python syntax, pattern-only analysis")
    if ast_findings is not None and suffix == ".py":
        diagnostics: list[str] = []
        taint_findings = python_taint.scan_python_taint(path, content, allowed_domains, diagnostics, tree=python_tree) or []
        if diagnostics:
            diagnostic = f"AST partial analysis: {path}: {'; '.join(diagnostics)}"
            if ast_mode == "required":
                raise ScanError(diagnostic)
            if ast_warnings is not None:
                ast_warnings.append(diagnostic)
        if ast_stats is not None:
            name = "partial" if diagnostics else "parsed"
            ast_stats[name] = ast_stats.get(name, 0) + 1
        # AST findings replace line-based duplicates (including multiline calls).
        existing = {(item["rule"], item["line"]): item for item in output}
        for item in [*ast_findings, *taint_findings]:
            if item["rule"] == "TAINT_URL":
                existing.pop(("NET_DYNAMIC", item["line"]), None)
            if item["rule"] in {"NET_EXTERNAL", "NET_GEO_API"}:
                existing.pop(("NET_DYNAMIC", item["line"]), None)
            if item["rule"] == "OBF_DECODE_EXEC":
                existing.pop(("OBF_DYNAMIC_EXEC", item["line"]), None)
            existing[(item["rule"], item["line"])] = item
        return list(existing.values())
    # Polyglot syntax trees replace proximity correlation for supported grammars.
    tree_findings: list[dict[str, Any]] = []
    parsed = False
    if suffix in polyglot_ast.SUPPORTED and ast_mode != "off":
        tree_findings, diagnostic = polyglot_ast.scan_tree(path, content, allowed_domains)
        parsed = diagnostic is None or diagnostic.startswith("AST partial ")
        if ast_stats is not None:
            name = "partial" if diagnostic and parsed else "degraded" if diagnostic else "parsed"
            ast_stats[name] = ast_stats.get(name, 0) + 1
        if diagnostic:
            if ast_mode == "required":
                raise ScanError(diagnostic)
            if ast_warnings is not None:
                # Avoid one missing-grammar warning per file in large repositories.
                category = suffix if diagnostic.startswith("AST unavailable") else path
                identifier = f"{category}: {diagnostic.split(': ', 2)[-1]}"
                if not any(item.startswith(f"AST diagnostic {category}:") for item in ast_warnings):
                    ast_warnings.append(f"AST diagnostic {category}: {diagnostic}")
    elif suffix == ".py" and ast_findings is None and ast_mode == "required":
        raise ScanError(f"Invalid Python syntax prevents AST analysis: {path}")
    elif suffix in polyglot_ast.SUPPORTED and ast_stats is not None:
        ast_stats["disabled"] = ast_stats.get("disabled", 0) + 1
    # Targeted language-specific rules complement generic rules without executing source.
    extra = language_analysis.scan_language(path, content, allowed_domains)
    seen = {(item["rule"], item["line"]) for item in output}
    for item in extra:
        if (item["rule"], item["line"]) not in seen:
            output.append(item)
            seen.add((item["rule"], item["line"]))
    if parsed:
        current = {(item["rule"], item["line"]): item for item in output}
        for item in tree_findings:
            if item["rule"] in {"TAINT_URL", "AST_NET_EXTERNAL", "AST_NET_DYNAMIC"}:
                current.pop(("NET_DYNAMIC", item["line"]), None)
            current[(item["rule"], item["line"])] = item
        return list(current.values())
    # Fallback for other languages and syntactically incomplete Python.
    # Stronger suspicion only when a geography decision is near an actionable operation.
    targets = [item for item in output if item["rule"] == "GEO_TARGET"]
    actions = [item for item in output if item["rule"] in {"FS_DELETE", "FS_WRITE", "NET_EXTERNAL", "NET_DYNAMIC"}]
    for geo in targets:
        for action in actions:
            if abs(action["line"] - geo["line"]) <= 15:
                output.append(finding("GEO_ACTION", "correlation", "high", path, action["line"],
                                      action["evidence"],
                                      f"Географическая проверка рядом с {action['rule']} (строка {geo['line']}); проверить поток управления"))
                break
    return output


def build_report(source: str, files: Iterable[tuple[str, str]], political_terms: list[str],
                 allowed_domains: list[str], warnings: list[str], watchlists: dict | None = None,
                 repository: str | None = None, package_repos: list[str] | None = None,
                 dependency_mode: str = "lock", dependency_max_packages: int = 2000,
                 dependency_max_depth: int = 12, dependency_max_requests: int = 300,
                 explicit_packages: list[str] | None = None,
                 ast_mode: str = "auto", malware_mode: str = "off",
                 malware_max_packages: int = 100, malware_max_requests: int = 120,
                 max_files: int = 10000, max_total_bytes: int = 100_000_000,
                 coverage: Coverage | None = None, advisory_snapshot=None,
                 malware_max_pages: int = 10, malware_retries: int = 1,
                 malware_time_budget: float = 120, go_builds=None, analysis_settings=None) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    scanned = 0
    total_bytes = 0
    ast_stats: dict[str, int] = {"parsed": 0, "partial": 0, "degraded": 0, "disabled": 0}
    ast_warnings: list[str] = []
    manifests: dict[str, str] = {}
    references: list[tuple[str, str, int, str]] = []
    coverage = coverage if coverage is not None else Coverage()
    context = analysis_context.Collector()
    if repository and watchlists is not None:
        references.append((repository.casefold(), "(repository)", 0, repository))
    for name in package_repos or []:
        owner, repo = github_coordinates(name)
        if watchlists is not None:
            references.append((f"{owner}/{repo}".casefold(), "(package)", 0, name))
    for path, content in files:
        if coverage.enumeration == 'provided':
            coverage.record(path, 'scanned', size=len(content.encode('utf-8')))
        scanned += 1
        total_bytes += len(content.encode("utf-8"))
        if scanned > max_files or total_bytes > max_total_bytes:
            raise ScanError("Total source file/byte budget exceeded; scan is incomplete")
        try:
            previous_stats = ast_stats.copy()
            results.extend(scan_text(path, content, political_terms, allowed_domains,
                                     ast_mode=ast_mode, ast_warnings=ast_warnings, ast_stats=ast_stats, context=context))
        except RecursionError as error:
            raise ScanError(f"Analysis nesting limit exceeded: {path}") from error
        status = next((key for key in ("partial", "degraded", "parsed", "disabled")
                       if ast_stats[key] > previous_stats[key]), "unsupported")
        if ast_mode == "off" and Path(path).suffix.lower() == ".py":
            status = "disabled"
        coverage.analyzed(Path(path).suffix.lower(), len(content.encode("utf-8")), status)
        if dependency_mode != "off" and threat_intel.is_manifest(path):
            manifests[path] = content
        if watchlists is not None:
            references.extend((repo, path, line, evidence)
                              for repo, line, evidence in threat_intel.scan_manifests(path, content))
    ingestion_complete = not warnings
    for build in go_builds or []:
        for path, checksum in coverage.raw_hashes.items():
            relevant = any(go_build_info.within(path, root) for root in build['module_roots']) and (
                Path(path).suffix.lower() in go_build_info.NATIVE or Path(path).name in go_build_info.METADATA)
            if (path in build['inputs'] and build['inputs'][path] != checksum) or (relevant and path not in build['inputs']):
                raise ScanError('Go build-info no longer matches the inputs observed during analysis')
    dependencies = dependency_analysis.analyze_dependencies(
        manifests, mode=dependency_mode, max_packages=dependency_max_packages,
        max_depth=dependency_max_depth, max_requests=dependency_max_requests,
        explicit_packages=explicit_packages, go_builds=go_builds)
    if not ingestion_complete:
        dependencies["summary"]["complete"] = False
        dependencies["summary"].setdefault("warnings", []).append("Source files were skipped or unreadable; dependency coverage is unknown")
    if watchlists is not None:
        references.extend(dependencies["references"])
    code_levels = [item["severity"] for item in results if item["severity"] != "info"]
    code_risk = max(code_levels, key=lambda s: SEVERITIES[s], default="none")
    if watchlists is not None:
        matches = threat_intel.match_repositories(references, watchlists)
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for pkg in dependencies["packages"]:
            if pkg["repository"]:
                by_repo.setdefault(pkg["repository"], []).append({
                    "ecosystem": pkg["ecosystem"], "name": pkg["name"],
                    "version": pkg["version"], "direct": pkg["direct"],
                    "via": pkg["via"], "source": pkg["source"]})
        for match in matches:
            if match.get("repository") in by_repo:
                match["matched_packages"] = by_repo[match["repository"]][:20]
        results.extend(matches)
        results.extend(threat_intel.match_packages(dependencies["packages"], watchlists))
    advisory_check = malware_intel.check_packages(
        dependencies["packages"], mode=malware_mode,
        max_packages=malware_max_packages, max_requests=malware_max_requests,
        inventory_complete=dependencies["summary"].get("complete", False), snapshot=advisory_snapshot,
        max_pages=malware_max_pages, retries=malware_retries, time_budget=malware_time_budget)
    results.extend(advisory_check["findings"])
    warnings.extend(advisory_check["warnings"])
    results.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    warnings.extend(ast_warnings)
    levels = {name: sum(f["severity"] == name for f in results) for name in SEVERITIES}
    technical = [f for f in results if f["severity"] != "info"]
    risk = max((technical_item["severity"] for technical_item in technical),
               key=lambda s: SEVERITIES[s], default="none")
    settings = {'ast_mode': ast_mode, 'profile': coverage.profile, 'allowed_domains': sorted(allowed_domains),
                'political_terms': sorted(political_terms), 'dependency_mode': dependency_mode,
                'dependency_limits': [dependency_max_packages, dependency_max_depth, dependency_max_requests],
                'explicit_packages': sorted(explicit_packages or []), 'package_repos': sorted(package_repos or []),
                'repository': repository, 'malware_mode': malware_mode,
                'malware_limits': [malware_max_packages, malware_max_requests, malware_max_pages, malware_retries, malware_time_budget],
                'source_limits': [max_files, max_total_bytes],
                'watchlists': {key: value for key, value in (watchlists or {}).items() if key != 'metadata'},
                'extra': analysis_settings or {}}
    review_context = context.finish(settings, dependencies, polyglot=ast_mode != 'off' and any(
        extension in polyglot_ast.SUPPORTED for extension in coverage.languages))
    return {"tool": "protestware-check", "version": VERSION, "source": source, "files_scanned": scanned,
            'analysis_context': review_context,
            "scan": {"complete": ingestion_complete}, "coverage": coverage.as_dict(),
            "risk": risk, "code_risk": code_risk, "summary": levels, "findings": results,
            "watchlists": watchlists["metadata"] if watchlists else {"mode": "off"},
            "malware_intel": advisory_check["metadata"],
            "dependencies": {"summary": dependencies["summary"], "packages": dependencies["packages"],
                             "mode": dependencies["mode"], 'go_builds': dependencies.get('go_builds', [])},
            "warnings": warnings, "ast": {"mode": ast_mode, **ast_stats,
                                         "complete": ast_stats["degraded"] == 0 and ast_stats["partial"] == 0 and
                                                     ast_stats["parsed"] > 0 and ast_mode != "off"}}


def report_text(report: dict[str, Any]) -> str:
    lines = [f"Source: {report['source']} | files: {report['files_scanned']} | "
             f"review risk: {report['risk']} (code: {report['code_risk']})",
             "Findings: " + ", ".join(f"{k}={v}" for k, v in report["summary"].items())]
    dep = report["dependencies"]
    if dep["mode"] != "off":
        lines.append(f"Dependencies: {dep['summary']['count']} | complete: "
                     f"{dep['summary']['complete']} | ecosystems: {dep['summary'].get('ecosystems', {})}")
    intel = report.get("malware_intel", {})
    if intel.get("mode") != "off":
        lines.append(f"Malware advisories: {intel.get('mode')} | queried: {intel.get('checked_packages')} | "
                     f"complete: {intel.get('complete')} | inventory complete: {intel.get('inventory_complete')}")
    for item in report["findings"]:
        lines.append(f"[{item['severity'].upper()}] {item['rule']} {item['file']}:{item['line']} — {item['message']}")
        lines.append(f"    {item['evidence']}")
    for warning in report.get("warnings", []) + dep["summary"].get("warnings", []):
        lines.append(f"Warning: {warning}")
    if "coverage" in report:
        coverage = report["coverage"]
        lines.append(f"Coverage: profile={coverage['profile']} | analyzed={coverage['files_analyzed']} | "
                     f"file outcomes={coverage['file_counts']} | pruned directories={coverage['pruned_directories']}")
    if "policy" in report:
        lines.append(f"Policy risk: {report['policy']['risk']} | decisions={report['policy']['counts']} | "
                     f"gate exit={report['gate']['exit_code']}")
    return "\n".join(lines) + "\n"


def output_text(report: dict[str, Any]) -> None:
    print(report_text(report), end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static protestware indicator scanner; never executes target code")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--path", type=Path, default=Path("."), help="Local directory (default: current)")
    selector.add_argument("--repo", help="GitHub OWNER/REPO or https://github.com/OWNER/REPO")
    parser.add_argument("--ref", help="GitHub branch, tag, or commit (only with --repo)")
    parser.add_argument("--format", choices=("text", "json", "sarif", "cyclonedx"), default="text")
    parser.add_argument("--ast-mode", choices=("auto", "required", "off"), default="auto",
                        help="Auto: AST if available; required: fail on missing/partial AST for supported languages only; off: legacy patterns")
    parser.add_argument("--output", type=Path, help="Write selected report format to this file (default: stdout)")
    parser.add_argument("--fail-on", choices=("low", "medium", "high"), default=None)
    parser.add_argument("--profile", choices=("source", "artifact"), default=None,
                        help="Source defaults or distributed artifacts, including bundles/builds/node_modules")
    parser.add_argument("--coverage-max-samples", type=int, default=100)
    parser.add_argument("--policy", type=Path, help="Explicit trusted TOML policy; never auto-loaded from scanned source")
    parser.add_argument("--baseline", type=Path, help="Reviewed fingerprint baseline JSON")
    parser.add_argument("--write-baseline", type=Path, help="Export finding fingerprints to a separate JSON file")
    comparison = parser.add_mutually_exclusive_group()
    comparison.add_argument("--only-new", action="store_true", default=None,
                            help="Apply the risk threshold to new findings and known findings whose review context changed")
    comparison.add_argument("--all-findings", dest="only_new", action="store_false")
    parser.add_argument("--allow-domain", action="append", default=[], help="Trusted domain and subdomains; repeatable")
    parser.add_argument("--exclude", action="append", default=[], help="Additional file/directory glob; repeatable")
    parser.add_argument("--political-terms-file", type=Path, help="One extra literal phrase per line (UTF-8)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-total-bytes", type=int, default=100_000_000)
    parser.add_argument("--watchlists", choices=("off", "live", "offline"), default="off",
                        help="Check toxic-repos and black-mark (off by default)")
    parser.add_argument("--black-mark-file", type=Path, help="Local black-mark README.md for offline mode")
    parser.add_argument("--toxic-repos-file", type=Path, help="Local toxic-repos JSON for offline mode")
    parser.add_argument("--package-repo", action="append", default=[],
                        help="Extra GitHub package OWNER/REPO to check; repeatable")
    parser.add_argument("--dependencies", choices=("off", "lock", "registry"), default="lock",
                        help="Inventory transitive packages: off/lockfiles/live official registries")
    parser.add_argument("--package", action="append", default=[],
                        help="Exact or constrained registry package, e.g. npm:axios@1.7.7 or pypi:requests@2.32.3")
    parser.add_argument("--dependency-max-packages", type=int, default=2000)
    parser.add_argument("--dependency-max-depth", type=int, default=12)
    parser.add_argument("--dependency-max-requests", type=int, default=300)
    parser.add_argument("--dependency-strict", action="store_true",
                        help="Exit 2 when dependency analysis is incomplete")
    parser.add_argument('--go-build-info', action='append', type=Path, default=[], help='Explicit trusted Go build-info export; repeat for separate profiles')
    parser.add_argument('--source-revision', help='Expected source revision for imported Go exports')
    parser.add_argument('--project-id', help='Stable project identity to bind reviewed baselines across CI workspaces')
    parser.add_argument("--malware-intel", choices=("off", "osv", "github", "both"), default="off",
                        help="Opt-in version-specific malware advisories (OSV/OpenSSF and GitHub)")
    parser.add_argument("--malware-max-packages", type=int, default=100,
                        help="Maximum distinct pinned packages queried against malware advisories")
    parser.add_argument("--malware-max-requests", type=int, default=120,
                        help="Maximum public advisory API requests")
    parser.add_argument("--malware-strict", action="store_true",
                        help="Exit 2 if advisory checks or the dependency inventory are incomplete")
    parser.add_argument('--malware-max-pages', type=int, default=10)
    parser.add_argument('--malware-retries', type=int, default=1)
    parser.add_argument('--malware-time-budget', type=float, default=120,
                        help='Seconds across advisory requests/retries; each request has at most 12 seconds socket timeout')
    parser.add_argument('--advisory-cache', type=Path, help='Explicit trusted snapshot JSON outside the scanned source')
    parser.add_argument('--advisory-cache-max-age', type=int, default=86400)
    parser.add_argument('--advisory-offline', action='store_true', help='Use fresh snapshot entries only; requires local input and lock dependencies')
    args = parser.parse_args(argv)
    try:
        policy = scan_policy.load(args.policy)
        baseline_values = scan_policy.load_baseline(args.baseline)
        args.profile = args.profile or policy['scan'].get('profile', 'source')
        args.fail_on = args.fail_on or policy['gate'].get('fail_on', 'high')
        args.only_new = args.only_new if args.only_new is not None else policy['gate'].get('only_new', False)
        args.exclude = policy['scan'].get('exclude', []) + args.exclude
        args.allow_domain = policy['scan'].get('allow_domains', []) + args.allow_domain
        if args.only_new and baseline_values is None:
            raise ValueError('--only-new requires --baseline')
        if not 0 <= args.coverage_max_samples <= 10000:
            raise ValueError('--coverage-max-samples must be between 0 and 10000')
        if args.write_baseline and args.output and args.write_baseline.resolve() == args.output.resolve():
            raise ValueError('Report and baseline outputs must differ')
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.ref and not args.repo:
        parser.error("--ref requires --repo")
    if min(args.max_bytes, args.max_files, args.max_total_bytes) < 1:
        parser.error("source file/byte limits must be positive")
    if args.dependency_max_packages < 1 or args.dependency_max_depth < 1 or args.dependency_max_requests < 1:
        parser.error("dependency limits must be positive")
    if args.package and args.dependencies == "off":
        parser.error("--package requires --dependencies lock or registry")
    if args.dependency_strict and args.dependencies == "off":
        parser.error("--dependency-strict requires dependency analysis")
    if args.go_build_info and (args.repo or args.dependencies != 'lock' or not args.source_revision or not go_build_info.REVISION.fullmatch(args.source_revision)):
        parser.error('--go-build-info requires local input, lock mode and an exact --source-revision')
    if args.project_id and (len(args.project_id) > 256 or any(ord(ch) < 32 for ch in args.project_id)):
        parser.error('Invalid --project-id')
    if args.malware_max_packages < 1 or args.malware_max_requests < 1:
        parser.error("malware-intel limits must be positive")
    if args.malware_intel != "off" and args.dependencies == "off":
        parser.error("--malware-intel requires --dependencies lock or registry")
    if args.malware_strict and args.malware_intel == "off":
        parser.error("--malware-strict requires --malware-intel osv, github or both")
    if not (1 <= args.malware_max_pages <= 100 and 0 <= args.malware_retries <= 3 and 0 < args.malware_time_budget <= 3600):
        parser.error('Invalid advisory page/retry/time limits')
    if args.advisory_cache and args.malware_intel == 'off':
        parser.error('--advisory-cache requires an enabled --malware-intel mode')
    if args.advisory_offline and (not args.advisory_cache or args.repo or args.dependencies != 'lock' or args.watchlists == 'live'):
        parser.error('--advisory-offline requires --advisory-cache, local input, lock dependencies and no live watchlists')
    if args.advisory_cache and not args.advisory_offline and not args.repo and args.advisory_cache.resolve().is_relative_to(args.path.resolve()):
        parser.error('Writable advisory cache must be outside the scanned source')
    inputs = [path.resolve() for path in (args.policy, args.baseline, args.advisory_cache, *args.go_build_info) if path is not None]
    outputs = [path.resolve() for path in (args.output, args.write_baseline) if path is not None]
    if any(path in inputs for path in outputs):
        parser.error('Outputs must differ from policy, baseline and snapshot inputs')
    domains = [x.lower().strip(".") for x in args.allow_domain]
    if any(not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", x) for x in domains):
        parser.error("--allow-domain expects a DNS domain, e.g. api.example.org")
    phrases = [s.casefold() for s in POLITICAL_TERMS]
    try:
        go_builds = [go_build_info.load(path, args.path, args.source_revision, max_files=args.max_files,
                                        max_bytes=args.max_bytes, max_total_bytes=args.max_total_bytes) for path in args.go_build_info]
        snapshot = AdvisoryCache(args.advisory_cache, mode='offline' if args.advisory_offline else 'readwrite',
                                 max_age=args.advisory_cache_max_age) if args.advisory_cache else None
        if args.political_terms_file:
            phrases.extend(line.strip().casefold() for line in args.political_terms_file.read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
        watchlists = threat_intel.load_watchlists(args.watchlists, args.black_mark_file, args.toxic_repos_file)
        packages = []
        for value in args.package_repo:
            owner, name = github_coordinates(value)
            packages.append(f"{owner}/{name}")
        warnings: list[str] = []
        coverage = Coverage(args.profile, enumeration='github' if args.repo else 'local', sample_limit=args.coverage_max_samples)
        if args.repo:
            files = iter_github(args.repo, args.ref, args.max_bytes, args.exclude, warnings, coverage, args.profile)
            source = args.repo + (f"@{args.ref}" if args.ref else "")
        else:
            files = iter_local(args.path, args.max_bytes, args.exclude, warnings, coverage, args.profile)
            source = str(args.path.resolve())
        root_repo = "/".join(github_coordinates(args.repo)) if args.repo else None
        report = build_report(source, files, phrases, domains, warnings,
                              watchlists=watchlists, repository=root_repo, package_repos=packages,
                              dependency_mode=args.dependencies,
                              dependency_max_packages=args.dependency_max_packages,
                              dependency_max_depth=args.dependency_max_depth,
                              dependency_max_requests=args.dependency_max_requests,
                              explicit_packages=args.package, ast_mode=args.ast_mode,
                              malware_mode=args.malware_intel,
                              malware_max_packages=args.malware_max_packages,
                              malware_max_requests=args.malware_max_requests,
                              max_files=args.max_files, max_total_bytes=args.max_total_bytes, coverage=coverage,
                              advisory_snapshot=snapshot, malware_max_pages=args.malware_max_pages,
                              malware_retries=args.malware_retries, malware_time_budget=args.malware_time_budget,
                              go_builds=go_builds, analysis_settings={'project_id': args.project_id,
                                  'exclude': sorted(args.exclude), 'max_bytes': args.max_bytes})
        if snapshot is not None:
            snapshot.save()
        scan_policy.apply(report, policy, baseline_values=baseline_values, only_new=args.only_new,
                          fail_on=args.fail_on, dependency_strict=args.dependency_strict,
                          malware_strict=args.malware_strict, ast_required=args.ast_mode == 'required')
        if args.write_baseline:
            safe_io.atomic_write(args.write_baseline, json.dumps(scan_policy.baseline(report), indent=2) + '\n',
                                 source_root=None if args.repo else args.path)
    except (ScanError, threat_intel.WatchlistError, ValueError, OSError, UnicodeError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    if args.format == "sarif":
        rendered = json.dumps(report_formats.sarif(report), ensure_ascii=False, indent=2) + "\n"
    elif args.format == "cyclonedx":
        rendered = json.dumps(report_formats.cyclonedx(report), ensure_ascii=False, indent=2) + "\n"
    elif args.format == "json":
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    else:
        rendered = None
    if args.output:
        try:
            safe_io.atomic_write(args.output, rendered if rendered is not None else report_text(report),
                                 source_root=None if args.repo else args.path)
        except OSError as err:
            print(f"Error: Cannot write report: {type(err).__name__}", file=sys.stderr)
            return 2
    elif rendered is not None:
        print(rendered, end="")
    else:
        output_text(report)
    return report['gate']['exit_code']


if __name__ == "__main__":
    sys.exit(main())
