#!/usr/bin/env python3
"""Non-executing heuristic scanner for potentially harmful protestware patterns."""

from __future__ import annotations

import argparse

import ast_analysis
import threat_intel
import dependency_analysis
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
from urllib.request import Request, urlopen

VERSION = "0.3.0"
DEFAULT_MAX_BYTES = 1_000_000
CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs",
    ".java", ".kt", ".rb", ".php", ".sh", ".bash", ".ps1", ".cs", ".c",
    ".cc", ".cpp", ".h", ".hpp", ".swift", ".lua", ".pl", ".r",
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
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "protestware-check/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(url, headers=headers), timeout=20) as response:
            return json.load(response)
    except HTTPError as err:
        raise ScanError(f"GitHub API returned HTTP {err.code}; check access, rate limit or ref") from err
    except (URLError, OSError, ValueError, json.JSONDecodeError) as err:
        raise ScanError(f"GitHub API request failed: {type(err).__name__}") from err


def is_scannable(path: str, extra_exclude: list[str]) -> bool:
    if any(part in EXCLUDED_DIRS for part in Path(path).parts):
        return False
    if any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(Path(path).name, p)
           for p in extra_exclude):
        return False
    if threat_intel.is_manifest(path):
        return True
    if any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(Path(path).name, p)
           for p in EXCLUDED_GLOBS):
        return False
    return Path(path).suffix.lower() in TEXT_SUFFIXES or Path(path).name in {"Dockerfile", "Makefile"}


def iter_local(root: Path, max_bytes: int, exclude: list[str], warnings: list[str]) -> Iterable[tuple[str, str]]:
    if not root.is_dir() or root.is_symlink():
        raise ScanError("--path must point to a real directory (not a symlink)")
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(base, d).is_symlink()
                         or d in EXCLUDED_DIRS
                         or any(fnmatch.fnmatch(d, p) for p in exclude)))
        for filename in sorted(files):
            actual = Path(base, filename)
            relative = actual.relative_to(root).as_posix()
            if actual.is_symlink() or not is_scannable(relative, exclude):
                continue
            try:
                if actual.stat().st_size > max_bytes:
                    warnings.append(f"Skipped oversized file: {relative}")
                    continue
                content = actual.read_bytes()
            except OSError as err:
                warnings.append(f"Could not read {relative}: {type(err).__name__}")
                continue
            if b"\x00" in content:
                continue
            yield relative, content.decode("utf-8-sig", errors="replace")


def iter_github(repo: str, ref: str | None, max_bytes: int, exclude: list[str], warnings: list[str]) -> Iterable[tuple[str, str]]:
    owner, name = github_coordinates(repo)
    token = os.environ.get("GITHUB_TOKEN")
    prefix = f"https://api.github.com/repos/{owner}/{name}"
    metadata = api_json(prefix, token)
    branch = ref or metadata.get("default_branch")
    if not branch:
        raise ScanError("Repository has no default branch")
    tree = api_json(f"{prefix}/git/trees/{quote(branch, safe='')}?recursive=1", token)
    if tree.get("truncated"):
        raise ScanError("GitHub tree was truncated; refusing to report partial results")
    if not isinstance(tree.get("tree"), list):
        raise ScanError("Invalid GitHub tree response")
    for item in sorted(tree["tree"], key=lambda obj: obj.get("path", "")):
        path = item.get("path", "")
        if item.get("type") != "blob" or item.get("mode") == "120000" or not is_scannable(path, exclude):
            continue
        if item.get("size", 0) > max_bytes:
            warnings.append(f"Skipped oversized file: {path}")
            continue
        sha = item.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            warnings.append(f"Missing blob SHA: {path}")
            continue
        blob = api_json(f"{prefix}/git/blobs/{sha}", token)
        if blob.get("encoding") != "base64":
            warnings.append(f"Unsupported blob encoding: {path}")
            continue
        try:
            raw = base64.b64decode(blob["content"], validate=False)
        except (KeyError, TypeError, ValueError) as err:
            raise ScanError(f"Invalid blob content: {path}") from err
        if len(raw) > max_bytes:
            warnings.append(f"Skipped oversized blob: {path}")
            continue
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


def scan_text(path: str, content: str, political_terms: list[str], allowed_domains: list[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    lines = content.splitlines()
    code_lines = python_code_only_lines(content) if Path(path).suffix.lower() == ".py" else lines
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
                parsed = urlparse(address.rstrip(".,;"))
                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())
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
    ast_findings = ast_analysis.scan_python(path, content, allowed_domains)
    if ast_findings is not None and Path(path).suffix.lower() == ".py":
        # AST findings replace line-based duplicates (including multiline calls).
        existing = {(item["rule"], item["line"]): item for item in output}
        for item in ast_findings:
            if item["rule"] in {"NET_EXTERNAL", "NET_GEO_API"}:
                existing.pop(("NET_DYNAMIC", item["line"]), None)
            if item["rule"] == "OBF_DECODE_EXEC":
                existing.pop(("OBF_DYNAMIC_EXEC", item["line"]), None)
            existing[(item["rule"], item["line"])] = item
        return list(existing.values())
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
                 explicit_packages: list[str] | None = None) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    scanned = 0
    manifests: dict[str, str] = {}
    references: list[tuple[str, str, int, str]] = []
    if repository and watchlists is not None:
        references.append((repository.casefold(), "(repository)", 0, repository))
    for name in package_repos or []:
        owner, repo = github_coordinates(name)
        if watchlists is not None:
            references.append((f"{owner}/{repo}".casefold(), "(package)", 0, name))
    for path, content in files:
        scanned += 1
        results.extend(scan_text(path, content, political_terms, allowed_domains))
        if dependency_mode != "off" and threat_intel.is_manifest(path):
            manifests[path] = content
        if watchlists is not None:
            references.extend((repo, path, line, evidence)
                              for repo, line, evidence in threat_intel.scan_manifests(path, content))
    dependencies = dependency_analysis.analyze_dependencies(
        manifests, mode=dependency_mode, max_packages=dependency_max_packages,
        max_depth=dependency_max_depth, max_requests=dependency_max_requests,
        explicit_packages=explicit_packages)
    if any(threat_intel.is_manifest(text.split(": ", 1)[-1]) for text in warnings
           if text.startswith(("Skipped oversized file:", "Skipped oversized blob:"))):
        dependencies["summary"]["complete"] = False
        dependencies["summary"].setdefault("warnings", []).append("Some dependency manifests were skipped due to size limits")
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
    results.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    levels = {name: sum(f["severity"] == name for f in results) for name in SEVERITIES}
    technical = [f for f in results if f["severity"] != "info"]
    risk = max((technical_item["severity"] for technical_item in technical),
               key=lambda s: SEVERITIES[s], default="none")
    return {"tool": "protestware-check", "version": VERSION, "source": source, "files_scanned": scanned,
            "risk": risk, "code_risk": code_risk, "summary": levels, "findings": results,
            "watchlists": watchlists["metadata"] if watchlists else {"mode": "off"},
            "dependencies": {"summary": dependencies["summary"], "packages": dependencies["packages"],
                             "mode": dependencies["mode"]},
            "warnings": warnings}


def output_text(report: dict[str, Any]) -> None:
    print(f"Source: {report['source']} | files: {report['files_scanned']} | review risk: {report['risk']} (code: {report['code_risk']})")
    print("Findings: " + ", ".join(f"{k}={v}" for k, v in report["summary"].items()))
    dep = report["dependencies"]
    if dep["mode"] != "off":
        print(f"Dependencies: {dep['summary']['count']} | complete: {dep['summary']['complete']} | "
              f"ecosystems: {dep['summary'].get('ecosystems', {})}")
    for item in report["findings"]:
        print(f"[{item['severity'].upper()}] {item['rule']} {item['file']}:{item['line']} — {item['message']}")
        print(f"    {item['evidence']}")
    for warning in report["warnings"] + report["dependencies"]["summary"].get("warnings", []):
        print(f"Warning: {warning}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static protestware indicator scanner; never executes target code")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--path", type=Path, default=Path("."), help="Local directory (default: current)")
    selector.add_argument("--repo", help="GitHub OWNER/REPO or https://github.com/OWNER/REPO")
    parser.add_argument("--ref", help="GitHub branch, tag, or commit (only with --repo)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=("low", "medium", "high"), default="high")
    parser.add_argument("--allow-domain", action="append", default=[], help="Trusted domain and subdomains; repeatable")
    parser.add_argument("--exclude", action="append", default=[], help="Additional file/directory glob; repeatable")
    parser.add_argument("--political-terms-file", type=Path, help="One extra literal phrase per line (UTF-8)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
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
    args = parser.parse_args(argv)
    if args.ref and not args.repo:
        parser.error("--ref requires --repo")
    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")
    if args.dependency_max_packages < 1 or args.dependency_max_depth < 1 or args.dependency_max_requests < 1:
        parser.error("dependency limits must be positive")
    if args.package and args.dependencies == "off":
        parser.error("--package requires --dependencies lock or registry")
    if args.dependency_strict and args.dependencies == "off":
        parser.error("--dependency-strict requires dependency analysis")
    domains = [x.lower().strip(".") for x in args.allow_domain]
    if any(not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", x) for x in domains):
        parser.error("--allow-domain expects a DNS domain, e.g. api.example.org")
    phrases = [s.casefold() for s in POLITICAL_TERMS]
    try:
        if args.political_terms_file:
            phrases.extend(line.strip().casefold() for line in args.political_terms_file.read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
        watchlists = threat_intel.load_watchlists(args.watchlists, args.black_mark_file, args.toxic_repos_file)
        packages = []
        for value in args.package_repo:
            owner, name = github_coordinates(value)
            packages.append(f"{owner}/{name}")
        warnings: list[str] = []
        if args.repo:
            files = iter_github(args.repo, args.ref, args.max_bytes, args.exclude, warnings)
            source = args.repo + (f"@{args.ref}" if args.ref else "")
        else:
            files = iter_local(args.path, args.max_bytes, args.exclude, warnings)
            source = str(args.path.resolve())
        root_repo = "/".join(github_coordinates(args.repo)) if args.repo else None
        report = build_report(source, files, phrases, domains, warnings,
                              watchlists=watchlists, repository=root_repo, package_repos=packages,
                              dependency_mode=args.dependencies,
                              dependency_max_packages=args.dependency_max_packages,
                              dependency_max_depth=args.dependency_max_depth,
                              dependency_max_requests=args.dependency_max_requests,
                              explicit_packages=args.package)
    except (ScanError, threat_intel.WatchlistError, ValueError, OSError, UnicodeError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        output_text(report)
    if args.dependency_strict and not report["dependencies"]["summary"].get("complete", False):
        return 2
    return int(SEVERITIES.get(report["risk"], 0) >= SEVERITIES[args.fail_on])


if __name__ == "__main__":
    sys.exit(main())
