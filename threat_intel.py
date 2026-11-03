"""Read-only matching of explicit GitHub source identities against third-party watchlists.

Watchlist entries are unverified third-party reports, not a verdict about an author.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import unquote, urlparse

BLACK_MARK_URL = "https://raw.githubusercontent.com/toxic-repos/black-mark/main/README.md"
TOXIC_REPOS_URL = "https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json"
MAX_WATCHLIST_BYTES = 6_000_000
# Source code references are considered ONLY when in dependency manifests, not in README or comments.
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bower.json", "composer.json", "composer.lock", "pyproject.toml", "poetry.lock",
    "uv.lock", "pipfile", "pipfile.lock", "requirements.txt", "setup.cfg", "setup.py",
    "cargo.toml", "cargo.lock", "go.mod", "gemfile", "gemfile.lock", ".gitmodules",
    "deno.json", "deno.lock", "mix.exs", "mix.lock", "gopkg.toml", "gopkg.lock",
    "go.sum", "pylock.toml", "requirements-resolver.txt",
}
REQUIREMENTS_NAME = re.compile(r"(?:requirements[-_\w]*\.(?:txt|in)|.*\.requirements\.txt)", re.I)
GITHUB_REF = re.compile(
    r"(?i)(?<![\w.-])(?:"
    r"(?:https?://|git\+https://|git\+ssh://(?:git@)?|git://|ssh://(?:git@)?)(?:www\.)?github\.com/"
    r"|git@github\.com:|github\.com/|github:)"
    r"([a-z\d_.-]+)/([a-z\d_.-]+(?:\.git)?)"
    r"(?=$|[^a-z\d_.-])"
)
NAME = re.compile(r"^[a-zA-Z\d_.-]+/[a-zA-Z\d_.-]+$")
ACCOUNT_URL = re.compile(r"^\s*[*+-]?\s*https://github\.com/([A-Za-z\d_.-]+)/?\s*$", re.I)


class WatchlistError(Exception):
    """Watchlist could not be downloaded or parsed; the scan must not claim a clean match."""


def canonical(owner: str, name: str) -> str | None:
    owner, name = owner.strip().lower(), name.strip().removesuffix(".git").lower()
    if not NAME.fullmatch(f"{owner}/{name}") or owner in {".", ".."} or name in {".", ".."}:
        return None
    return f"{owner}/{name}"


def github_refs(text: str) -> set[str]:
    refs = set()
    for match in GITHUB_REF.finditer(text):
        repo = canonical(match.group(1), match.group(2))
        if repo:
            refs.add(repo)
    return refs


def is_manifest(path: str) -> bool:
    name = Path(path).name.lower()
    return name in MANIFEST_NAMES or bool(REQUIREMENTS_NAME.fullmatch(name))


def scan_manifests(path: str, content: str) -> list[tuple[str, int, str]]:
    if not is_manifest(path):
        return []
    return [(repo, n, line.strip()[:240])
            for n, line in enumerate(content.splitlines(), 1) for repo in sorted(github_refs(line))]


def parse_black_mark(text: str) -> set[str]:
    accounts = set()
    for line in text.splitlines():
        match = ACCOUNT_URL.fullmatch(line)
        if match and match.group(1).lower() not in {".", ".."}:
            accounts.add(match.group(1).lower())
    if not accounts:
        raise WatchlistError("black-mark has no recognizable GitHub accounts")
    return accounts


def parse_toxic_repos(text: str) -> dict[str, list[dict]]:
    try:
        records = json.loads(text)
    except (ValueError, TypeError) as err:
        raise WatchlistError("toxic-repos JSON is malformed") from err
    if not isinstance(records, list) or not records:
        raise WatchlistError("toxic-repos must contain a nonempty JSON array")
    output: dict[str, list[dict]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        repos = set()
        # 'commit_link' may point at a specific commit or file, so only the first owner/repo counts.
        source = record.get("commit_link")
        if isinstance(source, str):
            repos.update(github_refs(source))
        name = record.get("name")
        if not repos and isinstance(name, str) and NAME.fullmatch(name.strip()):
            parts = name.strip().split("/")
            repo = canonical(parts[0], parts[1])
            if repo:
                repos.add(repo)
        if not repos:
            continue
        compact = {"id": record.get("id"), "type": str(record.get("problem_type", "unknown")),
                   "link": source[:1000] if isinstance(source, str) else ""}
        for repo in repos:
            output.setdefault(repo, []).append(compact)
    if not output:
        raise WatchlistError("toxic-repos has no usable GitHub references")
    return output


def parse_toxic_packages(text: str) -> dict[tuple[str, str], list[dict]]:
    """Recognize explicit registry identities from PURL and known registry links.

    No inference from an arbitrary free-text name or a GitHub account is allowed.
    """
    try:
        records = json.loads(text)
    except (ValueError, TypeError) as err:
        raise WatchlistError("toxic-repos JSON is malformed") from err
    if not isinstance(records, list):
        raise WatchlistError("toxic-repos JSON is not an array")
    output: dict[tuple[str, str], list[dict]] = {}
    for row in records:
        if not isinstance(row, dict):
            continue
        ecosystem = name = version = None
        purl = row.get("PURL")
        if isinstance(purl, str):
            m = re.fullmatch(r"pkg:(npm|pypi|cargo|composer|golang|nuget)/([^?#]+)", purl, re.I)
            if m:
                ecosystem = {"golang": "go", "nuget": "nuget"}.get(m.group(1).lower(), m.group(1).lower())
                coordinate = unquote(m.group(2))
                if "@" in coordinate and not coordinate.startswith("@"):
                    name, version = coordinate.rsplit("@", 1)
                elif coordinate.startswith("@") and coordinate.count("@") > 1:
                    name, version = coordinate.rsplit("@", 1)
                else:
                    name = coordinate
        if not name and isinstance(row.get("PURL-link"), str):
            url = urlparse(row["PURL-link"])
            if url.scheme == "https" and url.hostname in {
                "www.npmjs.com", "pypi.org", "www.nuget.org", "crates.io", "packagist.org"
            }:
                path = unquote(url.path.strip("/"))
                if url.hostname == "www.npmjs.com" and path.startswith("package/"):
                    ecosystem, name = "npm", path.removeprefix("package/")
                elif url.hostname == "pypi.org" and path.startswith("project/"):
                    ecosystem, name = "pypi", path.removeprefix("project/").split("/")[0]
                elif url.hostname == "www.nuget.org" and path.lower().startswith("packages/"):
                    ecosystem, name = "nuget", path.split("/")[1]
                elif url.hostname == "crates.io" and path.startswith("crates/"):
                    ecosystem, name = "cargo", path.split("/")[1]
                elif url.hostname == "packagist.org" and path.startswith("packages/"):
                    ecosystem, name = "composer", path.removeprefix("packages/")
        if not name or not ecosystem or not re.fullmatch(r"[A-Za-z0-9@._/-]+", name):
            continue
        if ecosystem == "pypi":
            name = re.sub(r"[-_.]+", "-", name.lower())
        else:
            name = name.lower()
        output.setdefault((ecosystem, name), []).append({
            "id": row.get("id"), "type": str(row.get("problem_type", "unknown")),
            "version": version, "source": str(row.get("PURL") or row.get("PURL-link") or "")[:500]})
    return output


def match_packages(packages: list[dict], data: dict) -> list[dict]:
    """Exact ecosystem/name matching; version-qualified PURLs match only that version."""
    entries = data.get("packages", {})
    output = []
    seen = set()
    for pkg in packages:
        ecosystem, name = pkg["ecosystem"], pkg["name"].lower()
        if ecosystem == "pypi":
            name = re.sub(r"[-_.]+", "-", name)
        for record in entries.get((ecosystem, name), []):
            version = record.get("version")
            if version and version != pkg.get("version"):
                continue
            key = (ecosystem, name, pkg.get("version"), pkg["manifest"], record.get("id"))
            if key in seen:
                continue
            seen.add(key)
            output.append({
                "rule": "TOXIC_PACKAGE", "category": "watchlist_package",
                "severity": "info", "file": pkg["manifest"], "line": 0,
                "evidence": f"{ecosystem}:{pkg['name']}@{pkg['version']}",
                "message": "Точное совпадение имени пакета и экосистемы с записью toxic-repos; версия и контекст требуют проверки",
                "package": {"ecosystem": ecosystem, "name": pkg["name"], "version": pkg["version"],
                            "direct": pkg["direct"], "via": pkg.get("via", [])},
                "watchlist": "toxic-repos", "record_ids": [str(record["id"])],
                "record_type": record["type"], "reference": record["source"]})
    return output


def download_public_list(url: str) -> str:
    if url not in {BLACK_MARK_URL, TOXIC_REPOS_URL}:
        raise WatchlistError("Watchlist source is not approved")
    req = Request(url, headers={"User-Agent": "protestware-check/0.2", "Accept": "text/plain,application/json"})
    try:
        with urlopen(req, timeout=20) as response:
            data = response.read(MAX_WATCHLIST_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError) as err:
        raise WatchlistError(f"Could not retrieve {url}: {type(err).__name__}") from err
    if len(data) > MAX_WATCHLIST_BYTES:
        raise WatchlistError("Watchlist size limit exceeded")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as err:
        raise WatchlistError("Watchlist is not UTF-8") from err


def read_local_list(path: Path) -> str:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_WATCHLIST_BYTES:
            raise WatchlistError(f"Invalid watchlist file or excessive size: {path}")
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as err:
        raise WatchlistError(f"Could not read watchlist file: {path}") from err


def load_watchlists(mode: str, black_file: Path | None = None, toxic_file: Path | None = None) -> dict | None:
    if mode == "off":
        if black_file or toxic_file:
            raise WatchlistError("--*-file options require --watchlists offline")
        return None
    if mode == "offline":
        if not (black_file and toxic_file):
            raise WatchlistError("offline mode requires --black-mark-file and --toxic-repos-file")
        black_text, toxic_text = read_local_list(black_file), read_local_list(toxic_file)
        source_names = {"black_mark": str(black_file), "toxic_repos": str(toxic_file)}
    elif mode == "live":
        if black_file or toxic_file:
            raise WatchlistError("Use --watchlists offline with local --*-file options")
        black_text = download_public_list(BLACK_MARK_URL)
        toxic_text = download_public_list(TOXIC_REPOS_URL)
        source_names = {"black_mark": BLACK_MARK_URL, "toxic_repos": TOXIC_REPOS_URL}
    else:
        raise WatchlistError(f"Unsupported watchlist mode: {mode}")
    black = parse_black_mark(black_text)
    toxic = parse_toxic_repos(toxic_text)
    packages = parse_toxic_packages(toxic_text)
    return {"black": black, "toxic": toxic, "packages": packages, "metadata": {"mode": mode,
            "retrieved_at_utc": datetime.now(timezone.utc).isoformat(), "sources": source_names,
            "black_mark_accounts": len(black),
            "toxic_repositories": len(toxic), "toxic_packages": len(packages)}}


def severity_for_type(problem_type: str) -> str:
    # Third-party assertions are review leads, not proof of executed malware.
    return {"malware": "medium", "ddos": "medium", "hostile_actions": "medium",
            "ip_block": "low", "broken_assembly": "low", "political_slogans": "info"}.get(problem_type, "info")


def match_repositories(references: list[tuple[str, str, int, str]], data: dict) -> list[dict]:
    """references: [(owner/repo, file_path, line, evidence), ...]."""
    findings = []
    seen = set()
    for repo, path, line, evidence in references:
        if repo not in data["toxic"] and repo.split("/")[0] not in data["black"]:
            continue
        owner = repo.split("/")[0]
        if owner in data["black"] and ("BLACK_MARK_OWNER", repo, path) not in seen:
            seen.add(("BLACK_MARK_OWNER", repo, path))
            findings.append({"rule": "BLACK_MARK_OWNER", "category": "watchlist_context", "severity": "info",
                             "file": path, "line": line, "evidence": evidence[:240],
                             "message": f"Владелец {owner} присутствует в black-mark; это не подтверждение вредоносности",
                             "repository": repo, "watchlist": "black-mark"})
        entries = data["toxic"].get(repo, [])
        if entries and ("TOXIC_REPO", repo, path) not in seen:
            seen.add(("TOXIC_REPO", repo, path))
            classes = sorted({rec["type"] for rec in entries})
            level = max((severity_for_type(kind) for kind in classes),
                        key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3}[s])
            ids = sorted({str(rec["id"]) for rec in entries if rec["id"] is not None})
            links = sorted({rec["link"] for rec in entries if rec["link"].startswith("https://github.com/")})
            findings.append({"rule": "TOXIC_REPO", "category": "watchlist_repository", "severity": level,
                             "file": path, "line": line, "evidence": evidence[:240],
                             "message": f"Репозиторий {repo} упоминается в toxic-repos ({', '.join(classes)}); требуется ручная проверка",
                             "repository": repo, "watchlist": "toxic-repos", "record_ids": ids,
                             "references": links[:8]})
    return findings
