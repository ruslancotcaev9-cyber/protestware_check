#!/usr/bin/env python3
"""Reproducible, read-only static audits of explicitly pinned public GitHub projects.

Never executes scanned source, runs package installers in a scanned checkout, or loads its scripts.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

SCANNER_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = SCANNER_ROOT / "audit-reports"
REPOS = [
    ("fmtlib/fmt", "main", "4ed3535092a96ac9f56fab80df83416d51bcc78e"),
    ("Neargye/magic_enum", "master", "7f7c70473857c47c6eb88261771c4ab3dc7616d4"),
    ("Anti-Prop/antiprop_basic", "main", "5df3875efa40082167b1c11012b7f4b2ad2f045a"),
]
WATCHLISTS = [
    ("black-mark.md", "toxic-repos/black-mark", "fa3aa4271b7550490a9754812a247d83c8f54994", "README.md"),
    ("toxic-repos.json", "toxic-repos/toxic-repos", "85621bdf82336c5e6f2a1b10f1efca1a37ffc4cb", "data/json/toxic-repos.json"),
]


def fetch_reference_lists() -> list[dict]:
    output = []
    sources = OUTPUT / "watchlists"
    sources.mkdir(parents=True, exist_ok=True)
    for filename, repo, sha, path in WATCHLISTS:
        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
        request = Request(url, headers={"User-Agent": "protestware-check-audit/2026-11-04"})
        with urlopen(request, timeout=45) as response:
            data = response.read(6_000_001)
        if len(data) > 6_000_000:
            raise RuntimeError(f"Watchlist too large: {filename}")
        data.decode("utf-8-sig")  # fail on encoding issues
        (sources / filename).write_bytes(data)
        output.append({"file": filename, "repository": repo, "commit": sha,
                       "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    return output


def clone_pinned(repo: str, branch: str, sha: str, workdir: Path) -> Path:
    target = workdir / repo.replace("/", "__")
    # Clone only; do not initialize submodules, install packages, or execute project hooks.
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--depth=1",
                    "--no-tags", "--single-branch", "--branch", branch,
                    f"https://github.com/{repo}.git", str(target)], check=True, timeout=180)
    actual = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    if actual != sha:
        raise RuntimeError(f"Unexpected commit for {repo}: actual {actual}, pinned {sha}")
    return target


def is_runtime_path(repo: str, path: str) -> bool:
    if repo == "fmtlib/fmt":
        return path.startswith(("include/", "src/"))
    if repo == "Neargye/magic_enum":
        return path.startswith(("include/", "module/"))
    if repo == "Anti-Prop/antiprop_basic":
        return path == "index.html" or path.startswith("scripts/")
    return False


def summarize(repo: str, commit: str, report: dict, exit_code: int) -> dict:
    findings = report.get("findings", [])
    code = [f for f in findings if f.get("category", "") not in (
        "context", "watchlist_context", "watchlist_repository", "watchlist_package")]
    production = [f for f in code if is_runtime_path(repo, f.get("file", ""))]
    watchlist = [f for f in findings if f.get("category", "").startswith("watchlist_")]
    return {
        "repo": repo, "commit": commit, "files_scanned": report["files_scanned"],
        "risk": report["risk"], "code_risk": report["code_risk"],
        "exit_code": exit_code, "counts_by_severity": report["summary"],
        "counts_by_rule": dict(Counter(x["rule"] for x in findings)),
        "production_findings_count": len(production),
        "production_findings_by_rule": dict(Counter(x["rule"] for x in production)),
        "code_findings_count": len(code),
        "watchlist": [{k: x.get(k) for k in ("rule", "repository", "record_ids", "references", "severity", "message", "watchlist")}
                      for x in watchlist],
        "dependencies": report["dependencies"]["summary"],
        "ast": report["ast"],
        "warnings": report.get("warnings", []),
        "production_findings": [
            {"rule": x["rule"], "file": x["file"], "line": x["line"],
             "severity": x["severity"], "message": x["message"],
             "evidence": x.get("evidence", "")[:200]} for x in production[:150]],
        "other_code_findings": [
            {"rule": x["rule"], "file": x["file"], "line": x["line"],
             "severity": x["severity"], "message": x["message"],
             "evidence": x.get("evidence", "")[:200]} for x in code if not is_runtime_path(repo, x["file"])][:120],
        "political_findings": [
            {"rule": x["rule"], "file": x["file"], "line": x["line"],
             "evidence": x.get("evidence", "")[:180]} for x in findings if x.get("rule") == "POLITICAL_RU"][:30],
    }


def markdown_report(s: dict) -> str:
    lines = [f"# Отчёт: `{s['repo']}`", "", "## Объект проверки", "",
             f"- Снимок GitHub: `{s['commit']}`.",
             f"- Сканер: protestware-check v0.6.0 (указанный коммит находится в audit-metadata.json).",
             f"- Прочитано файлов: **{s['files_scanned']}**.",
             f"- Сводный риск сканера: **{s['risk']}**, только код: **{s['code_risk']}**.",
             f"- Подозрительных конструкций в runtime-каталогах: **{s['production_findings_count']}**.",
             f"- Полнота AST: `{json.dumps(s['ast'], ensure_ascii=False)}`.",
             f"- Полнота анализа зависимостей: `{s['dependencies'].get('complete')}`; пакетов: `{s['dependencies'].get('count')}`.",
             "", "## Совпадения со сторонними базами", ""]
    for x in s["watchlist"]:
        lines.append(f"- **{x['rule']} / {x['severity']}**: {x['message']}; IDs: {x.get('record_ids') or 'нет'}.")
    if not s["watchlist"]:
        lines.append("Совпадений нет.")
    lines += ["", "## Сводка правил", "", "| Правило | Найдено | В runtime-коде |", "|---|---:|---:|"]
    for rule, count in sorted(s["counts_by_rule"].items()):
        lines.append(f"| `{rule}` | {count} | {s['production_findings_by_rule'].get(rule, 0)} |")
    lines += ["", "## Технические находки runtime-кода", "", "| Приоритет | Файл:строка | Правило | Описание |", "|---|---|---|---|"]
    for f in s["production_findings"]:
        desc = str(f["message"]).replace("|", "\\|").replace("\n", " ")[:180]
        location = f"{f['file']}:{f['line']}"
        lines.append(f"| {f['severity']} | `{location}` | `{f['rule']}` | {desc} |")
    if not s["production_findings"]:
        lines.append("| — | — | — | В runtime-коде эвристик не выявлено |")
    lines += ["", "## Ограничения", "",
              "Статический эвристический анализ. Отсутствие находок не доказывает отсутствие вредоносного поведения. ",
              "Для C/C++ полноценный AST-анализ в версии 0.6.0 не реализован. Для JS используется Tree-sitter. ",
              "Совпадения с toxic-repos или black-mark — внешние утверждения, требующие проверки, а не доказательство атаки.",
              "Никакой код проверяемых проектов не запускался, установка их зависимостей не производилась.",
              "", "## Предупреждения", ""]
    for w in (s["warnings"] + s["dependencies"].get("warnings", []))[:40]:
        lines.append(f"- {str(w)[:500]}")
    if not s["warnings"] and not s["dependencies"].get("warnings"):
        lines.append("Нет.")
    return "\n".join(lines) + "\n"


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    watch_metadata = fetch_reference_lists()
    metadata = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
                "targets": [{"repository": r, "branch": b, "commit": sha} for r, b, sha in REPOS],
                "watchlists": watch_metadata, "scanner_repo_commit": os.environ.get("GITHUB_SHA"),
                "scanner_flags": ["--watchlists offline", "--dependencies lock", "--ast-mode auto", "--fail-on high"],
                "security": "No execution, installation, or import of target projects"}
    (OUTPUT / "audit-metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    summaries = []
    errors = []
    sys.path.insert(0, str(SCANNER_ROOT))
    from report_formats import sarif, cyclonedx
    with tempfile.TemporaryDirectory(prefix="protestware-audit-") as tmp:
        for repo, branch, commit in REPOS:
            slug = repo.replace("/", "__")
            try:
                target = clone_pinned(repo, branch, commit, Path(tmp))
                output_file = OUTPUT / f"{slug}.json"
                args = [sys.executable, str(SCANNER_ROOT / "protestware_check.py"),
                        "--path", str(target), "--package-repo", repo,
                        "--watchlists", "offline",
                        "--black-mark-file", str(OUTPUT / "watchlists" / "black-mark.md"),
                        "--toxic-repos-file", str(OUTPUT / "watchlists" / "toxic-repos.json"),
                        "--dependencies", "lock", "--ast-mode", "auto",
                        "--fail-on", "high", "--format", "json", "--output", str(output_file)]
                run = subprocess.run(args, cwd=SCANNER_ROOT, text=True, capture_output=True, timeout=270)
                if run.returncode not in (0, 1) or not output_file.is_file():
                    raise RuntimeError(f"Scanner exit {run.returncode}: {run.stderr[-2000:]}")
                report = json.loads(output_file.read_text(encoding="utf-8"))
                (OUTPUT / f"{slug}.sarif").write_text(json.dumps(sarif(report), ensure_ascii=False, indent=2), encoding="utf-8")
                (OUTPUT / f"{slug}.cdx.json").write_text(json.dumps(cyclonedx(report), ensure_ascii=False, indent=2), encoding="utf-8")
                summary = summarize(repo, commit, report, run.returncode)
                summaries.append(summary)
                (OUTPUT / f"{slug}.md").write_text(markdown_report(summary), encoding="utf-8")
                print("AUDIT_SUMMARY::" + json.dumps(summary, ensure_ascii=False, separators=(",", ":")), flush=True)
                if run.stderr:
                    print(f"AUDIT_STDERR::{slug}::{run.stderr[-4000:]}", flush=True)
            except Exception as error:
                errors.append({"repo": repo, "error": f"{type(error).__name__}: {str(error)[:800]}"})
                print("AUDIT_ERROR::" + json.dumps(errors[-1], ensure_ascii=False), flush=True)
    (OUTPUT / "summary.json").write_text(json.dumps({"metadata": metadata, "summaries": summaries,
                                                       "errors": errors}, ensure_ascii=False, indent=2), encoding="utf-8")
    header = ["# Static protestware audit — 2026-11-04", "", "| Repository | Commit | Scanned | Code risk | Overall alert | Watchlist |", "|---|---|---:|---|---|---|"]
    for s in summaries:
        header.append(f"| {s['repo']} | `{s['commit'][:12]}` | {s['files_scanned']} | {s['code_risk']} | {s['risk']} | {', '.join(x['rule'] for x in s['watchlist'])} |")
    header += ["", "Raw JSON, SARIF, CycloneDX and per-repository Markdown reports are in this workflow artifact.", ""]
    summary_text = "\n".join(header)
    (OUTPUT / "SUMMARY.md").write_text(summary_text, encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(summary_text)
    if errors:
        raise SystemExit("One or more scans failed; see AUDIT_ERROR and reports")


if __name__ == "__main__":
    main()
