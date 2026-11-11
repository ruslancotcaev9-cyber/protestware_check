"""Conservative, non-executing multilingual syntactic heuristics.

This is NOT an AST parser for non-Python languages. Comment masking is intentionally
lightweight and errs on the side of warning rather than pretending to parse all
interpolated strings, macros and preprocessors.
"""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse
import sql_operations

SCRIPT_LANGS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".cs"}
STYLE_LANGS = {".css", ".scss", ".sass", ".less"}
SUPPORTED = SCRIPT_LANGS | STYLE_LANGS | {".sql", ".html", ".htm"}

# SQL also masks quoted literal/identifier contents, retaining offsets/delimiters.
def mask_comments(text: str, suffix: str) -> str:
    if suffix == '.sql':
        return sql_operations.mask(text)
    if suffix not in SUPPORTED:
        return text
    line_comment = ("//",) if suffix in SCRIPT_LANGS | STYLE_LANGS else (("--",) if suffix == ".sql" else ())
    block = ("<!--", "-->") if suffix in {".html", ".htm"} else ("/*", "*/")
    chars = list(text)
    i, n, quote = 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and suffix != ".sql":
                i += 2
                continue
            if ch == quote:
                if suffix == ".sql" and i + 1 < n and text[i + 1] == quote:
                    chars[i] = chars[i + 1] = " " if quote == "'" else "_"
                    i += 2
                    continue
                quote = ""
            elif suffix == ".sql" and ch != "\n":
                chars[i] = " " if quote == "'" else "_"
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            i += 1
            continue
        match = next((s for s in line_comment if text.startswith(s, i)), None)
        if match == "//" and suffix in STYLE_LANGS and re.search(r"https?:$", text[max(0, i - 6):i], re.I):
            i += 2  # Unquoted CSS url(https://...) is not a comment.
            continue
        if match:
            end = text.find("\n", i)
            if end == -1:
                end = n
            for j in range(i, end):
                chars[j] = " "
            i = end
            continue
        if text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            end = n if end == -1 else end + len(block[1])
            for j in range(i, end):
                if chars[j] != "\n":
                    chars[j] = " "
            i = end
            continue
        i += 1
    return "".join(chars)


def scan_language(path: str, source: str, allowed_domains: list[str]) -> list[dict]:
    """Emit distinct rule IDs; caller merges with generic heuristics."""
    suffix = Path(path).suffix.lower()
    if suffix not in SUPPORTED:
        return []
    cleaned = mask_comments(source, suffix)
    findings: list[dict] = []
    original_lines = source.splitlines()
    def emit(rule: str, category: str, severity: str, number: int, message: str) -> None:
        evidence = original_lines[number - 1].strip()[:240]
        findings.append({"rule": rule, "category": category, "severity": severity, "file": path,
                         "line": number, "evidence": evidence, "message": message,
                         "analysis": "language-pattern"})

    def domains_near(statement: str) -> list[str]:
        domains = set()
        for uri in re.findall(r"https?://[^\s\"'<>`\\)]+", statement, re.I):
            try:
                host = urlparse(uri.rstrip(",;)}")).hostname
                if host and not any(host.lower().rstrip(".") == value or
                                    host.lower().rstrip(".").endswith("." + value)
                                    for value in allowed_domains):
                    domains.add(host.lower())
            except ValueError:
                continue
        return sorted(domains)

    if suffix in STYLE_LANGS:
        pattern = re.compile(r"(?:@import\s+(?:url\s*\()?\s*['\"]?https?://|url\s*\(\s*['\"]?https?://)", re.I)
        for number, line in enumerate(cleaned.splitlines(), 1):
            if pattern.search(line) and domains_near(line):
                emit("STYLE_REMOTE_RESOURCE", "network", "low", number,
                     "Внешний ресурс CSS/Sass/Less: проверить необходимость, происхождение и отслеживание пользователей")
            if re.search(r"url\s*\([^)]*\\[0-9a-f]{2,6}(?:\s|\\)", line, re.I):
                emit("STYLE_OBFUSCATED_URL", "obfuscation", "medium", number,
                     "CSS URL содержит escape-последовательности, затрудняющие аудит адреса")
        return findings

    if suffix in {".html", ".htm"}:
        # Tags may span lines and attributes may appear in any order.
        tag_patterns = [
            ("script", "src", "HTML_REMOTE_SCRIPT", "medium", "HTML загружает внешний скрипт; проверить источник и SRI"),
            ("iframe", "src", "HTML_REMOTE_IFRAME", "low", "HTML встраивает внешний iframe"),
            ("link", "href", "HTML_REMOTE_STYLESHEET", "low", "HTML загружает внешний CSS-ресурс"),
        ]
        for tag, attribute, rule, severity, message in tag_patterns:
            for match in re.finditer(r"<\s*" + tag + r"\b[^>]*>", cleaned, re.I | re.S):
                content = match.group()
                attr = re.search(r"\b" + attribute + r"\s*=\s*['\"]?(https?://[^\s'\">]+)", content, re.I)
                if not attr or not domains_near(attr.group(1)):
                    continue
                if tag == "link" and not re.search(r"\brel\s*=\s*['\"]?stylesheet\b", content, re.I):
                    continue
                line = cleaned.count("\n", 0, match.start() + attr.start()) + 1
                emit(rule, "network", severity, line, message)
        for number, line in enumerate(cleaned.splitlines(), 1):
            if re.search(r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh\b", line, re.I):
                emit("HTML_REDIRECT", "network", "low", number,
                     "HTML автоматически перенаправляет пользователя")
        # Embedded scripts and styles are inspected without losing source line numbers.
        for tag, extension in (("script", "js"), ("style", "css")):
            for match in re.finditer(r"<" + tag + r"\b[^>]*>(.*?)</" + tag + r"\s*>", cleaned, re.I | re.S):
                inner = match.group(1)
                start = cleaned.count("\n", 0, match.start(1))
                original_lines = source.splitlines()
                for item in scan_language("inline." + extension, inner, allowed_domains):
                    number = start + item["line"]
                    if number > len(original_lines):
                        continue
                    item.update(file=path, line=number, evidence=original_lines[number - 1].strip()[:240])
                    findings.append(item)
        return findings

    rules: list[tuple[str, str, str, str, str]] = []
    if suffix == ".go":
        rules = [
            (r"\b(?:http\.(?:Get|Post|PostForm|NewRequest(?:WithContext)?)|client\.(?:Get|Post|Do))\s*\(",
             "GO_NETWORK", "network", "low", "Go HTTP-клиент: проверьте адрес назначения"),
            (r"\bos\.(?:Remove|RemoveAll)\s*\(",
             "GO_FS_DELETE", "filesystem", "medium", "Go выполняет потенциально удаляющую операцию"),
            (r"\b(?:os\.(?:WriteFile|Create|Rename)|ioutil\.WriteFile)\s*\(",
             "GO_FS_WRITE", "filesystem", "low", "Go записывает или перемещает файлы"),
            (r"\b(?:base64\.(?:StdEncoding|RawStdEncoding|URLEncoding)\.DecodeString|exec\.Command)\s*\(",
             "GO_DYNAMIC", "obfuscation", "low", "Go декодирует данные или запускает внешнюю команду"),
        ]
    elif suffix == ".cs":
        rules = [
            (r"\b(?:HttpClient\s*\(|(?:client|httpClient)\.(?:GetAsync|PostAsync|SendAsync|GetStringAsync|GetStreamAsync)\s*\(|WebRequest\.Create\s*\()",
             "CS_NETWORK", "network", "low", "C# HTTP-клиент: проверьте внешний endpoint"),
            (r"\b(?:System\.IO\.)?(?:File|Directory)\.(?:Delete)\s*\(",
             "CS_FS_DELETE", "filesystem", "medium", "C# удаляет файл или каталог"),
            (r"\b(?:System\.IO\.)?(?:File|Directory)\.(?:WriteAllText|WriteAllBytes|AppendAllText|Move|Copy|Create)\s*\(",
             "CS_FS_WRITE", "filesystem", "low", "C# модифицирует файловую систему"),
            (r"\b(?:Convert\.FromBase64String|Process\.Start|Assembly\.Load)\s*\(",
             "CS_DYNAMIC", "obfuscation", "low", "C# декодирование или динамическая загрузка/исполнение"),
        ]
    elif suffix == ".sql":
        for number in sql_operations.truncates(source):
            emit('SQL_DESTRUCTIVE', 'database', 'medium', number,
                 'SQL-команда TRUNCATE удаляет строки таблицы; проверить назначение и область действия')
        rules = [
            (r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b",
             "SQL_DESTRUCTIVE", "database", "medium", "SQL-команда удаления структуры или данных"),
            (r"\b(?:DELETE\s+FROM|UPDATE\s+[\w.\[\]\"`]+\s+SET)\b",
             "SQL_MODIFY", "database", "low", "SQL-команда изменения пользовательских данных"),
            (r"\b(?:xp_cmdshell|COPY\b.+\bTO\s+PROGRAM|EXECUTE\s+IMMEDIATE)\b",
             "SQL_DYNAMIC", "database", "medium", "SQL динамически исполняет запрос или команду ОС"),
        ]
    else:
        rules = [
            (r"\b(?:eval|Function)\s*\(\s*(?:atob|String\.fromCharCode|(?:base64\.)?b64decode)\s*\(",
             "OBF_DECODE_EXEC", "obfuscation", "high", "JavaScript/TypeScript исполняет декодируемые данные"),
            (r"\b(?:globalThis|window)\.fetch\s*\(|\b(?:fetch|axios|got)\s*\(",
             "JS_NETWORK", "network", "low", "JavaScript/TypeScript выполняет сетевой запрос"),
            (r"\b(?:require\s*\(\s*['\"](?:node:)?fs['\"]\s*\)|(?:fs|fsPromises)\.(?:rm|rmSync|unlink|unlinkSync|writeFile|writeFileSync)\s*\()",
             "JS_FILE_API", "filesystem", "low", "JavaScript/TypeScript использует API файловой системы"),
            (r"\b(?:new\s+Function|eval|atob|String\.fromCharCode)\s*\(",
             "JS_DYNAMIC", "obfuscation", "low", "JavaScript/TypeScript динамически создаёт код или декодирует строку"),
        ]
    compiled = [(re.compile(expr, re.I), rule, category, severity, message)
                for expr, rule, category, severity, message in rules]
    lines = cleaned.splitlines()
    for number, line in enumerate(lines, 1):
        for regex, rule, category, severity, message in compiled:
            if regex.search(line):
                emit(rule, category, severity, number, message)
                if rule in {"GO_NETWORK", "CS_NETWORK", "JS_NETWORK"}:
                    extra = domains_near(" ".join(lines[number - 1:number + 2]))
                    if extra:
                        emit("NET_EXTERNAL", "network", "medium", number,
                             "Сетевой вызов к домену вне allowlist: " + ", ".join(extra))
    return findings
