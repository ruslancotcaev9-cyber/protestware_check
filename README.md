# protestware-check

## Версия 0.6.0: межпроцедурный taint-analysis и трассировки SARIF

**Новое:** анализатор отслеживает ограниченные потоки данных внутри одного файла через именованные функции: аргумент вызова → параметр → присваивания/простые строковые преобразования → `return` → URL-параметр сетевого вызова. Для Python используется `ast`, для **Go, C#, JavaScript и TypeScript/TSX** — существующий Tree-sitter-движок. Динамические URL, полученные из геолокации, переменных среды и входных HTTP-параметров, создают `TAINT_URL` с полем `dataflow` (шаги `source`, `assignment`, `call`, `parameter`, `return`, `call-result`, `sink`). В SARIF эти шаги сериализуются как `codeFlows/threadFlows/locations` для просмотра маршрута в GitHub Code Scanning.

```bash
python3 -m pip install -r requirements-ast.txt -r requirements-resolver.txt
python3 -c 'from tree_sitter_language_pack import download; download(["go", "csharp", "javascript", "typescript", "tsx", "sql", "html", "css", "scss", "less"])'
python3 protestware_check.py --path ./project --ast-mode required --format sarif --output findings.sarif
```

Пример правила: `os.getenv("DEST") → wrapper(dest) → return dest → requests.get(url)`. Сканер не исполняет пользовательский код и не делает HTTP-запрос к обнаруженным URL. Все признаки остаются поводом для ручного ревью, а не свидетельством атаки.

**Границы реализации:** анализ ограничен **одним файлом и именованными функциями** с простыми параметрами и возвратами; нет полноценного разрешения виртуальных вызовов, межмодульной передачи, замыканий, сложных полей объектов, корутин, рефлексии или SSA. Рекурсивные вызовы и глубина имеют фиксированные лимиты (6 уровней, до 200 вызовов на файл), неизвестные функции консервативно сохраняют taint. Путь `dataflow` является **эвристической трассировкой происхождения данных**, а не доказанным путём выполнения; при ветвлениях может отражать один из возможных путей. SQL, HTML, CSS, SCSS, Less и Sass продолжают AST/структурный анализ из версии 0.5.0, но не получают межпроцедурный URL-taint как исполняемый язык. В `auto` отсутствие Tree-sitter явно отмечается как снижение полноты, а в `required` останавливает проверку.

---

## Версия 0.5.0: мультиязычный AST и taint analysis

Добавлены независимые слои синтаксического и потокового анализа:

* **Python:** стандартный модуль `ast`, сопоставление ветвей и простой intraprocedural taint-анализ сетевых URL.
* **Go, C#, JavaScript, TypeScript (включая JSX/TSX), SQL, HTML, CSS, SCSS, Less:** Tree-sitter (пакет грамматик закреплён в `requirements-ast.txt`). AST используется для нахождения реальных вызовов, присваиваний, условий, SQL-операторов, внешних ресурсов в HTML/CSS. Встроенный JavaScript и CSS внутри HTML разбирается отдельно.
* **Sass `.sass`:** встроенный структурный парсер отступов строит вложенные узлы блоков/свойств и исследует `@import` / `url(...)`; **это подмножество Sass, не полный парсер грамматики**.
* **Taint:** маркировка исходных данных (`os.getenv`, `process.env`, `Environment.GetEnvironmentVariable`, `request.query`, `location.search`, `geoip` и некоторые другие), распространение по простым присваиваниям, строковым операциям и ветвлениям, сопоставление с URL аргументами HTTP-вызовов. Правило `TAINT_URL` содержит тип и строку источника. Нет запуска анализируемых исходников.

**Установка расширенного режима:**

```bash
python3 -m pip install -r requirements-ast.txt
python3 -c 'from tree_sitter_language_pack import download; download(["go", "csharp", "javascript", "typescript", "tsx", "sql", "html", "css", "scss", "less"])'
```

Грамматики Tree-sitter являются нативными бинарными компонентами, скачиваемыми на первом использовании. Для CI предзагружайте их в доверенной среде и кэшируйте; для изолированного/offline-процесса подготовьте их до отключения сети. Для **неполного или недоступного парсинга** используется `warnings` и JSON-поле `ast`:

```bash
# Не допускать незаметного отката к регулярным выражениям:
python3 protestware_check.py --path ./project --ast-mode required --format sarif --output report.sarif

# По возможности AST, иначе явное предупреждение и существующие эвристики:
python3 protestware_check.py --repo owner/repo --ast-mode auto --format json

# Только старые правила, если дополнительные грамматики не установлены:
python3 protestware_check.py --path ./project --ast-mode off
```

`--ast-mode required` возвращает код 2, если грамматика отсутствует или парсер восстановил синтаксис с ошибками. `auto` не называет такой файл полностью проверенным: `ast.degraded/partial`, `ast.complete=false`, предупреждения. Наличие `TAINT_URL` — повод для анализа назначения запроса, а не самостоятельное доказательство вредоносности; источник может быть допустимой конфигурацией.

**Границы анализа:** Taint-analysis поддерживает ограниченные вызовы в одном файле, без межмодульного графа вызовов, точного вычисления значений циклов, полного контроля sanitizers и разрешения алиасов сложных объектов. SQL-диалекты отличаются, HTML-шаблонизация может быть неполной. CSS/Sass/Less URL обычно не являются исполняемыми HTTP-вызовами; неизвестные CSS-переменные и HTML-шаблоны помечаются как `AST_STYLE_DYNAMIC_URL` / `AST_HTML_DYNAMIC_URL`, а не необоснованно объявляются tainted. Синтаксическое дерево не эквивалентно полноценному CFG/SSA анализу. Поддерживаемые конструкции покрываются тестами, но гарантий обнаружения всех форм вредоносного кода нет.


**Мультиязычный статический анализатор исходных репозиториев для triage потенциального protestware** и рисков цепочки поставки ПО. Python ≥3.11; основной анализ использует стандартную библиотеку, а онлайн-разрешение версий и pnpm YAML — дополнительные зависимости из `requirements-resolver.txt`. Анализируемый код, зависимости, `pip install`, `npm install`, shell-скрипты и тесты проверяемого проекта **не запускаются**.

> **Правильная интерпретация:** высказывания о России, географические ограничения и упоминание автора в стороннем списке **не подтверждают вредоносность**. `black-mark` — перечень аккаунтов с политически мотивированной классификацией, а не база подтверждённых заражений. `toxic-repos` — база сообщений третьей стороны, достоверность и актуальность которых следует проверять самостоятельно. Вывод сканера — основание для ручного security review, не автоматическое обвинение и не рекомендация блокировать автора.

## Установка и быстрый старт

```bash
# Клонировать репозиторий
git clone https://github.com/ruslancotcaev9-cyber/protestware_check.git
cd protestware_check

# Для режима registry и pnpm lockfile установите зависимости анализатора:
python3 -m pip install -r requirements-resolver.txt

# Проверить локальный проект (без сетевых запросов)
python3 protestware_check.py --path ../my-project --format json

# Проверить публичный GitHub-репозиторий и сверить его с обеими базами
python3 protestware_check.py --repo owner/repository --watchlists live --format json

# Раскрыть дерево зависимостей и получить GitHub-источники из метаданных npm/PyPI
python3 protestware_check.py --path ../my-project \
  --dependencies registry --watchlists live --dependency-strict --format json

# Проверить конкретную версию пакета из npm или PyPI
python3 protestware_check.py --path ../empty \
  --package npm:axios@1.7.7 --package pypi:requests@2.32.3 \
  --dependencies registry --watchlists live --format json

# Проверить явно указанный исходный GitHub-репозиторий пакета
python3 protestware_check.py --path ../my-project --package-repo owner/dependency --watchlists live

# Для приватного GitHub-репозитория используйте токен только через переменную окружения
export GITHUB_TOKEN="<token-with-contents-read-access>"
python3 protestware_check.py --repo owner/private-repo --ref main --watchlists live
```

Режим проверки списков по умолчанию **`off`**, поэтому сканирование локальной папки не обращается к сторонним хостам. `--watchlists live` загружает актуальные на момент запуска файлы по **двум фиксированным HTTPS-адресам**, без выполнения какого-либо содержимого. В случае сбоя скачивания/неверного формата процесс завершится с кодом `2`: отсутствие ответа базы **не** означает отсутствия совпадений.

### Проверка по локальным копиям баз (воспроизводимо, без сети)

Загрузите в доверенной среде и сохраните **ровно** файлы `README.md` из `toxic-repos/black-mark` и `data/json/toxic-repos.json` из `toxic-repos/toxic-repos`. Можно зафиксировать SHA соответствующих коммитов. Запустите:

```bash
python3 protestware_check.py --path ../my-project \
  --watchlists offline \
  --black-mark-file ./black-mark-README.md \
  --toxic-repos-file ./toxic-repos.json \
  --fail-on medium --format json
```

Обновление баз **не выполняется автоматически**: `live` читает текущее состояние ветки `main`, `offline` — только указанные локальные снимки. Для воспроизводимого CI используйте `offline` и сохраняйте контрольные суммы файлов; для регулярной проверки свежести используйте `live` осознанно и контролируйте изменение результатов.

### Анализ прямых и транзитивных зависимостей (v0.3.0+)

Новый модуль [`dependency_analysis.py`](dependency_analysis.py) строит **инвентаризацию пакетов**, не устанавливая и не исполняя код:

| Экосистема | Источники фиксированных версий | Режим `registry` |
|---|---|---|
| npm | `package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v6–v9 | `registry.npmjs.org` (репозиторий, зависимости, версии) |
| Python / PyPI | `uv.lock`, `poetry.lock`, `pylock.toml`, `requirements*.txt`, `pyproject.toml` | `pypi.org` JSON API (ссылки на код, `requires_dist`, маркеры PEP 508) |
| Rust / Cargo | `Cargo.lock` | `crates.io` (репозиторий) |
| PHP / Composer | `composer.lock` | `repo.packagist.org` (репозиторий) |
| Go | `go.sum` | извлечение идентичности `github.com/owner/repo` из пути модуля; Go Proxy не вызывается |
| .NET / C# (v0.4.0) | `packages.lock.json`, `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` | NuGet API пока не вызывается; без lock-файла транзитивный граф неполный |

**Режимы `--dependencies`:** `lock` (по умолчанию, без сетевых запросов к реестрам) извлекает все зафиксированные версии, доступные в поддерживаемых lock-файлах. Для npm/pnpm и Python uv/Poetry восстанавливаются известные связи и глубина; версии с неизвестной достижимостью сохраняются с пометкой `lockfile-unreachable-or-conditional`. `registry` дополнительно считывает исходный GitHub-репозиторий для каждого зафиксированного пакета и может рекурсивно раскрывать зависимости из `package.json`, `pyproject.toml` или явно указанных `--package`, если lock отсутствует. `off` отключает анализ дерева.

**Важная точность:** lock-файлы дают наиболее достоверный список *зафиксированных* версий; они могут охватывать dev-, optional- и платформозависимые пакеты, не обязательно установленные в конкретной среде. Режим `registry` без lock-файла подбирает версии по метаданным и диапазонам независимо, **не выполняет полного SAT/backtracking-разрешения** npm/pip, не учитывает все peer/engine, wheel tag, платформы и дополнительные индексы. Такие результаты помечаются `complete: false`, а не выдаются за воспроизводимое дерево. Для строгого контроля фиксируйте lock-файлы и используйте `--dependency-strict` (exit code `2` при неполном анализе). Режим `registry` не требует и не выполняет `npm install`, `pip install`, `setup.py`, скрипты пакетов и git hooks.

`yarn.lock`, `Pipfile.lock` и `Gemfile.lock` в этой версии не разбираются как полноценный граф: наличие этих файлов фиксируется как неполнота. Указанные непосредственно в них ссылки GitHub могут проверяться старой текстовой эвристикой. Для воспроизводимого npm-графа используйте `package-lock.json` / `pnpm-lock.yaml`; для Python — `uv.lock` / `poetry.lock` / `pylock.toml`.

Сканер сравнивает с обеими базами GitHub-ссылки из самих манифестов, явно переданные `--package-repo` и обнаруженные при разрешении версии upstream-ссылки `repository`/`Source` из реестров. Правило `TOXIC_REPO` прикрепляет сведения о найденных пакетах, включая `direct`, `via`, `version`, а правило `TOXIC_PACKAGE` (`info`) сопоставляет строгие имена и экосистемы из `PURL` и `PURL-link` в данных `toxic-repos`. Совпадение по имени пакета без URL репозитория **не** считается совпадением GitHub-репозитория. Записи в базах могут описывать только конкретный коммит, а не все релизы проекта.

По соображениям безопасности реестры ограничены фиксированными официальными HTTPS-хостами, с запретом перенаправлений, ограничениями размера метаданных, числа запросов (`--dependency-max-requests`), глубины (`--dependency-max-depth`) и пакетов (`--dependency-max-packages`). Данные реестров рассматриваются как недоверенные. Никакого исполнения зависимостей или произвольных сетевых запросов по URL из них не производится.

### Используемые источники

| Источник | Читаемый файл | Правило и уровень |
|---|---|---|
| [toxic-repos/black-mark](https://github.com/toxic-repos/black-mark) | [`README.md`](https://github.com/toxic-repos/black-mark/blob/main/README.md) | `BLACK_MARK_OWNER`, `info` — **только совпадение аккаунта владельца** |
| [toxic-repos/toxic-repos](https://github.com/toxic-repos/toxic-repos) | [`data/json/toxic-repos.json`](https://github.com/toxic-repos/toxic-repos/blob/main/data/json/toxic-repos.json) | `TOXIC_REPO` — совпадение **конкретного репозитория**, оценка по типу записи |

`TOXIC_REPO` использует существующий в базе `problem_type`: `political_slogans` → `info`, `ip_block` и `broken_assembly` → `low`, `malware`, `ddos` и `hostile_actions` → `medium`, неизвестные типы → `info`. Эти уровни означают **приоритет проверки утверждения из списка**, а не подтверждённую эксплуатацию. В отчёте сохраняются типы и ID записей, доступные GitHub-ссылки и название списка. `BLACK_MARK_OWNER` всегда `info` и сам по себе **не повышает уровень риска**.

## AST-анализ Python (новое в 0.2.0)

Файлы `.py`, которые корректно разбираются `ast.parse`, получают структурный анализ синтаксического дерева:

- `if` / `elif` по странами `RU`, `RUS`, `BY`, `BLR` и названиям стран в сочетании с `country`, `country_code`, `geoip`, `region` и аналогичными индикаторами; простые промежуточные Boolean-переменные также распознаются.
- Вызовы `os.remove/unlink`, `shutil.rmtree`, `Path.unlink`, `Path.write_text/write_bytes`, `open(..., mode="w")`, сетевые `requests`/`httpx`/`urllib`, `eval/exec` с импортными алиасами; многострочные аргументы и литералы URL извлекаются из AST.
- **`GEO_ACTION` для валидного Python** выдаётся, только когда операция находится в исполняемой ветви соответствующего `if` (или `else`), а не просто рядом на соседних строках. Объявления вложенных функций/классов не считаются немедленным выполнением.
- Результаты AST содержат поле `"analysis": "ast"`. Если идентичная пара `правило+строка` уже найдена текстовыми эвристиками, AST-результат имеет приоритет.

Для остальных языков используется специализированный текстовый анализ, а не AST; для Python с ошибками синтаксиса остаётся текстовый fallback. Анализатор **не является** полноценным taint/data-flow, межпроцедурным анализом или средой динамического выполнения: алиасы через присваивания, рефлексия, динамический импорт и пути через внешние API могут остаться незамеченными.

## Правила обнаружения

| Правило | Интерпретация | Уровень |
|---|---|---|
| `POLITICAL_RU` | текстовый политический контекст, не security-вердикт | `info` |
| `GEO_DISCOVERY` | GeoIP или API геолокации | `low` |
| `GEO_TARGET` | географическая проверка RU/BY | `medium` |
| `NET_EXTERNAL` | явный сетевой домен вне allowlist | `medium` |
| `NET_DYNAMIC` | URL вычисляется динамически | `low` |
| `NET_GEO_API` | запрос к GeoIP-сервису | `medium` |
| `FS_DELETE` | потенциальное удаление данных | `medium` |
| `FS_WRITE` | запись, перемещение или замена | `low` |
| `OBF_DECODE_EXEC` | исполнение декодируемых данных | `high` |
| `OBF_DYNAMIC_EXEC` | `eval`, `exec` | `medium` |
| `OBF_ENCODING` | признаки закодированных строк | `low` |
| `GEO_ACTION` | операция под географическим условием (Python AST) / близость в других языках | `high` при AST-удалении; для других случаев по правилам ниже |
| `BLACK_MARK_OWNER` | владелец проекта упомянут в `black-mark` | `info` |
| `TOXIC_REPO` | репозиторий явно присутствует в `toxic-repos` | `info`–`medium` |
| `TOXIC_PACKAGE` | идентичность пакета подтверждена PURL / ссылкой на реестр из базы | `info` |

**Внимание:** проверка внешних доменов `NET_EXTERNAL` фиксирует неизвестные хосты, но не проверяет их репутацию. Для других языков `GEO_ACTION` по-прежнему опирается на близость строк (до 15) и оценивается как `high`; это не доказательство реального control-flow. Технический факт нахождения операции в ветви по стране тоже не доказывает злонамеренность без анализа назначения и параметров.

## Параметры CLI

```text
--path DIR                  Локальный каталог (по умолчанию текущий)
--repo OWNER/REPO           Репозиторий GitHub; взаимоисключающе с --path
--ref REF                   GitHub ветка, тег или SHA (только с --repo)
--format text|json|sarif|cyclonedx  Формат вывода (по умолчанию text)
--output PATH              Записать отчёт в файл вместо stdout
--fail-on low|medium|high   Порог для exit code 1 (по умолчанию high)
--watchlists off|live|offline  Режим внешних списков (по умолчанию off)
--black-mark-file PATH      Снимок black-mark для offline
--toxic-repos-file PATH     Снимок toxic-repos JSON для offline
--package-repo OWNER/REPO   Явное дополнительное GitHub-репо пакета, повторяемое
--dependencies off|lock|registry  Анализ графа зависимостей (по умолчанию lock)
--package npm:pkg@version  Пакет из реестра для проверки, повторяемое (также pypi/cargo/composer)
--dependency-max-packages N  Предел пакетов (по умолчанию 2000)
--dependency-max-depth N     Предел рекурсивной глубины (12)
--dependency-max-requests N  Предел HTTPS-запросов к реестрам (300)
--dependency-strict          Завершить с кодом 2 при неполном графе
--allow-domain DOMAIN      Разрешённый домен и поддомены, повторяемое
--exclude GLOB             Дополнительные исключения файлов, повторяемое
--max-bytes N              Максимальный размер одного файла (по умолчанию 1000000)
--political-terms-file PATH Дополнительные контекстные фразы UTF-8
```

### Коды выхода и отчёт

- **`0`** — проверка завершена, сводный `risk` ниже заданного `--fail-on`.
- **`1`** — проверка завершена, сводный `risk` достиг порога.
- **`2`** — ошибка аргументов, чтения или источников, а также `--dependency-strict` при неполном дереве. При обрезанном GitHub API tree, недоступном списке или невалидном JSON сканер **не сообщает успешную проверку**.

В JSON перечислены `source`, `files_scanned`, `risk` (совокупный приоритет ревью), `code_risk` (только исходный код, без совпадений списков), `summary`, `findings`, `warnings`, `dependencies` (массив пакетов и полнота графа) и `watchlists` с режимом, временем загрузки, точными URL/путями к локальным спискам и количеством разобранных элементов. Результаты содержат строки кода: не публикуйте отчёты приватных проектов.

```json
{
  "tool": "protestware-check",
  "version": "0.4.0",
  "source": "owner/repository",
  "files_scanned": 1,
  "risk": "medium",
  "code_risk": "none",
  "summary": {"info": 1, "low": 0, "medium": 1, "high": 0},
  "findings": [
    {"rule": "TOXIC_REPO", "category": "watchlist_repository", "severity": "medium",
     "file": "package.json", "line": 6, "evidence": "git+https://github.com/a/example.git",
     "repository": "a/example", "watchlist": "toxic-repos",
     "record_ids": ["123"], "references": ["https://github.com/a/example/commit/xyz"],
     "message": "Репозиторий a/example упоминается в toxic-repos (malware); требуется ручная проверка"}
  ],
  "watchlists": {"mode": "offline", "retrieved_at_utc": "...", "sources": {
    "black_mark": "./black-mark-README.md", "toxic_repos": "./toxic-repos.json"},
    "black_mark_accounts": 1, "toxic_repositories": 1},
  "warnings": []
}
```

*Пример выше — иллюстрация формата, а не реальный результат проверки или запись конкретного пакета.*

## Форматы отчётов для DevSecOps (v0.4.0)

Сканер поддерживает машиночитаемый **SARIF 2.1.0** для GitHub Code Scanning и **CycloneDX JSON 1.6** для SBOM. Это сериализация уже собранных результатов, без дополнительных сетевых запросов. Выбор формата не меняет коды выхода. Используйте `--output`, чтобы результат сохранился даже при возврате `1` по порогу риска или `2` из-за `--dependency-strict` (после успешного составления отчёта).

```bash
# Технические и контекстные сигналы: SARIF
python3 protestware_check.py --path ../my-project --dependencies lock \
  --format sarif --output findings.sarif --fail-on high

# Инвентарь зависимостей и связи: CycloneDX SBOM
python3 protestware_check.py --path ../my-project --dependencies lock \
  --format cyclonedx --output sbom.cdx.json
```

В SBOM сохраняются название, зафиксированная версия (если известна), PURL, upstream GitHub URL (если установлен), контекст манифеста и максимально достоверные связи `dependsOn` из lock-файла. Степень полноты фиксируется в `metadata.component.properties` как `protestware-check:dependency-analysis-complete`; неизвестные связи **не** выводятся как достоверные. При отсутствии версий SBOM остаётся частичной инвентаризацией. В SBOM **не** создаются записи `vulnerabilities` по одному только совпадению с политическим списком.

SARIF описывает обнаруженные индикаторы с уровнем `note`/`warning`/`error`, относительными путями, номерами строк и устойчивыми отпечатками находок. Записи уровня репозитория без физической строки выводятся без `locations` и могут не отображаться как отдельные GitHub Code Scanning alerts; их сохраняет полный JSON-отчёт.

[Пример GitHub Actions для выгрузки SARIF](examples/github-code-scanning.yml) нужно скопировать в `.github/workflows/` проекта, где включён GitHub Code Scanning. Workflow использует `github/codeql-action/upload-sarif@v4`, требует `security-events: write` и доступность Code Scanning для типа вашего репозитория. Для приватных репозиториев может потребоваться включённый GitHub Code Security. Встроенный `tests.yml` **не** отправляет SARIF в GitHub автоматически.

### Поддержка языков: фактически реализованные проверки

| Язык | Расширения | Покрытие и ограничения |
|---|---|---|
| Python | `.py` | `ast.parse` для условий географии, вызовов сети/FS/динамического исполнения; fallback на шаблоны при некорректном AST |
| Go | `.go` | HTTP-клиент, `os.Remove/RemoveAll`, запись, `exec.Command`, Base64; regex-эвристики, **не AST Go** |
| C# | `.cs` | `HttpClient`, `File.Delete`, `Directory.Delete`, операции записи, динамическая загрузка; NuGet lock для зависимостей; **не Roslyn** |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `fetch`, `axios`, `fs`, `eval`, декодирование, внешние URL; комментарии маскируются; **не JS AST** |
| TypeScript | `.ts`, `.tsx` | Те же правила, что для JS; типы, decorators, динамические импорты и type-flow отдельно не разрешаются |
| SQL | `.sql` | `DROP`, `TRUNCATE`, `DELETE`, `UPDATE`, `xp_cmdshell`; это эвристический поиск, не SQL-диалектный парсер и не поиск инъекций |
| HTML | `.html`, `.htm` | внешние `<script>`, `<iframe>`, `<link rel=stylesheet>`, редирект через meta, встроенный JavaScript/CSS |
| CSS | `.css` | внешние `@import`, `url()`, подозрительно экранированные URL |
| Sass | `.sass`, `.scss` | аналогичные CSS-правила; Sass-макросы, переменные и сборка не исполняются |
| Less | `.less` | аналогичные CSS-правила; Less-переменные и импорты не разрешаются |

Для Go/C#/JS/TS шаблоны комментариев маскируются, а политические фразы в документации остаются информационным контекстом. **Полноценного AST/CFG для этих языков нет**, поэтому `GEO_ACTION` вне Python остаётся эвристикой близости строк и может давать ложноположительные результаты. Шаблоны не обещают находить операции через любые алиасы, обфускацию, сборочные макросы или динамические ссылки.

Проверки совместимости запускаются командами:

```bash
python3 -m py_compile protestware_check.py ast_analysis.py language_analysis.py \
  dependency_analysis.py threat_intel.py report_formats.py
python3 -m unittest discover -s tests -v
```

## Безопасность и ограничения

- GitHub-репозитории читаются через HTTPS GitHub REST API без `git clone` и запуска хуков. Символьные ссылки в локальном каталоге и Git tree не обходятся. По умолчанию исключаются директории сборки, зависимости и бинарные файлы.
- Размер каждого текстового файла ограничен `--max-bytes`; список — 6 MB на источник. Неуспешная загрузка списка или неверный формат считается ошибкой. Файлы списков загружаются **только по фиксированным ссылкам**, указанным в `threat_intel.py`, и только при `--watchlists live`. Независимо от этого `--dependencies registry` может загружать JSON-метаданные по именам/версиям пакетов с ограниченного набора официальных реестров.
- В режиме `registry` HTTP-запросы направляются **только к официальным метаданным npm, PyPI, crates.io и Packagist**; перенаправления запрещены. Не делается запросов к произвольным адресам, найденным в сканируемом коде; не выполняются установочные скрипты, не декодируется и не запускается найденный код.
- Содержимое `black-mark` и `toxic-repos` может включать неточности, политические оценки и устаревшие ссылки. Сопоставление по владельцу ≠ совпадение пакета, совпадение пакета ≠ обнаруженная вредоносность. Ручная проверка, version pinning, ревью изменений и тесты в изолированной среде необходимы независимо от сканера.
- В некоторых публичных репозиториях большие/исключённые файлы останутся непроверенными. Анализ охватывает конкретное дерево указанного `--ref`, а не историю коммитов или связанные issues.

## Тестирование и CI

```bash
python3 -m pip install -r requirements-resolver.txt
python3 -m py_compile protestware_check.py ast_analysis.py threat_intel.py dependency_analysis.py
python3 -m unittest discover -s tests -v
```

GitHub Actions запускает тесты при push/pull request, устанавливая **только фиксированные зависимости самого анализатора**, без загрузки сторонних баз и без выполнения подозрительного тестового кода. В тестах используются только инертные строки и локальные образцы форматов источников. Можно отдельно включить `--watchlists live` в защищённом CI, учитывая стабильность внешней сети и обновления списков.
