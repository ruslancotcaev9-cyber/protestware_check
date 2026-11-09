# Руководство пользователя protestware-check

Актуально для **v1.1.0**. [На главную](../README.md) · [Политика безопасности](../SECURITY.md) · [Технический справочник](TECHNICAL_REFERENCE.md).

## 1. Назначение и модель угроз

Сканер используется для **первичной статической оценки** библиотек и репозиториев на предмет необычных сетевых и файловых действий, проверок геолокации, динамических URL, обфускации, возможных сетевых flood-сценариев, а также сигналов из двух внешних списков. Он не исполняет анализируемый код и не устанавливает пакеты из проверяемых проектов.

**Что не является доказательством атаки:** политический текст, совпадение владельца со списком `black-mark`, запись о `political_slogans` в `toxic-repos`, использование GeoIP по штатному назначению, наличие `fetch()` или `eval()` без контекста. Результат требует проверки специалистом ИБ. Отсутствие находок означает лишь отсутствие сигналов в рамках выбранных правил, файлов и бюджета анализа.

## 2. Установка

**Требуется:** Python 3.11 или новее; Git нужен только для получения **самого инструмента**. Для анализа локального дерева интернет не обязателен, если заранее установлены зависимости и грамматики, а `--watchlists` выключен и `--dependencies` не равен `registry`.

```bash
git clone https://github.com/ruslancotcaev9-cyber/protestware_check.git
cd protestware_check
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-ast.txt -r requirements-resolver.txt
python -c 'from tree_sitter_language_pack import download; download(["go","csharp","javascript","typescript","tsx","sql","html","css","scss","less","c","cpp"])'
python protestware_check.py --help
```

Для **Windows PowerShell** активируйте `.venv\Scripts\Activate.ps1` вместо `source .venv/bin/activate`; для Windows при настройке PATH при необходимости замените `python3` на `py -3.11` или `python`.

`requirements-ast.txt` и `requirements-resolver.txt` — **необязательные компоненты самого сканера**, версии в них закреплены. Tree-sitter использует нативные грамматики: скачайте их заранее из доверенного источника при работе в изолированной среде. Если нужен только базовый анализ и формат `text`/`json`, достаточно Python; `--ast-mode auto` при отсутствии парсеров выдаст предупреждения о снижении полноты. Для предсказуемого CI используйте `--ast-mode required`.

### Работа с GitHub API

Для публичных репозиториев может хватить неавторизованных запросов, но действуют лимиты API. Для приватных доступных репозиториев и повышенных лимитов используйте токен с минимально необходимыми правами, передавая его через `GITHUB_TOKEN` и секреты CI. **Никогда не включайте токен в аргументы командной строки, URL, коммиты или публикуемые журналы.**

```bash
export GITHUB_TOKEN="$(cat /secure/path/github-token)"
python protestware_check.py --repo owner/repo --ref 0123456789abcdef0123456789abcdef01234567 --format json
```

Этот пример демонстрирует форму 40-символьного SHA, а не существующий commit; используйте SHA требуемой версии. Убедитесь, что URL действительно относится к `github.com`, а для анализа крупного репозитория учитывайте ограничения объёма и rate-limit.

## 3. Сценарии использования

### A. Быстрая локальная проверка без внешних источников

```bash
python protestware_check.py --path ../application \
  --ast-mode auto --dependencies lock --watchlists off \
  --format json --output ./findings.json
```

Файл `findings.json` рекомендуется размещать **вне сканируемого каталога**. Если файл совпадёт с исходным файлом, `--output` его перезапишет; выбирайте новый путь заранее.

### B. Проверка фиксированного коммита GitHub

```bash
python protestware_check.py --repo fmtlib/fmt --ref YOUR_COMMIT_SHA \
  --watchlists live --dependencies lock --ast-mode auto \
  --format json --output ./fmt-report.json
```

`--ref` поддерживает SHA, ветку или тег. Для воспроизводимости используйте **конкретный commit SHA**; ссылка на ветку изменяется со временем. Режим `--repo` запрашивает файлы через GitHub REST API; не выполняет `git clone`, хуки, сборку или тесты проверяемого репозитория.

### C. Проверка зависимостей

```bash
python protestware_check.py --path ../application \
  --dependencies lock --dependency-strict --format cyclonedx \
  --output ./sbom.cdx.json
```

`lock` читает зафиксированный состав из поддерживаемых манифестов. Если lock-файл отсутствует или неподдерживаемый формат не позволяет получить полный граф, `--dependency-strict` может завершиться с кодом 2. При отсутствии поддерживаемых манифестов нельзя делать вывод «зависимостей нет».

```bash
python protestware_check.py --path ../application \
  --dependencies registry --dependency-max-packages 1000 \
  --dependency-max-depth 8 --dependency-max-requests 100 \
  --watchlists live --format json --output ./supply-chain.json
```

`registry` дополняет граф HTTPS-метаданными официальных реестров. Разрешение диапазонов версий **эвристическое** и не заменяет штатные npm/pip/Cargo/Composer-разрешители; версии фиксируйте lock-файлом.

Дополнительная проверка явно указанного GitHub-репозитория или пакета реестра:

```bash
python protestware_check.py --path ../application --package-repo owner/library \
  --watchlists live --format json
python protestware_check.py --path ../application --dependencies registry \
  --package npm:axios@1.7.7 --format json
```

### D. Полностью локальная сверка с загруженными заранее списками

Сохраните **в отдельной доверенной процедуре** два файла и зафиксируйте их SHA256: `README.md` из `toxic-repos/black-mark` и `data/json/toxic-repos.json` из `toxic-repos/toxic-repos`. Не используйте произвольные копии и не исполняйте файлы источников.

```bash
python protestware_check.py --path ../application \
  --watchlists offline \
  --black-mark-file ./watchlists/black-mark-README.md \
  --toxic-repos-file ./watchlists/toxic-repos.json \
  --dependencies lock --format json --output ./offline-report.json
```

`--watchlists off` означает отсутствие сверки; `live` загружает списки из заданных источников и требует HTTPS; `offline` требует оба локальных файла. Совпадение **по владельцу** в `black-mark` — только контекстный сигнал; запись `toxic-repos` тоже требует независимой проверки.

### E. SARIF для GitHub Code Scanning

```bash
python protestware_check.py --path ../application \
  --ast-mode required --format sarif --output ./findings.sarif
```

Используйте [пример workflow](../examples/github-code-scanning.yml). GitHub Code Scanning должен быть доступен и настроен для целевого репозитория; для публикации SARIF нужны `security-events: write` и подходящие права. **Результаты в SARIF не равны подтверждённым CVE или вредоносным пакетам.**

## 4. Справочник CLI

Точную версию ключей всегда проверяйте `python protestware_check.py --help`.

| Параметр | Назначение / умолчание |
| --- | --- |
| `--path DIR` | Сканировать локальный каталог; по умолчанию `.` |
| `--repo OWNER/REPO` | GitHub-репозиторий, вместо `--path` |
| `--ref REF` | Ветка/тег/commit SHA, только вместе с `--repo` |
| `--format text\|json\|sarif\|cyclonedx` | Формат отчёта; `text` |
| `--output PATH` | Сохранить отчёт в файл; по умолчанию stdout |
| `--ast-mode auto\|required\|off` | Использование синтаксических парсеров; `auto` |
| `--fail-on low\|medium\|high` | Порог кода выхода 1; `high` |
| `--allow-domain DOMAIN` | Доверенный DNS-домен (включая поддомены); можно повторять |
| `--exclude GLOB` | Дополнительные маски исключений; можно повторять |
| `--political-terms-file PATH` | Дополнительные контекстные фразы (UTF-8; по строке) |
| `--max-bytes N` | Максимальный размер исходного файла; `1000000` |
| `--watchlists off\|live\|offline` | Сверка с двумя внешними списками; `off` |
| `--black-mark-file PATH` | Файл `black-mark` для `offline` |
| `--toxic-repos-file PATH` | JSON `toxic-repos` для `offline` |
| `--package-repo OWNER/REPO` | Добавить GitHub-репозиторий к сверке; можно повторять |
| `--dependencies off\|lock\|registry` | Инвентаризация зависимостей; `lock` |
| `--package ECOSYSTEM:NAME@VERSION` | Пакет из реестра; можно повторять |
| `--dependency-max-packages N` | Лимит числа пакетов; `2000` |
| `--dependency-max-depth N` | Лимит рекурсии зависимостей; `12` |
| `--dependency-max-requests N` | Лимит запросов к реестрам; `300` |
| `--dependency-strict` | Код 2, если граф зависимостей неполон |

Пример снижения ложных срабатываний для известного доверенного API:

```bash
python protestware_check.py --path ../application --allow-domain api.example.org \
  --exclude 'tests/fixtures/*' --fail-on medium --format text
```

Добавление домена в allowlist **не делает его безопасным** и не должно применяться к неизвестным хостам без расследования.

## 5. Интерпретация отчётов и CI

**JSON:** `source`, `files_scanned`, `risk`, `code_risk`, `summary`, `findings`, `watchlists`, `dependencies`, `ast`, `warnings`. В каждой находке проверяйте `rule`, `severity`, `file`, `line`, `message`, `evidence`; для отдельных AST/taint-правил предусмотрены `dataflow` и `reachability`.

**SARIF:** результаты с привязкой к файлам/строкам, а при наличии трассировок — `codeFlows`. Сигналы уровня репозитория без файла могут не отображаться в интерфейсе Code Scanning; сохраняйте также JSON. **CycloneDX:** список компонентов и предполагаемых связей, с индикатором `protestware-check:dependency-analysis-complete`. Совпадение с `black-mark` не становится CVE/SBOM-vulnerability.

**Выходные коды:** `0` — анализ завершён и оценка риска ниже `--fail-on`; `1` — превышен/достигнут порог; `2` — ошибка ввода/данных либо неполнота при `--dependency-strict`. Анализ в режиме `auto` может завершаться с кодом 0, даже если некоторые парсеры недоступны: всегда смотрите `ast.complete`, `warnings`, `dependencies.summary.complete`.

**Рекомендуемый pipeline:** проверить SHA источника → статический анализ → собрать JSON/SARIF/SBOM → не публиковать приватные фрагменты → вручную разбирать технические `high` → документировать разрешённые исключения → повторить проверку после обновлений. Сборку и выполнение недоверенного кода отделяйте от статического сканирования и проводите только в отдельном изолированном контуре.

## 6. Поддерживаемые форматы

| Языки/файлы | Тип анализа |
| --- | --- |
| Python (`.py`) | AST, известные API, ограниченный interprocedural URL-taint |
| Go (`.go`) | Tree-sitter, URL-taint и вызовы внутри файла |
| C# (`.cs`) | Tree-sitter, сетевые и файловые сигналы, ограниченный URL-taint |
| JavaScript/TypeScript (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`) | Tree-sitter, URL-taint, `NETWORK_FLOOD`, `OBFUSCATED_JS` |
| C/C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, `.hxx`) | Tree-sitter, известные network/FS/process sinks и ограниченный внут­рифайловый call graph |
| SQL, HTML, CSS, SCSS, Less | Tree-sitter и специализированные статические правила |
| Sass `.sass` | Частичный структурный разбор по отступам |

Зависимости: npm (`package-lock.json` v1–v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v6–v9), Python (`uv.lock`, `poetry.lock`, `pylock.toml`, `requirements*.txt`, `pyproject.toml`), Cargo (`Cargo.lock`), Composer (`composer.lock`), Go (`go.sum`), NuGet (`packages.lock.json`, проекты и `Directory.Packages.props`). Не поддерживаются как полный lock-граф `yarn.lock`, `Pipfile.lock`, `Gemfile.lock` и некоторые динамически вычисляемые манифесты. Подробнее см. [технический справочник](TECHNICAL_REFERENCE.md).

## 7. Типовые проблемы

| Симптом | Что проверить |
| --- | --- |
| `HTTP 403` или rate-limit GitHub | `GITHUB_TOKEN`, права, бюджет API; не встраивать токен в URL |
| Tree-sitter грамматика не найдена | Установить `requirements-ast.txt`, заранее скачать грамматики; `--ast-mode required` не должен молча деградировать |
| Нет пакетов в SBOM | Проверить lock/manifest, `dependencies.summary.complete` и пропуски по лимитам |
| `--dependency-strict` даёт код 2 | Сохранить JSON и исправить причины неполного графа; не обходить без обоснования |
| Много `NET_EXTERNAL` | Разобрать назначение доменов; только затем точечно `--allow-domain` |
| Слишком много результатов в тестах | `--exclude` только после оценки, документировать исключения |
| Не видны repo-level события в GitHub Code Scanning | Использовать полный JSON, т.к. часть SARIF записей не имеет `locations` |
| Проблема с записью отчёта | Проверить путь `--output`, права и отсутствие конфликтов с исходниками |

## Перед публичным релизом

- [ ] Проверить право на публикацию всего включённого исходного кода, тестов, примеров и документации; проверить лицензии сторонних материалов.
- [ ] Проверить `LICENSE` (Apache-2.0), лицензионные заголовки при необходимости, `SECURITY.md` и процедуру релизов.
- [ ] Перевести репозиторий в `public` только после проверки секретов и истории коммитов, исключить внутренние артефакты из git.
- [ ] Включить GitHub **Private vulnerability reporting**, убедиться, что закрытая форма действительно доступна внешнему исследователю; назначить ответственного и резервный канал связи.
- [ ] Убедиться в доступности CI, поддерживаемых версий Python, обязательных грамматик Tree-sitter и тестов на безопасных фикстурах.
- [ ] Разместить релиз с тегом, закреплёнными зависимостями и контрольными суммами; обновлять документацию с каждой версией.
- [ ] Чётко отметить, что политические контекстные индикаторы и списки третьих лиц не являются доказательством вредоносности.

## Дополнительные материалы

- [README](../README.md) — краткое описание продукта.
- [Security policy](../SECURITY.md) — сообщения об уязвимостях в сканере.
- [Лицензия Apache-2.0](../LICENSE) — условия использования.
- [Пример GitHub Code Scanning](../examples/github-code-scanning.yml).
- [Технический справочник](TECHNICAL_REFERENCE.md).


## Дополнительные источники о вредоносных пакетах (v1.1.0)

После чтения lock-файлов сканер может по явному запросу проверить точные версии пакетов по OpenSSF Malicious Packages / OSV и GitHub Advisory Database (`type=malware`):

```bash
python protestware_check.py --path ../application --dependencies lock \
  --malware-intel both --malware-strict \
  --malware-max-packages 200 --malware-max-requests 250 \
  --format sarif --output malware-findings.sarif
```

`--malware-intel` принимает `off` (по умолчанию), `osv`, `github`, `both`; `--malware-strict` включает код выхода 2 при неполноте источников или инвентаризации. Проверка имён и версий передаёт эти координаты внешним API и потому требует отдельного решения при анализе частных зависимостей. `--watchlists` продолжает независимо проверять `toxic-repos` / `black-mark`.

Точные схемы сопоставления, обработка отозванных записей, лимиты и отдельные источники описаны в [справочнике](MALWARE_INTELLIGENCE.md). Обычные CVE не считаются protestware.


## Уточнения по безопасному запуску после проверки 09.11.2026

- Установите `requirements-resolver.txt` перед тестами разрешения версий. Для полного AST установите `requirements-ast.txt` и заранее загрузите перечисленные выше грамматики. При сканировании автоматическая загрузка грамматик отключена: `auto` сообщает о неполном AST, `required` возвращает код 2.
- Лимиты исходных данных: `--max-bytes` (на файл, по умолчанию 1 000 000), `--max-files` (10 000), `--max-total-bytes` (100 000 000 байт декодированного текста в UTF-8). Превышение суммарного бюджета прекращает анализ с кодом 2. Нечитаемые и слишком большие файлы также исключают успешный код завершения; JSON содержит `scan.complete=false`. Поле относится к чтению выбранных исходных файлов: полнота AST и зависимостей отражается отдельно. Исключения путей и неподдерживаемые расширения остаются вне области сканирования.
- Используйте стабильную копию проекта. В POSIX обход каталогов опирается на файловые дескрипторы; чтение ограничено и допускает только обычные файлы. На Windows нет гарантии защиты от одновременной подмены родительских каталогов. Для враждебного изменяемого дерева используйте изолированную среду и снимок только для чтения.
- Отчёт записывается атомарно. Символические ссылки в конечном пути отчёта и перезапись существующего файла внутри сканируемого каталога запрещены. Сохраняйте отчёты в отдельный доверенный каталог. Существующий отчёт вне исходного дерева можно обновлять.
- GitHub API и загрузка внешних списков не следуют перенаправлениям; используйте актуальное имя репозитория. Ответ GitHub API ограничен 16 МБ.
- В `--package` диапазоны (`^1.0.0`, `>=1.0`, `1.*`) не считаются зафиксированной версией. В режиме `lock` они отмечаются как неполные; `registry` пытается подобрать версию и явно сохраняет приблизительный характер разрешения. Запросы malware advisories отправляются только для конкретных версий.
- Предупреждения сохраняются в текстовом отчёте и в SARIF `invocations.toolExecutionNotifications`; неполное чтение отражается в `executionSuccessful=false`. Для строгой проверки используйте `--ast-mode required --dependency-strict`, а при включённых advisories — `--malware-strict`.
