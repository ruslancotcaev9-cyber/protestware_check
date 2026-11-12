# Руководство пользователя protestware-check

Актуально для кода **v1.4.0 в `main`, unreleased**. [Указатель документации](README.md) · [На главную](../README.md) · [Политика безопасности](../SECURITY.md) · [Технический справочник](TECHNICAL_REFERENCE.md).

## 1. Назначение и модель угроз

Сканер используется для **первичной статической оценки** библиотек и репозиториев на предмет необычных сетевых и файловых действий, проверок геолокации, динамических URL, обфускации, возможных сетевых flood-сценариев, а также сигналов из двух внешних списков. Он не исполняет анализируемый код и не устанавливает пакеты из проверяемых проектов.

**Что не является доказательством атаки:** политический текст, совпадение владельца со списком `black-mark`, запись о `political_slogans` в `toxic-repos`, использование GeoIP по штатному назначению, наличие `fetch()` или `eval()` без контекста. Результат требует проверки специалистом ИБ. Отсутствие находок означает лишь отсутствие сигналов в рамках выбранных правил, файлов и бюджета анализа.

## 2. Установка

**Требуется:** Python 3.11 или новее; Git нужен только для получения **самого инструмента**. Для анализа локального дерева интернет не обязателен, если заранее установлены зависимости и грамматики, а `--watchlists off` (или `offline` с локальными списками), `--malware-intel off` и `--dependencies lock`/`off`.

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

`requirements-ast.txt` и `requirements-resolver.txt` — **необязательные компоненты самого сканера**, версии в них закреплены. Tree-sitter использует нативные грамматики: скачайте их заранее из доверенного источника при работе в изолированной среде. Для базовых эвристик, встроенного Python AST и всех форматов отчётов достаточно стандартной библиотеки; дополнительные пакеты требуются для Tree-sitter, pnpm YAML и разрешения некоторых диапазонов версий; `--ast-mode auto` при отсутствии парсеров выдаст предупреждения о снижении полноты. Для предсказуемого CI используйте `--ast-mode required`.

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

Файл `findings.json` размещайте **вне сканируемого каталога**, в доверенном каталоге отчётов. `--output` запрещает перезапись существующего файла внутри исходного дерева и конечные символические ссылки. Запись атомарная; существующий отчёт вне исходного дерева можно обновлять. Родительский каталог должен существовать.

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

Для Go учитываются объявленные версии из `go.mod`, `// indirect` и `replace`.
`go.sum` используется для контрольных сумм, включая различие между архивом и
`/go.mod`; старые версии не выдаются за текущие требования. Полный выбранный граф
сборки внутри сканера не вычисляется, поэтому без доверенного импорта Go-модуль с требованиями получает
`dependencies.summary.complete=false`. Подробнее — [ограничения Go](TECHNICAL_REFERENCE.md#особенности-go).

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

Используйте [пример workflow](../examples/github-code-scanning.yml): он отдельно получает целевой проект и закреплённый коммит сканера, устанавливает только зависимости сканера, заранее готовит грамматики и пишет SARIF вне исходного дерева. Коды 1/2 сохраняют ошибку шага, а доступный отчёт загружается отдельно. Пример использует `--ast-mode required`, но не включает строгую инвентаризацию или внешние advisories: включайте их согласно политике проекта. GitHub Code Scanning должен быть доступен и настроен для целевого репозитория; для публикации SARIF нужны `security-events: write` и подходящие права. **Результаты в SARIF не равны подтверждённым CVE или вредоносным пакетам.**

### F. Политика и baseline после рассмотрения находок

```bash
python protestware_check.py --path ../application --project-id team/application \
  --policy ./review-policy.toml --format json --output ./review.json \
  --write-baseline ./baseline-v2.json
# После рассмотрения и утверждения baseline в доверенной конфигурации:
python protestware_check.py --path ../application --project-id team/application \
  --policy ./review-policy.toml --baseline ./baseline-v2.json --only-new \
  --format json --output ./current.json
```

Политику передавайте явно: сканер не загружает её автоматически из проверяемого
проекта. Одинаковые проект, политика и параметры нужны на обоих шагах.
`--only-new` оставляет известные находки в отчёте, но исключает их из порога только
при совпадении контекста. Изменение выбранного кода или настроек возвращает их
на ревью как `updated`; baseline schema 1 для фильтрации отклоняется с кодом 2.
[Политика и исключения](POLICY_AND_CI.md), [контекст и миграция](BASELINE_AND_GO_IMPORT.md).

### G. Импорт выбранного профиля Go

```bash
python protestware_check.py --path ../application --dependencies lock \
  --go-build-info ../trusted-go/build-info.json --source-revision "$CI_COMMIT_SHA" \
  --project-id "$CI_PROJECT_PATH" --dependency-strict \
  --format json --output ./go-report.json
```

Пример предназначен для CI, где эти переменные заданы доверенной конфигурацией.
JSON заранее формируется отдельным доверенным заданием Go и нормализуется
`scripts/prepare_go_build_info.py`. Сканер заново проверяет набор и хеши входных
файлов, не вызывает Go и не устанавливает зависимости. Повторяйте `--go-build-info`
для разных поддерживаемых профилей. Полнота относится к указанным целям и профилям;
тестовые пакеты, vendor и overlay не поддерживаются.
[Подготовка JSON, параметры helper и границы доверия](BASELINE_AND_GO_IMPORT.md).

### H. Проверка поставляемых файлов

```bash
python protestware_check.py --path ../application --profile artifact \
  --dependencies lock --format json --output ./artifact-report.json
```

`artifact` включает дополнительные сборочные каталоги, `node_modules` и минифицированные
файлы; остальные фильтры и бюджеты сохраняются. По умолчанию действует `source`.
Сравнивайте `coverage.file_counts`, `pruned_directories` и `ast_by_extension`;
профиль не делает бинарные файлы объектом статического анализа.
[Область и учёт пропусков](POLICY_AND_CI.md).

### I. Удаление файлов в JavaScript/TypeScript

Для разрешения Node API заранее загрузите грамматики `javascript`, `typescript`
и `tsx` и используйте `--ast-mode required`. Правило `FS_DELETE` распознаёт,
например, `import { rm as remove } from 'node:fs/promises'; remove(path)` и
`const fs = require('fs'); fs.promises.rm(path)` с учётом локального затенения.
Проверяемый JavaScript не выполняется. Поддерживаются `.js`, `.jsx`, `.mjs`,
`.cjs`, `.ts`, `.tsx`.

При успешном полном AST прежняя текстовая эвристика `FS_DELETE` для этих файлов
заменяется результатом разрешения импортов. В `off`, при отсутствии грамматики
или частичном разборе `auto` сохраняет ограниченный fallback; качество разрешения
имён к нему не относится. `required` возвращает 2 при диагностированной неполноте.
Это анализ одного файла: динамические загрузчики и произвольные межфайловые
переэкспорты не разрешаются. [Подробности и пределы](TECHNICAL_REFERENCE.md#nodejs-и-typescript).

## 4. Справочник CLI

Таблица охватывает все прикладные параметры CLI 1.4.0; `-h`/`--help` показывает
встроенную справку. Явные CLI-значения `--profile`, `--fail-on` и переключателя
`--only-new`/`--all-findings` имеют приоритет над политикой; `--exclude` и
`--allow-domain` дополняют списки политики. По умолчанию политика и baseline
не загружаются, `--only-new` выключен. [Формат политики](POLICY_AND_CI.md).

| Параметр | Назначение / умолчание |
| --- | --- |
| `--path DIR` | Сканировать локальный каталог; по умолчанию `.` |
| `--repo OWNER/REPO` | GitHub-репозиторий, вместо `--path` |
| `--ref REF` | Ветка/тег/commit SHA, только вместе с `--repo` |
| `--format text\|json\|sarif\|cyclonedx` | Формат отчёта; `text` |
| `--output PATH` | Сохранить отчёт в файл; по умолчанию stdout |
| `--ast-mode auto\|required\|off` | Использование синтаксических парсеров; `auto`. `required` требует успешного разбора только для языков с поддерживаемым AST-парсером |
| `--fail-on low\|medium\|high` | Порог кода выхода 1; `high` |
| `--profile source\|artifact` | Область отбора файлов; `source` |
| `--coverage-max-samples N` | Максимум примеров пропусков в отчёте; `100`, диапазон `0–10000`; счётчики сохраняются при `0` |
| `--policy PATH` | Явный доверенный TOML; без него используется встроенная политика |
| `--baseline PATH` | Явный рассмотренный JSON baseline; для фильтрации требуется schema 2 |
| `--write-baseline PATH` | Сохранить baseline schema 2 отдельно от отчёта; автоматически не утверждает находки |
| `--only-new` | Применять порог к новым находкам и известным с изменившимся контекстом; требует baseline schema 2 |
| `--all-findings` | Применять порог ко всем активным находкам; отменяет `only_new` политики, несовместим с `--only-new` |
| `--allow-domain DOMAIN` | Доверенный DNS-домен (включая поддомены); можно повторять |
| `--exclude GLOB` | Дополнительные маски исключений; можно повторять |
| `--political-terms-file PATH` | Дополнительные контекстные фразы (UTF-8; по строке) |
| `--max-bytes N` | Максимальный размер исходного файла; `1000000` байт |
| `--max-files N` | Лимит выбранных текстовых файлов; `10000` |
| `--max-total-bytes N` | Лимит декодированного текста в UTF-8; `100000000` байт |
| `--watchlists off\|live\|offline` | Сверка с двумя внешними списками; `off` |
| `--black-mark-file PATH` | Файл `black-mark` для `offline` |
| `--toxic-repos-file PATH` | JSON `toxic-repos` для `offline` |
| `--package-repo OWNER/REPO` | Добавить GitHub-репозиторий к сверке; можно повторять |
| `--dependencies off\|lock\|registry` | Инвентаризация зависимостей; `lock` |
| `--package ECOSYSTEM:NAME@VERSION` | npm, pypi, cargo, composer; точная версия или ограничение; можно повторять. Диапазоны разрешаются приблизительно в `registry` для npm/PyPI, в `lock` отмечаются как неполные |
| `--dependency-max-packages N` | Лимит числа пакетов; `2000` |
| `--dependency-max-depth N` | Лимит рекурсии зависимостей; `12` |
| `--dependency-max-requests N` | Лимит запросов к реестрам; `300` |
| `--dependency-strict` | Код 2, если инвентаризация зависимостей неполна |
| `--go-build-info PATH` | Доверенный экспорт выбранных Go-пакетов; повторяется для разных профилей, только local/lock |
| `--source-revision SHA` | Ожидаемая ревизия для Go-экспорта: 40/64 строчных hex-символа; обязательна при импорте, без значения по умолчанию |
| `--project-id ID` | Устойчивая идентичность проекта для baseline; до 256 символов без управляющих ASCII; по умолчанию отсутствует |
| `--malware-intel off\|osv\|github\|both` | Сверка точных версий по malware advisories; `off` |
| `--malware-max-packages N` | Лимит уникальных координат пакетов для advisories; `100` |
| `--malware-max-requests N` | Лимит запросов к advisory API; `120` |
| `--malware-strict` | Код 2 при неполноте advisories или инвентаризации; требует включённого `--malware-intel` |
| `--malware-max-pages N` | Лимит страниц на пакет/источник; `10`, диапазон `1–100` |
| `--malware-retries N` | Повторы временных ошибок advisory API; `1`, диапазон `0–3` |
| `--malware-time-budget SECONDS` | Общий бюджет advisory-этапа; `120`, больше 0 и не больше 3600; не жёсткий таймаут всего процесса |
| `--advisory-cache PATH` | Явный доверенный JSON-снимок ответов; требует включённого `--malware-intel` |
| `--advisory-cache-max-age SECONDS` | Максимальный возраст записи снимка; `86400`, диапазон `1–31536000` |
| `--advisory-offline` | Только свежие записи снимка, без advisory-сети; требует `--advisory-cache`, local/lock и отсутствия live-watchlists |

`--package` и `--dependency-strict` требуют включённого анализа зависимостей.
`--malware-intel` также несовместим с `--dependencies off`. `--go-build-info`
допускается только с локальным `--path`, режимом `lock` и `--source-revision`.
Пути отчёта и нового baseline должны отличаться друг от друга и от входов политики,
baseline и снимков. Все числовые лимиты положительны, кроме допускающих `0`
`--coverage-max-samples` и `--malware-retries`.

Пример снижения ложных срабатываний для известного доверенного API:

```bash
python protestware_check.py --path ../application --allow-domain api.example.org \
  --exclude 'tests/fixtures/*' --fail-on medium --format text
```

Добавление домена в allowlist **не делает его безопасным** и не должно применяться к неизвестным хостам без расследования.

## 5. Интерпретация отчётов и CI

Начиная с 1.4.0 полный JSON-отчёт содержит `schema: 1`; поле `version` продолжает
обозначать версию сканера. Для проверки сохранённого артефакта используйте
`python scripts/validate_json.py report PATH` после установки
`requirements-contracts.txt`. Helper возвращает 0/2 по корректности формата,
а не по риску. [Схемы, старые отчёты и миграция](JSON_CONTRACTS.md).

**JSON:** `schema`, `tool`, `version`, `source`, `files_scanned`, `risk`, `code_risk`, `summary`,
`findings`, `watchlists`, `dependencies`, `malware_intel`, `scan`, `coverage`, `ast`,
`analysis_context`, `policy`, `gate`, `warnings`. В каждой находке проверяйте `rule`,
`severity`, `file`, `line`, `message`, `evidence`; для отдельных AST/taint-правил
предусмотрены `dataflow` и `reachability`. CLI добавляет `fingerprint`,
`baseline_state`, `effective_severity` и `policy_decision`.
Разрешённые файловые вызовы Go/Node содержат `resolved_symbol`. Для Node
`binding_certainty=resolved|possible` отражает однозначность связи с импортом;
`possible` означает также неизвестную альтернативу при слиянии ветвей.
Эти поля сохраняются в SARIF `properties` и не выражают вероятность вредоносности.

**SARIF:** результаты с привязкой к файлам/строкам, а при наличии трассировок — `codeFlows`. Для advisory сохраняются пакет, версия, происхождение, ID и ссылки в `properties`; неизвестный номер строки не подменяется фиктивным. Сигналы уровня репозитория без файла могут не отображаться в интерфейсе Code Scanning; сохраняйте также JSON. **CycloneDX:** список компонентов и предполагаемых связей, с индикатором `protestware-check:dependency-analysis-complete` и свойством `protestware-check:package-origin`. Совпадение с `black-mark` не становится CVE/SBOM-vulnerability.

**Выходные коды:** `0` — риск ниже `--fail-on` и нет ошибки, требующей кода 2; `1` — достигнут порог; `2` — ошибка ввода/вывода, неполное чтение, превышение суммарного бюджета, отсутствие/неполнота AST для поддерживаемого парсером языка при `required` или неполнота при `--dependency-strict` / `--malware-strict`. Код 2 имеет приоритет перед кодом 1. Ошибка до построения отчёта может оставить только сообщение в stderr: наличие выходного файла не гарантировано.

При политике/baseline порог применяется к `policy.risk`, исходный `risk` сохраняется
для ревью; итоговый код находится также в JSON `gate.exit_code`. Ошибки чтения и
строгих этапов не скрываются исключениями или сравнением с baseline.

| Поле | Как трактовать |
| --- | --- |
| `scan.complete` | Полнота чтения выбранных исходных файлов; исключённые пути, неподдерживаемые расширения и отфильтрованные бинарные файлы не входят в область проверки |
| `ast.complete` | Есть хотя бы один разобранный AST, нет деградации/частичного разбора или остановки по внутренним лимитам, режим не `off`; это не покрытие всех языков и файлов |
| `dependencies.summary.complete` | Нет зарегистрированных ошибок/пропусков инвентаризации; не доказательство полного воспроизводимого разрешения установки |
| `malware_intel.complete` | Полнота выбранных advisory-запросов; при `off` значение `true` означает отсутствие запрошенной проверки |
| `malware_intel.inventory_complete` | Отдельный признак полноты входной инвентаризации |
| `coverage` | Профиль, число наблюдённых/выбранных/проанализированных файлов, причины пропусков, AST по расширению; для GitHub — разрешённые commit/tree SHA |
| `analysis_context` | Хеши выбранных входов, правил/парсеров, конфигурации и зависимостей; не содержит исходников |
| `policy.risk` | Риск активных находок после политики, исключений и baseline; применяется к порогу gate |
| `policy.baseline_context_match` | Совпадение контекста с загруженным baseline; `null`, если baseline не задан |
| `gate.exit_code`, `gate.reasons` | Итоговый код CLI и причины неполноты, требующие кода 2 |
| `dependencies.go_builds` | Заявленные Go-профили, ревизии, хеши снимков, область целей и результат проверки входов |

SARIF сохраняет состояния baseline `new`/`unchanged`/`updated` и причины повторного
ревью в свойствах находок. CycloneDX добавляет `protestware-check:build-context`
для импортированных Go-компонентов. Подробности — в
[описании контекста и происхождения Go](BASELINE_AND_GO_IMPORT.md).

В `auto` и без строгих флагов код 0 возможен при неполном AST, зависимостях или advisories. Проверяйте режимы, поля полноты и предупреждения вместе. SARIF сохраняет предупреждения в `invocations.toolExecutionNotifications`. `executionSuccessful=false` отражает зарегистрированную неполноту чтения или включённых анализов; `invocations.properties.analysisCoverage` показывает соответствующие этапы (`null` — этап не применялся). Этот флаг не заменяет проверку кода завершения и остальных полей.

`--ast-mode required` не означает AST-покрытие всех языков и не требует хотя бы одного разобранного AST. Если каталог содержит только Rust (`.rs`), документацию или пуст, код 0 возможен при `ast.parsed=0` и `ast.complete=false`. Для `.rs` остаются базовые эвристики; AST-парсер Rust не реализован. В смешанном проекте `ast.complete=true` также не означает AST-разбор каждого файла: оценивайте состав проекта и таблицу поддерживаемых форматов.

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

Зависимости: npm (`package-lock.json` v1–v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v6–v9), Python (`uv.lock`, `poetry.lock`, `pylock.toml`, `requirements*.txt`, `pyproject.toml`), Cargo (`Cargo.lock`), Composer (`composer.lock`), Go (`go.mod`/`go.sum` и выбранные профили из доверенного JSON), NuGet (`packages.lock.json`, проекты и `Directory.Packages.props`). `go.work`/`go.work.sum` связываются с исходниками в доверенном экспорте; самостоятельно полный workspace-граф из них не вычисляется. Не поддерживаются как полный lock-граф `yarn.lock`, `Pipfile.lock`, `Gemfile.lock` и некоторые динамически вычисляемые манифесты. Подробнее см. [технический справочник](TECHNICAL_REFERENCE.md).

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
| Проблема с записью отчёта | Проверить существование родительского каталога, права, отсутствие конечной ссылки; выбрать путь вне исходников |
| Код 2 при пропуске большого/нечитаемого файла | Проверить `warnings`; восстановить доступ или обоснованно изменить лимиты/область анализа |
| `Total source file/byte budget exceeded` | Сканировать меньшие независимые части или обоснованно увеличить `--max-files` / `--max-total-bytes` |
| `--malware-strict` даёт код 2 | Проверить точные версии, происхождение (`skipped_unverified_origin`), полноту инвентаризации, API и лимиты запросов |
| HTTP 3xx от GitHub/списков | Перенаправления запрещены; использовать актуальный источник |
| `Context-aware baseline schema 2 required` | Пересмотреть исходный отчёт и создать новый baseline; schema 1 не может фильтровать находки |
| Известные находки вернулись как `updated` | Изучить `baseline_context_changes`: изменение выбранного кода, правил или настроек требует повторного ревью |
| `Go build-info ... stale` / `revision mismatch` | Повторно экспортировать JSON в доверенном CI для текущего неизменяемого дерева и ожидаемой ревизии |
| Неполнота `go_imports` при нескольких снимках | Проверить дубли профилей и `dependencies.summary.warnings`; передавать один снимок на профиль |

## Перед публичным релизом

- [ ] Проверить право на публикацию всего включённого исходного кода, тестов, примеров и документации; проверить лицензии сторонних материалов.
- [ ] Проверить `LICENSE` (Apache-2.0), лицензионные заголовки при необходимости, `SECURITY.md` и процедуру релизов.
- [ ] Проверить секреты в исходниках, доступной истории Git и артефактах. Репозиторий уже публичный; его видимость и публикация GitHub Release — разные действия.
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


## Дополнительные источники о вредоносных пакетах

После чтения lock-файлов сканер может по явному запросу проверить точные версии пакетов по OpenSSF Malicious Packages / OSV и GitHub Advisory Database (`type=malware`):

```bash
python protestware_check.py --path ../application --dependencies lock \
  --malware-intel both --malware-strict \
  --malware-max-packages 200 --malware-max-requests 250 \
  --format sarif --output malware-findings.sarif
```

`--malware-intel` принимает `off` (по умолчанию), `osv`, `github`, `both`; `--malware-strict` включает код выхода 2 при неполноте источников или инвентаризации. Пакеты из известных частных, Git, локальных и неопределённых источников пропускаются, что отражается в `skipped_unverified_origin` и `complete=false`. Допущенные имена и версии передаются внешним API; `--package` задаёт публичные координаты явно. Go проверяется по объявленному полному пути модуля, без установления публичности репозитория. `--watchlists` продолжает независимо проверять `toxic-repos` / `black-mark`.

Точные схемы сопоставления, обработка отозванных записей, лимиты и отдельные источники описаны в [справочнике](MALWARE_INTELLIGENCE.md). Обычные CVE не считаются protestware.


## 8. Безопасная эксплуатация и ограничения

- Установите `requirements-resolver.txt` перед тестами разрешения версий. Для полного AST установите `requirements-ast.txt` и заранее загрузите перечисленные выше грамматики. При сканировании автоматическая загрузка грамматик отключена: `auto` сообщает о неполном AST, `required` возвращает код 2.
- Лимиты исходных данных: `--max-bytes` (на файл, по умолчанию 1 000 000), `--max-files` (10 000), `--max-total-bytes` (100 000 000 байт декодированного текста в UTF-8). Превышение суммарного бюджета прекращает анализ с кодом 2. Нечитаемые и слишком большие файлы также исключают успешный код завершения; JSON содержит `scan.complete=false`. Поле относится к чтению выбранных исходных файлов: полнота AST и зависимостей отражается отдельно. Исключения путей и неподдерживаемые расширения остаются вне области сканирования.
- Используйте стабильную копию проекта. В POSIX обход каталогов опирается на файловые дескрипторы; чтение ограничено и допускает только обычные файлы. На Windows нет гарантии защиты от одновременной подмены родительских каталогов. Для враждебного изменяемого дерева используйте изолированную среду и снимок только для чтения.
- Отчёт записывается атомарно. Символические ссылки в конечном пути отчёта и перезапись существующего файла внутри сканируемого каталога запрещены. Сохраняйте отчёты в отдельный доверенный каталог. Существующий отчёт вне исходного дерева можно обновлять.
- GitHub API и загрузка внешних списков не следуют перенаправлениям; используйте актуальное имя репозитория. Ответ GitHub API ограничен 16 МБ.
- В `--package` диапазоны (`^1.0.0`, `>=1.0`, `1.*`), включая сокращённые npm-формы `1` и `1.2`, не считаются зафиксированной версией. В режиме `lock` они отмечаются как неполные; `registry` пытается подобрать версию и явно сохраняет приблизительный характер разрешения. Запросы malware advisories отправляются только для конкретных версий. Для npm нужна полная версия `major.minor.patch` с допустимыми prerelease/build-суффиксами; правило сокращённых npm-версий не переносится на PyPI или NuGet.
- Предупреждения сохраняются в текстовом отчёте и в SARIF `invocations.toolExecutionNotifications`; зарегистрированная неполнота включённых этапов отражается в `executionSuccessful=false` и `properties.analysisCoverage`. Для строгой проверки используйте `--ast-mode required --dependency-strict`, а при включённых advisories — `--malware-strict`.
