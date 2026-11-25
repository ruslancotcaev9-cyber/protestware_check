# Проверка пакета кодовым агентом

Используйте **check-package**, когда разработчик или агент предлагает добавить, обновить, установить или впервые запустить стороннюю библиотеку, CLI либо плагин. Агент проверяет файл, который попадёт в проект, и возвращает решение для его версии, хеша и целевой платформы. Пакет остаётся данными для статического анализа. [Инструкция скилла](../.agents/skills/check-package/SKILL.md)

## Подключение

В этом репозитории скилл целиком находится в `.agents/skills/check-package/`. Codex обнаруживает его при работе в доверенной копии проекта. Для другого проекта скопируйте **всю папку `check-package`** из проверенной ревизии в каталог из таблицы. Сохраните имя папки и расположение `SKILL.md`, `scripts/`, `references/`, `agents/` и `assets/`. [Состав скилла](../.agents/skills/check-package)

| Агент | Каталог в целевом проекте | Явный вызов |
| --- | --- | --- |
| Codex CLI и расширение IDE | `.agents/skills/check-package/` | Укажите `$check-package` в запросе или выберите скилл через `/skills`. [Codex](https://learn.chatgpt.com/docs/build-skills) |
| Claude Code | `.claude/skills/check-package/` | `/check-package` и описание пакета. [Claude Code](https://code.claude.com/docs/en/skills) |
| GitHub Copilot CLI и Copilot в VS Code | `.github/skills/check-package/` | `/check-package`. В CLI команда `/skills info check-package` покажет расположение. [CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) · [VS Code](https://code.visualstudio.com/docs/agent-customization/agent-skills) |
| Cursor, Cline, Mistral Vibe Code | `.agents/skills/check-package/` | `/check-package`. В Cline скилл должен быть включён, в Vibe рабочий каталог должен быть доверенным. [Cursor](https://cursor.com/docs/skills) · [Cline](https://docs.cline.bot/customization/skills) · [Vibe](https://docs.mistral.ai/vibe/code/cli/skills) |
| Gemini CLI | `.agents/skills/check-package/` | Проверьте наличие через `/skills list`, затем попросите «Примени check-package к этому пакету». [Gemini CLI](https://geminicli.com/docs/cli/skills/) |
| OpenCode v2 | `.agents/skills/check-package/` | Упомяните `@check-package` в запросе. [OpenCode](https://opencode.ai/docs/skills/) |
| Google Antigravity CLI, Devin Local | `.agents/skills/check-package/` | `/check-package`. [Antigravity](https://antigravity.google/docs/skills) · [Devin Local](https://docs.devin.ai/desktop/devin-local/customizations) |
| Kiro IDE и CLI | `.kiro/skills/check-package/` | `/check-package`. Для собственного агента CLI добавьте `skill://.kiro/skills/*/SKILL.md` в `resources`. [Kiro](https://kiro.dev/docs/skills/) |

Например, если доверенная копия этого репозитория находится рядом с целевым проектом и называется `protestware_check`, из корня целевого проекта подключите скилл к Claude Code следующей командой. Для Codex замените `.claude` на `.agents`. Команда рассчитана на первую установку в свободный каталог.

```sh
python -c "from shutil import copytree; copytree('../protestware_check/.agents/skills/check-package', '.claude/skills/check-package')"
```

В Aider можно передать `SKILL.md` и оба файла из `references/` через `--read`, а скрипт подготовки и сканер запустить отдельно по инструкции. [Aider](https://aider.chat/docs/usage/conventions.html)

## Первый запрос

**Публичный выпуск.** «Перед добавлением проверь npm-пакет `is-number@7.0.0` из официального реестра для использования в Node.js. Покажи SHA-256 полученного архива, существенные находки, охват зависимостей и решение. Заверши задачу отчётом».

**Внутренний пакет.** «Проверь приложенный wheel для нашего сервиса на Python 3.11. Ожидаемую SHA-256 возьми из доверенного lock-файла. Для бюллетеней используй внутренний снимок. Укажи источник сведений, дату снимка и пробелы в проверке». Передайте агенту пути к архиву, lock-файлу и снимку. Внешним сервисам можно передавать только разрешённые публичные координаты.

Агенту нужны доступ к терминалу, Python 3.11+, доверенная копия `protestware-check` и временный каталог вне проверяемого проекта. Для языков с Tree-sitter заранее подготовьте нужные грамматики. Скилл умеет получить точный выпуск из публичных npm и PyPI или принять локальный архив с ожидаемым хешем из независимого доверенного источника. При проверке кода пакета установка, импорт, сборка и install-хуки исключены. [Получение архива](../.agents/skills/check-package/references/package-intake.md) · [Запуск сканера и проверка бюллетеней](../.agents/skills/check-package/references/scanner.md)

## Как читать ответ

| Решение | Что делать разработчику |
| --- | --- |
| **ДОПУСТИТЬ** | Использовать проверенный выпуск в указанном окружении в пределах проверенного графа зависимостей. |
| **БЛОКИРОВАТЬ** | Остановить добавление полученного файла. При несовпадении доверенного хеша проверить происхождение архива. |
| **РУЧНАЯ ПРОВЕРКА** | Передать указанную находку на оценку. В отчёте должно быть видно, какой путь исполнения или эффект требует решения. |
| **НЕДОСТАТОЧНО ДАННЫХ** | Получить недостающий артефакт, актуальный бюллетень или сведения о составе и повторить проверку. |

Для решения о допуске нужны проверенная идентичность и целостность, покрытие существенных точек запуска и зависимостей, а также актуальные сведения об уязвимостях и вредоносных выпусках. Код выхода `0` при сканировании файлов подтверждает результат только этого этапа. Отчёт агента указывает, что он проверил и какие ограничения остались. [Критерии решений](../.agents/skills/check-package/SKILL.md) · [Источники сведений о пакетах](MALWARE_INTELLIGENCE.md)
