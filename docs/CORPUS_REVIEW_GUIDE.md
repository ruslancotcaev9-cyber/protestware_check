# Независимое ревью меток корпуса

[Указатель](README.md) · [Правила ротации](../tests/corpus/README.md) ·
[Таблица 56 примеров](CORPUS_LABEL_REVIEW_V6.md).

Метрика требует корректных эталонных меток. Сейчас они подготовлены ассистентом;
независимая человеческая проверка **не выполнена**. Никакой скрипт не может
удостоверить, что заполненное имя принадлежит независимому эксперту.

## Отдельная выборка v8

[24 целых файла](../tests/corpus/fresh-v8.json), [журнал](../tests/corpus/fresh-v8-review.json)
и [таблица меток](CORPUS_LABEL_REVIEW_V8.md) подготовлены отдельно; все 24 pending.
[Протокол](EVALUATION_V8_PROTOCOL.md) и [первый результат](EVALUATION_V8_2026-11-18.md)
сохраняют порядок фиксации. В командах ниже для v8 подставляются fresh-v8.json
и fresh-v8-review.json. Существующие журналы не перезаписываются.

Ссылка label_sources у C#-обёртки указывает на другой закреплённый case только
для проверки метки; detector context остаётся однофайловым. У SQL отрицательная
метка для SQL_DESTRUCTIVE допускает UPDATE/INSERT/DELETE FROM как SQL_MODIFY.
Source kind отличает production, исходник теста и SQL-пример; ни один target
не выполнялся. После просмотра результатов v8 уже использован для оценки,
а не остаётся новым скрытым набором для следующих исправлений.

## Историческая выборка v7

Отдельно подготовлены [24 новых файла](../tests/corpus/fresh-v7.json),
[их журнал](../tests/corpus/fresh-v7-review.json) и
[таблица меток](CORPUS_LABEL_REVIEW_V7.md). Все 24 записи pending.
Для неё в командах ниже замените corpus/review соответствующими путями;
существующий журнал 56 примеров не перезаписывается.
[Протокол](EVALUATION_V7_PROTOCOL.md) · [Результаты](EVALUATION_V7_2026-11-17.md).

## Текущий остаток v7 после C#/Go-реализации

Восемь изученных файлов Cake и go-billy исключены из текущей оценки и перенесены в регрессию.
[retained-v7.json](../tests/corpus/retained-v7.json) и
[retained-v7-review.json](../tests/corpus/retained-v7-review.json) содержат 16
оставшихся случаев/pending; [таблица](CORPUS_LABEL_REVIEW_RETAINED_V7.md).
Их журнал проверяется отдельно от прежних 56 external.json и исторических 24 v7.

## Материалы

- [external.json](../tests/corpus/external.json): код, предложенная метка, правило,
  режим AST, происхождение, лицензия, обоснование и строки положительного evidence.
- [supporting-sources.json](../tests/corpus/supporting-sources.json): закреплённый
  контекст файловых обёрток. Используется для ревью, не для подмены входа детектора.
- [external-review.json](../tests/corpus/external-review.json): журнал решений,
  привязанный к точному SHA-256 корпуса и каждого примера. Все 56 записей — pending.
- [Таблица](CORPUS_LABEL_REVIEW_V6.md): ссылки на неизменяемые upstream-файлы.

Проверяющий изучает полный файл, импорты, контекст обёрток и область правила.
Положительная метка означает присутствие рассматриваемого вызова/команды, а не
вредоносность или обязательное исполнение. Отрицательная относится только к
целевому правилу. Наличие метода Remove/Delete, строки с таким текстом или
type-only import не равнозначно удалению.

## Заполнение журнала

Для каждой записи сохраняются `id`, `case_sha256`, `proposed_positive`. Решение:

| decision | Значение |
|---|---|
| pending | Ревью не завершено; reviewer/reviewer_type/reviewed_at пусты, reason — пустая строка |
| confirmed | Проверяющий согласен с предложением |
| disputed | Проверяющий оспаривает предложение; требуется решение по метке/контексту |

Для confirmed/disputed указываются `reviewer`, `reviewer_type=independent-human`,
`reviewed_at` с часовым поясом и содержательное `reason` со ссылкой на код/контекст.
Личность, компетентность и независимость проверяются организационным процессом.
Файл журнала и задания CI должны поступать из доверенной конфигурации.
Спорная запись не меняет метку автоматически и не исчезает из метрик.

```bash
# Проверить целостность/структуру, допустив незавершённые записи:
python scripts/corpus_review.py validate --corpus tests/corpus/external.json \
  --review tests/corpus/external-review.json

# Потребовать заполнения всех записей без disputed:
python scripts/corpus_review.py validate --corpus tests/corpus/external.json \
  --review tests/corpus/external-review.json --require-complete
```

Без require-complete код 0 означает лишь корректность привязки и структуры.
С require-complete незавершённое/спорное ревью возвращает 1; неверные данные,
неизвестные/повторные ID и несоответствие хешей возвращают 2. Статус claimed-complete
отражает заявления в журнале, не удостоверенную личность: `identity_verified=false`
сохраняется. Для текущих 56 pending-записей require-complete возвращает 1.

## Новая версия корпуса

Изменение кода, метки, правила, режима или происхождения делает прежнюю привязку
неактуальной. Сначала пересмотрите изменение; для новой версии подготовьте новые
файлы, сохранив историю решений:

```bash
python scripts/corpus_review.py prepare --corpus ../external-next.json \
  --output ../external-next-review.json --worksheet ../external-next-review.md
```

Prepare всегда создаёт pending-записи и отказывается перезаписывать существующие
файлы, включая случай их появления между проверкой и записью. Старые решения
нельзя переносить как подтверждённые на изменившийся пример без нового ревью.

## Оценка и CI

```bash
python scripts/evaluate_corpus.py --corpus tests/corpus/external.json \
  --review-file tests/corpus/external-review.json \
  --report-only --measure --output ../external-v4-metrics.json
```

Журнал проверяется до анализа. Метрики включают его статус и counts; pending
не превращается в подтверждение меток. CI сохраняет отчёт, журнал и freeze-файл.
FP/FN внешней оценки видны, но не блокируют report-only; ошибки оценки дают 2.
Частичный AST в заранее выбранном auto отражается отдельно и не становится
успешным полным разбором. Подробности — в [методике корпуса](../tests/corpus/README.md).
