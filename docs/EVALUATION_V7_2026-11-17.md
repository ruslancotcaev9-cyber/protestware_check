# Новая внешняя оценка v7 — 17.11.2026

На 24 новых целых файлах код **1.7.0** дал **TP=8, TN=12, FP=0, FN=4,
ошибки=0**, два partial. Четыре пропуска относятся к Go/C# и возникли при
статусе parsed без предупреждений. Это исходная оценка замороженных правил;
исправления детектора и версия кода в этом этапе не менялись.

[Протокол](EVALUATION_V7_PROTOCOL.md) · [Таблица меток](CORPUS_LABEL_REVIEW_V7.md) ·
[Предыдущая проверка](VALIDATION_1_7_0.md) · [Исходный JSON](evaluation/fresh-v7-1.7.0-2026-11-17.json).
Версия остаётся unreleased.

## Зафиксированные входы

[Протокол 01ca43c](https://github.com/ruslancotcaev9-cyber/protestware_check/commit/01ca43c2c54fdd8246d74cdc3792d43e42f14af1)
закрепил шесть новых репозиториев/ревизий и план 24 файлов до первого измерения.
[Коммит входов e6cdf35](https://github.com/ruslancotcaev9-cyber/protestware_check/commit/e6cdf3500681c2761dbd8174b8732f308f2b5f76)
сохранил полные тексты, метки, auto, лицензии, Git blob SHA и SHA-256.
Первый полный успешный прогон выполнен на
[f7124a8ef7bdf70ca7c5b944f7471a0d4e04f0b4](https://github.com/ruslancotcaev9-cyber/protestware_check/commit/f7124a8ef7bdf70ca7c5b944f7471a0d4e04f0b4).

[Манифест](../tests/corpus/fresh-v7-selection.json) перечисляет источники и два
рассмотренных, но не выбранных файла с причинами, заданными до результатов.
Новые источники не совпадают с прежними repository/helper origins, Git blob SHA
или хешами текстов; это проверяет тест. Основной путь и исходник сохраняются.
Каждому case подаётся **один файл**: соседние модули не подставляются.
Target-код, его зависимости, сборочные и установочные скрипты не исполняются.

Код 1.7.0 зафиксирован в main
[8f5369b](https://github.com/ruslancotcaev9-cyber/protestware_check/commit/8f5369beeb1a484ba258c210f2773b4f5578cf8a);
[заморозка правил](evaluation/detector-freeze-v1.7.0.json) ссылается на
d032d7787576f0fdab26649d6e6ad96ddc1ad92f. Правила, resolver, harness
и прежние external/promoted/supporting inputs не изменены.
Новые тексты, метки и режимы не заменялись по полученным исходам.

## Исходы по языкам

| Язык | TP | FP | TN | FN | Ошибки оценки | Partial |
|---|---:|---:|---:|---:|---:|---:|
| C# | 0 | 0 | 2 | 2 | 0 | 0 |
| Go | 0 | 0 | 2 | 2 | 0 | 0 |
| JavaScript | 2 | 0 | 2 | 0 | 0 | 0 |
| Python | 2 | 0 | 2 | 0 | 0 | 1 |
| SQL | 2 | 0 | 2 | 0 | 0 | 0 |
| TypeScript | 2 | 0 | 2 | 0 | 0 | 1 |
| Всего | 8 | 0 | 12 | 4 | 0 | 2 |

В каждом языке два положительных и два отрицательных примера из одного нового
проекта. Доля найденных положительных — 8/12; это результат малого целевого
набора, а не оценка полноты на всех проектах. Положительная метка означает
операцию, а не вредоносность или обязательную достижимость. Отрицательная
относится только к конкретному правилу удаления/SQL.

## Четыре известных пропуска

| Исходник | Строки evidence | Область | AST-статус |
|---|---|---|---|
| [go-git/go-billy:osfs/os_bound.go](https://github.com/go-git/go-billy/blob/d67c9b5cfb14a92d0d5662d42b39444449b36642/osfs/os_bound.go#L153) | 153, 172 | known-wrapper-call | parsed, без предупреждений |
| [go-git/go-billy:osfs/os_rootfs.go](https://github.com/go-git/go-billy/blob/d67c9b5cfb14a92d0d5662d42b39444449b36642/osfs/os_rootfs.go#L198) | 198, 222 | native-instance-call | parsed, без предупреждений |
| [cake-build/cake:src/Cake.Core/IO/File.cs](https://github.com/cake-build/cake/blob/fa072e0574312c3997eceeec47c8de6c36b629b5/src/Cake.Core/IO/File.cs#L59) | 59 | native-instance-call | parsed, без предупреждений |
| [cake-build/cake:src/Cake.Core/IO/Directory.cs](https://github.com/cake-build/cake/blob/fa072e0574312c3997eceeec47c8de6c36b629b5/src/Cake.Core/IO/Directory.cs#L51) | 51 | native-instance-call | parsed, без предупреждений |

В Go RootOS хранит поле *os.Root и вызывает его Remove/RemoveAll; BoundOS
создаёт RootOS через os.OpenRoot и делегирует ему операции. go_bindings.py
в этой версии разрешает прямые os.Remove/RemoveAll и dot-import, но не типы
экземпляров/полей и межфайловые объявления. Для BoundOS конечный native
метод устанавливается при ревью os_rootfs.go; соседний файл не входит в
однофайловый вход этого case. Имя Remove само по себе не доказательство:
отрицательный memfs/memory.go использует память и должен остаться TN.

В Cake readonly-поля _file/_directory имеют типы System.IO.FileInfo и
System.IO.DirectoryInfo и создаются в конструкторах. Их Delete не попадает
в ограниченный шаблон File.Delete/Directory.Delete этой версии.
Нужна проверяемая привязка типа/создания экземпляра с учётом затенения имён,
а не правило для любого одноимённого метода.

Назначение API сверено с первичными источниками:
[Go Root.Remove](https://pkg.go.dev/os#Root.Remove),
[Go Root.RemoveAll](https://pkg.go.dev/os#Root.RemoveAll),
[FileInfo.Delete](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo.delete?view=net-10.0),
[DirectoryInfo.Delete](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo.delete?view=net-10.0).
Это подтверждает API; метки по-прежнему ожидают независимого ревью.

**Parsed/ast.complete описывают выполнение предусмотренных проходов,
а не полноту семантики языка.** Все четыре FN не имеют AST-warning.
Required сам по себе не добавляет отсутствующие связи API. Зелёный CI
в report-only также не означает отсутствие пропусков.

## Частичность и происхождение находок

Два case с TP сохраняют partial:

- angular-angular-cli-fresh-v7-1, delete-output-dir.ts: рекурсивный вызов
  Tree-sitter taint; FS_DELETE найден через tree-sitter-ast.
- pypa-virtualenv-fresh-v7-1, _sync.py: рекурсивный вызов Python taint;
  FS_DELETE найден через ast.

Остальные 22 файла имеют parsed. Четыре положительных JS/TS-файла обнаружены
через tree-sitter-ast, Python — через ast. Два SQL-положительных имеют
matching_analyses=language-pattern, даже при parsed: это не следует называть
семантическим разрешением SQL AST. Статусы и backend сохранены по каждому case.

## CI и исходные данные

[Первый полный CI](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44044966949)
прошёл **516 unit-тестов без пропусков**, syntax checks, реальный Go export/import
на собственной безопасной фикстуре и advisory-регрессии. Шесть новых тестов
проверяют происхождение/лицензии, баланс/режимы, отсутствие пересечений,
неизменность прежних входов, pending-журнал и поведение CI.
[Закреплённые репозитории](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44044966944)
и [сканирование истории](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44044966993)
также прошли. Сторонние проверяемые исходники не выполнялись.

Старые наборы сохранили исходы: собственные 48 — 24TP/24TN; перенесённые 38 —
20TP/18TN, 10 partial; оставшиеся внешние 56 — 28TP/28TN, 6 partial.
В них FP/FN/ошибки=0. Их результаты не объединяются в одну метрику с новым
набором: цели и история использования различаются.

[Исходный JSON](evaluation/fresh-v7-1.7.0-2026-11-17.json) — 18 805 точных байт
отчёта CI, декодированных из архивных строк журнала. SHA-256 сверена с суммой CI.
Отчёт также включён в
[артефакт 14311002733](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44044966949/artifacts/14311002733).
Git-копия JSON доступна после истечения срока хранения Actions-артефакта.

| Объект | SHA-256 |
|---|---|
| fresh-v7.json | 0d917304b8db1254c9532be38f6266220f068bf7468c1790a7182099657cd2a2 |
| Исходный JSON измерения | f28bb4ff7c0ca5f7b6326d028050bca9cb57922ddd97fa876fe6375c0291fea7 |

Одно измерение новых 24 случаев: около 2,95 с без загрузки грамматик,
пик tracemalloc — 3 573 211 байт. Это не вся нативная память парсеров
и не гарантия ресурсов; размеры/сложность файлов отличаются от старых наборов.

## Ограничения и следующий шаг

24 метки предложены ассистентом; [журнал](../tests/corpus/fresh-v7-review.json)
имеет pending=24, confirmed=0, disputed=0, identity_verified=false.
Независимое человеческое ревью не выполнено. Выборка целевая, сбалансированная,
коррелированная внутри проектов и не слепая: ассистент знает архитектуру правил.
Она даёт новые конкретные пропуски, но не независимую сертификацию качества
или безопасность всего пакета. Шесть проектов не представляют все их файлы.

Следующая реализация: привязка FileInfo/DirectoryInfo в C# и os.Root в Go,
затем явные обёртки и диагностика непокрытых связей. Отдельно остаются рекурсивные
partial и прежние SQL syntax recovery. Для исправлений использованные случаи
нужно считать регрессионными, сохранить первый результат v7 и оценить правила
на новых источниках. На этом этапе правила по результатам v7 не подстраивались.

После изучения Cake в 1.8.0 четыре использованных файла перенесены в регрессию.
Текущий retained-v7 содержит 20 остальных примеров; исходные 24 и этот первый
результат не изменены. [Проверка 1.8.0](VALIDATION_1_8_0.md).
