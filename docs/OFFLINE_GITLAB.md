# Сканер для закрытого контура GitLab

Образ предназначен для Docker executor на Linux/amd64. В нём есть сканер, политика с минимумом в один файл, Python 3.11, закреплённые по SHA-256 колёса Python и 12 грамматик Tree-sitter. Проверяемый проект поступает в контейнер как данные. Сборка образа требует внешней сети. Для работы заданий достаточно связи с внутренним GitLab и реестром.

## Проверенная сборка от 20 ноября 2026 года

| Объект | Значение |
|---|---|
| Исходный код образа | [Коммит db22d2f](https://github.com/ruslancotcaev9-cyber/protestware_check/commit/db22d2fcb24d71c15f77e696b56b022cb9d0fc0f) |
| Манифест OCI Linux/amd64 | `sha256:73b645983e5ce70ced8f0001899ae8f3b5d2745e7cce156138763b6f63d7860f` |
| SHA-256 файла `scanner.oci.tar` | `89f85dc3f8e8511371246eccbaeb90d1ca6ca544338c1aed083254afdf2ac930` |
| SHA-256 скачанного ZIP | `591977791c042e8425d9fe75999f8e5407fff3663c3fef0fa1539eec11b5c3cb` |
| Готовые файлы | [Скачать архив](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44763143696/artifacts/14641787783) · [Файл GitLab с digest](../examples/protestware-image.yml) |

В двух новых контейнерах с отключённой сетью сканер разобрал четыре файла, включая SQL в UTF-16. Совпали находки, покрытие, результаты AST, контекст анализа и решение gate. В обоих запусках код выхода — 0.

Затем во временном GitLab CE зарегистрировали новый GitLab Runner. В изолированной сети два конвейера одного коммита успешно прошли `protestware_scan` и `protestware_gate` с этим digest. В каждом отчёте разобраны оба исходных файла. Находки, покрытие и решение gate совпали при повторе. [Журнал приёмки](https://github.com/ruslancotcaev9-cyber/protestware_check/actions/runs/44763143696/job/136380648284).

## Перенос готового образа

1. Скачайте артефакт **offline-scanner-linux-amd64** успешного задания **Offline GitLab acceptance** для утверждённой ревизии. Сверьте контрольную сумму OCI-архива с записью приёмки. После распаковки проверьте остальные файлы и перенесите образ в свой реестр. Укажите адрес разрешённого репозитория в переменной окружения `PROTESTWARE_IMAGE_REPOSITORY`.

   ```bash
   sha256sum -c SHA256SUMS
   skopeo copy --preserve-digests oci-archive:scanner.oci.tar "docker://${PROTESTWARE_IMAGE_REPOSITORY}:approved"
   digest=$(cat image-digest.txt)
   skopeo inspect --raw "docker://${PROTESTWARE_IMAGE_REPOSITORY}@${digest}" | sha256sum
   ```

   Последняя команда должна вернуть хеш из image-digest.txt. Имя тега используется при переносе. Задания обращаются к образу по digest манифеста.

2. Перенесите `gitlab-ci-offline.yml` в конфигурацию pipeline и положите поставляемый `protestware-image.yml` по пути `.gitlab/protestware-image.yml` проверяемого проекта. Обе задачи наследуют один образ. В настройках доверенной CI-конфигурации задайте переменную `PROTESTWARE_IMAGE_REPOSITORY` со значением из первого шага. Защитите выбор политики и образа тем же способом, что и остальные обязательные проверки.
3. Подготовьте во внутреннем контуре служебный helper, совместимый с версией GitLab Runner. Для локально загруженных образов можно применять pull_policy=never. Приёмочный тест использует этот режим. Запрет внешнего трафика задаётся сетью runner. У job-контейнеров сохраняется доступ к внутреннему GitLab для checkout и передачи артефактов.
4. Первое задание создаёт report.json, findings.sarif и status.json. Второе проверяет отчёт и возвращает исходное решение сканера. Профиль использует зависимости из lock-файлов, обязательный AST и отключённые сетевые источники advisories и watchlists.

## Пилот в существующем проекте

Для GitLab 18.2 и новее предусмотрен отдельный дочерний конвейер. Сохраните `gitlab-ci-offline.yml` из проверенного архива как `.gitlab/protestware-offline.yml`, а `protestware-image.yml` как `.gitlab/protestware-image.yml`. Добавьте [шаблон пилота](../examples/gitlab-ci-pilot.yml) в репозиторий под именем `.gitlab/protestware-pilot.yml`. В существующем списке `include` основной конфигурации добавьте элемент `local: '/.gitlab/protestware-pilot.yml'`. В проекте должно быть хотя бы одно обычное задание вне стадий `.pre` и `.post`.

Задайте `PROTESTWARE_IMAGE_REPOSITORY` с адресом внутреннего репозитория образов. Для первого запуска передайте переменную `PROTESTWARE_PILOT=1` конвейеру тестовой ветки. Сканер появится в стадии `.post` после успешного выполнения обычных заданий. Ошибка проверки видна в дочернем конвейере и как предупреждение в родительском. Без флага пилот пропускается.

В артефакте `report.json` проверьте `coverage.files_analyzed`, причины пропусков, находки и `gate.exit_code`. Код 1 означает достижение порога риска, код 2 — ошибку или неполную проверку. Если отчёт отсутствует, откройте `status.json` и журнал задания сканирования. Для разбора с командой используйте `findings.sarif`.

## Повторная сборка и приёмка

`bash ci/offline/build.sh /path/to/new-bundle` запускают с проверенной копии проекта на хосте с Bash, GNU tar/zstd, curl, Skopeo и Docker Buildx с OCI exporter. Список зависимостей закреплён в requirements.lock, а базовый Linux-образ и исходный архив грамматик — по digest. Для нового архива используйте созданный вместе с ним файл GitLab с digest. Задание CI сначала выполняет два запуска в новых контейнерах с `--network none`. Дополнительно оно поднимает временные GitLab CE и GitLab Runner в изолированной Docker-сети и сравнивает отчёты двух pipeline одного коммита. Итоговые поля сравнения включают находки, покрытие, AST, контекст и решение gate.
