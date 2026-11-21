# Проверка внешних примеров GEO_ACTION

Этот лист фиксирует задание до первого запуска. С 21.11.2026 шесть фрагментов используются для авторской регрессии. Для нового слепого измерения нужна другая выборка. Ссылки в таблице ведут на закреплённые коммиты. [Результаты и решение о режиме оценки](GEO_ACTION_EVALUATION.md).

**Критерий.** Определите, управляет ли проверка страны RU/BY или локали ru/be достижимостью конкретной записи в файл либо сетевого вызова. Учитывайте обе ветви, ранний выход и вызов видимой обёртки. Перевод текста, выбор названия и безусловная запись после ветвления сами по себе не образуют такую связь. Оценивается возможное поведение программы. Для каждого ответа укажите условие и строку действия либо причину отсутствия связи.

| Пример | Закреплённые строки | Связь есть / нет / спорно | Условие, действие, обоснование |
|---|---|---|---|
| geo-1 | [shurshun/count-in, 60–75](https://github.com/shurshun/count-in/blob/bd604a66b4145f07f3244ae4a31d5b8ccc49f027/docs/build_site.py#L60-L75) | | |
| geo-2 | [ravindraten/Covid19WorldStats, 752–1156](https://github.com/ravindraten/Covid19WorldStats/blob/22ead0e613c22a94c67dc1e3480a1c1c1154dc87/Bot.py#L752-L1156) | | |
| geo-3 | [videoreg/pi-videoreg, 7–14](https://github.com/videoreg/pi-videoreg/blob/bb0ec6fc6a973ba019b139d2ac4026a15bd9f341/sdk/i18n.py#L7-L14) | | |
| geo-4 | [eugenehp/espeak-ng-rs, 287–337](https://github.com/eugenehp/espeak-ng-rs/blob/8d34c92dbbfcfcdffd7b56e26ab0d25a6566afef/scripts/generate_dict_crates.py#L287-L337) | | |
| geo-5 | [mozilla/mozaic-forecasting, 365–475](https://github.com/mozilla/mozaic-forecasting/blob/e97413b9034b04ae8fbe6ff3b8688c4f656f7cf3/mozaic/holiday_smart.py#L365-L475) | | |
| geo-6 | [Maximoff/Apktool-M-updates, 1–131](https://github.com/Maximoff/Apktool-M-updates/blob/28b30e6c76d9a8626d9ee5cb572ec985feea5191/translate.py#L1-L131) | | |

Исходный протокол предусматривал самостоятельную разметку до просмотра меток и запись решений в журнал с именем, датой и обоснованием. Все шесть записей журнала независимого ревью имеют статус `pending`. Авторское решение хранится отдельно. [Журнал](../tests/corpus/geo-v1-review.json) · [Авторское решение](../tests/corpus/geo-v1-author-decision.json).

Контрольная сумма манифеста — `838dc4e7e141efe89ba03cea24004ca74687b31041120a9f74ed7235f70f56af`.
