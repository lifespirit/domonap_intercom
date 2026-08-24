# Пример `automation.yaml`

Обезличенный пример находится в [`examples/automation.yaml`](../examples/automation.yaml).

Он показывает две вещи:

1. Telegram router с ручным меню дверей для двух и более Rubetek Panel аккаунтов.
2. Автоматизацию входящего звонка, которая переносит `config_entry_id` и `DoorId` из события Domonap прямо в callback кнопки «Открыть».

В пример не включены реальные токены, chat ID, thread ID, `config_entry_id`, `DoorId`, адреса, названия объектов или entity ID.

## Что нужно заменить

### Telegram event entity

В router есть строка:

```yaml
entity_id: event.REPLACE_WITH_TELEGRAM_BOT_UPDATE_EVENT
```

Замените её на event entity вашего Telegram bot в Home Assistant. Его можно увидеть в **Developer Tools → States** или на странице entities Telegram-интеграции. В современных конфигурациях это обычно entity, атрибуты которой содержат `event_type`, `command`, `chat_id`, callback id и `message`.

### `domonap_telegram_chat_id`

Это ID Telegram-чата, куда Home Assistant должен отправлять входящие звонки.

Удобнее хранить его в `secrets.yaml`:

```yaml
domonap_telegram_chat_id: REPLACE_WITH_CHAT_ID
```

ID можно получить из входящего Telegram update: посмотрите атрибут `chat_id` у event entity Telegram после сообщения боту.

### `domonap_telegram_thread_id`

Если используется Telegram forum/topic, это `message_thread_id` нужной темы:

```yaml
domonap_telegram_thread_id: REPLACE_WITH_THREAD_ID
```

Посмотрите атрибут `message_thread_id` после сообщения, отправленного именно в нужную тему. Иногда значение лежит непосредственно среди атрибутов event entity, иногда внутри объекта `message`.

Если topics не используются, удалите `message_thread_id` из automation входящего звонка. Сам router умеет определять thread исходной команды/callback и отвечает в него автоматически.

### `domonap_entry_a`, `domonap_entry_b`

Это `config_entry_id` соответствующих Rubetek Panel записей.

Получить значение можно в **Developer Tools → Template** по любой entity нужной записи:

```jinja
{{ config_entry_id('camera.REPLACE_WITH_ENTITY_ID') }}
```

или из `.storage/core.config_entries`:

```bash
jq -r '
  .data.entries[]
  | select(.domain == "domonap")
  | [.entry_id, .title]
  | @tsv
' .storage/core.config_entries
```

В `secrets.yaml`:

```yaml
domonap_entry_a: REPLACE_WITH_CONFIG_ENTRY_ID_A
domonap_entry_b: REPLACE_WITH_CONFIG_ENTRY_ID_B
```

Не редактируйте `.storage/core.config_entries` вручную.

### `domonap_door_a`, `domonap_door_b`

Это Domonap `DoorId` для ручного меню дверей.

Самый удобный способ получить `DoorId`:

1. откройте **Developer Tools → Events**;
2. начните слушать `domonap_incoming_call`;
3. вызовите нужный домофон;
4. возьмите `DoorId` и одновременно запомните `config_entry_id` события.

В `secrets.yaml`:

```yaml
domonap_door_a: REPLACE_WITH_DOOR_ID_A
domonap_door_b: REPLACE_WITH_DOOR_ID_B
```

Каждую ручную дверь обязательно связывайте с тем `config_entry_id`, через который у аккаунта действительно есть ключ/доступ к этой двери.

## Почему входящий звонок не использует статическую таблицу дверей

У события Rubetek Panel уже есть нужная пара:

```yaml
DoorId: "..."
config_entry_id: "..."
```

Поэтому callback строится непосредственно из события:

```text
/dn:o:<config_entry_id>:<DoorId>
```

И router вызывает:

```yaml
action: domonap.open_relay_by_door_id
data:
  door_id: "{{ incoming_door_id }}"
  config_entry_id: "{{ incoming_entry_id }}"
```

Такой вариант корректен даже если одна физическая дверь видна нескольким Domonap аккаунтам.

## Почему callback короткий

Telegram ограничивает `callback_data` размером 64 байта. Поэтому пример использует короткий prefix:

```text
/dn:o:
```

Полный `config_entry_id` Home Assistant вместе с обычным Domonap `DoorId` при таком формате помещается в лимит.

## Несколько аккаунтов

Чтобы добавить третий и последующие аккаунты, достаточно:

1. добавить ещё одну Rubetek Panel запись в Home Assistant;
2. получить её `config_entry_id`;
3. при необходимости добавить отдельный SIP User на Asterisk;
4. добавить новые элементы в `doors:` только для ручного меню.

Для кнопки входящего вызова никаких новых mapping rules не требуется — `config_entry_id` приходит в самом событии.
