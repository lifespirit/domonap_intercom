# SIP / Asterisk для Rubetek Panel

Внешний SIP доступен только для профиля **Rubetek Panel**. Он предназначен для того, чтобы входящий вызов Domonap одновременно поступал на обычный SIP-номер, например внутренний номер Asterisk.

> Поддержка SIP пока экспериментальная. Сигнализация и маршрутизация уже работают, но завершение некоторых Domonap SIP-сессий ещё может вести себя нестабильно на отдельных вызовах. Для диагностики полезно сохранять `pjsip set logger on` на Asterisk и DEBUG-логи `custom_components.domonap.panel_sip`/`panel_call_controller`.

## Архитектура

Home Assistant не проксирует RTP:

```text
                 SIP/TCP                 SIP/UDP
Domonap  <---------------->  Home Assistant  <---------------->  Asterisk
   │                                                            │
   │                         RTP                                │
   └────────────────────────────────────────────────────────────┘
                                                                │ RTP
                                                                ▼
                                                           SIP extension
```

Интеграция работает как небольшой signaling bridge/B2BUA:

1. Panel получает `DomofonCalling` и временные Domonap SIP credentials.
2. Home Assistant регистрирует временный SIP account на стороне Domonap.
3. Одновременно Home Assistant использует настроенный постоянный SIP account на Asterisk.
4. Исходный SDP offer Domonap передаётся Asterisk **без изменения**.
5. SDP answer Asterisk передаётся обратно Domonap **без изменения**.
6. RTP идёт напрямую между Domonap и Asterisk.

Поэтому NAT, RTP range, codec negotiation, jitter buffer и transcoding должны быть настроены на Asterisk, а не в Home Assistant.

## Настройка в Home Assistant

Откройте запись Rubetek Panel:

**Настройки → Устройства и службы → Domonap → нужная запись → Настроить**.

Параметры:

- **Принимать звонки домофона на SIP** — включает внешний SIP.
- **SIP User** — логин отдельного SIP account на Asterisk.
- **SIP Password** — пароль.
- **SIP domain** — `host` или `host:port`, например `pbx.example.lan:5060`.
- **Transport** — сейчас поддерживается только UDP.
- **Номер для звонка** — extension/номер, на который Asterisk должен направить входящий звонок.

## Рекомендуемая схема Asterisk

Для HA-facing endpoint рекомендуется отдельный account на каждую Rubetek Panel запись.

Пример PJSIP endpoint:

```ini
[domonap-panel-a]
type=endpoint
transport=transport-udp
context=from-domonap
auth=domonap-panel-a-auth
aors=domonap-panel-a

direct_media=no
dtmf_mode=info

force_rport=yes
rewrite_contact=yes
rtp_symmetric=yes

disallow=all
allow=alaw
allow=ulaw

[domonap-panel-a-auth]
type=auth
auth_type=userpass
username=domonap-panel-a
password=CHANGE_ME

[domonap-panel-a]
type=aor
max_contacts=1
remove_existing=yes
```

`direct_media=no` важен: Asterisk должен оставаться RTP endpoint, который видит Domonap. Не следует делать re-INVITE напрямую к конечному телефону.

Если Asterisk находится за NAT, SDP, который он возвращает Home Assistant, должен содержать адрес, достижимый со стороны Domonap. Обычно это требует корректных `external_media_address`, `external_signaling_address`, `local_net` и проброса RTP range на Asterisk.

## DTMF

Интеграция не находится в RTP path, поэтому она не видит RFC4733/in-band DTMF непосредственно.

Для открытия двери используется **SIP INFO**, цифра `1`:

```ini
dtmf_mode=info
```

Конечный телефон может использовать другой DTMF mode; Asterisk должен преобразовать его в SIP INFO на leg между Asterisk и Home Assistant.

При получении `1` интеграция:

1. открывает дверь текущего Domonap-вызова;
2. завершает внешний SIP leg;
3. завершает Domonap SIP leg;
4. отправляет backend notification о завершении вызова;
5. снимает временную Domonap SIP-регистрацию.

Такое же поведение используется при открытии двери из Home Assistant или Telegram: **успешное открытие двери завершает текущий звонок**, что соответствует логике Rubetek Panel APK.

Если абонент на Asterisk просто кладёт трубку без открытия двери, интеграция завершает оставшийся Domonap leg.

## Временная Domonap SIP-регистрация

SIP account из полей `SipAccount`, `SipPassword`, `SipDomain` и `SipPort` относится к конкретному входящему вызову и не является постоянной учётной записью.

После завершения вызова интеграция пытается выполнить полный teardown:

```text
NotifyCallEnded(callId)
        +
terminate SIP dialog
        ↓
REGISTER Expires: 0
        ↓
close temporary SIP session
```

Это отдельная регистрация от постоянного SIP account Home Assistant на Asterisk.

## Диагностика

На Asterisk:

```text
pjsip set logger on
rtp set debug on
```

В Home Assistant полезны DEBUG-логи следующих logger'ов:

```text
custom_components.domonap.panel_sip
custom_components.domonap.panel_call_controller
custom_components.domonap.external_sip_signaling
custom_components.domonap.panel_api
```

Для нескольких Rubetek Panel записей обязательно используйте разные SIP User. Подробнее: [multi-account.md](multi-account.md).
