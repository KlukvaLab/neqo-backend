# Анатомия отпечатка

Как именно neqo-backend добивается совпадения ClientHello с Firefox.
Каждый элемент привязан к источнику в Gecko; номера строк — для
актуального mozilla-central, с которого снимались значения.

## Два пути — два механизма

### QUIC / HTTP-3: отпечаток «из коробки»

neqo — это буквально QUIC/HTTP3-стек Firefox. `Http3Client` из
`neqo-http3` формирует QUIC ClientHello тем же кодом, что и браузер:
порядок расширений, параметры транспорта, кодирование фреймов.
Дополнительные меры в `quic.rs`:

* ALPN `"h3"` (как necko в Http3Session);
* TLS-шифры `TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_256_GCM_SHA384` — те же три набора, что Firefox разрешает
  для QUIC (`neqo-transport::Connection::set_ciphers`);
* случайные 8-байтовые Connection ID (RandomConnectionIdGenerator(8));
* `ConnectionParameters::default()` — дефолты neqo совпадают с тем,
  что использует gecko (versions v1+v2 compatible negotiation, pacing,
  pmtud, congestion control new-reno по умолчанию).

### TLS over TCP: профиль fingerprint.rs

NSS по умолчанию отличается от Firefox — браузер настраивает сокеты
сам (nsNSSIOLayer.cpp). Наш `fingerprint::configure_socket()` делает
то же самое, элемент за элементом:

| Элемент | Значение | Источник |
|---|---|---|
| Версии TLS | 1.2–1.3 | StaticPrefList: security.tls.version.min=3, max=4 |
| Шифры | см. ниже | nsNSSComponent.cpp `sCipherPrefs` + `InitializeCipherSuite()` |
| Сигнатурные схемы | 11 схем (вкл. ecdsa_sha1, rsa_pkcs1_sha1) | nsNSSIOLayer.cpp `sEnabledSignatureSchemes` (release) |
| Named groups (desktop) | mlkem768x25519, x25519, p256, p384, p521, ffdhe2048, ffdhe3072 | nsNSSIOLayer.cpp:1609 |
| Key shares (desktop) | mlkem768x25519 + x25519 + p256 (3 share) | `SSL_SendAdditionalKeyShares(2)` |
| Named groups (android) | без mlkem; shares x25519 + p256 | pref security.tls.enable_kyber = nightly-only на Android |
| GREASE | вкл (`SSL_ENABLE_GREASE`) | включён в современном NSS, Firefox не отключает |
| Пермутация расширений | вкл (`SSL_ENABLE_CH_EXTENSION_PERMUTATION`) | Firefox 124+, дефолт NSS |
| TLS 1.3 compat mode | вкл | nsNSSIOLayer.cpp:1502 — всегда PR_TRUE |
| ECH GREASE | вкл, probability 100%, размер 100 | prefs security.tls.ech.grease_* |
| Сжатие сертификатов | zlib(1), brotli(2), zstd(3) | prefs security.tls.enable_certificate_compression_* |
| OCSP stapling | запрашивается (`SSL_ENABLE_OCSP_STAPLING`) | pref security.ssl.enable_ocsp_stapling |
| SCT | запрашивается | CT-режим Firefox |
| ALPN | вкл; список задаёт приложение | pref security.ssl.enable_alpn |
| Session tickets | вкл | ConfigureTLSSessionIdentifiers |
| 0-RTT | разрешён | pref security.tls.enable_0rtt_data |
| Delegated credentials | разрешены | pref security.tls.enable_delegated_credentials |
| EMS / downgrade check | вкл | nsNSSComponent.cpp CommonInit |

### Наборы шифров (wire-порядок задаёт NSS, не список!)

Firefox в `InitializeCipherSuite()` сначала выключает ВСЕ шифры NSS,
затем включает разрешённые префами. Мы повторяем буквально это.
Порядок в ClientHello определяется порядком компиляции NSS
(`ssl3con.c`) — ещё одна причина держать ту же версию NSS, что у Firefox.

Включены (release-канал):

```
TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
```

Выключены (префы false / удалены из NSS): все DHE-наборы, 3DES, RC4,
NULL, EXPORT. Ошибки «cipher not implemented» при включении отдельных
наборов сознательно игнорируются — так переживаются минорные различия
версий NSS.

### Профили

`NbConnectOptions.profile`:
* `0` = **firefox-desktop** — ML-KEM включён (pref true на desktop),
  три key share. Такой ClientHello у Firefox на Windows/Linux/macOS.
* `1` = **firefox-android** — ML-KEM выключен (pref = nightly-only на
  Android), два key share. Такой ClientHello у release-Firefox на Android.

## Что НЕ входит в ClientHello (но важно для поведенческого анализа)

* **False start** — Firefox включает (pref true), мы нет: он требует
  асинхронной верификации. Не виден на wire, влияет только на тайминг
  первого запроса.
* **TLS resumption** — Firefox переиспользует тикеты между сессиями;
  v1 не хранит TLS-сессии (QUIC 0-RTT-токены — поддерживаются).
* **Record size limit** — Firefox не отправляет это расширение для TLS
  (только для WebRTC); мы тоже.
* **SCSV fallback** — Firefox отправляет TLS_FALLBACK_SCSV только при
  даунгрейде после ошибки (intolerance retry); v1 всегда ходит с
  максимумом (1.3), SCSV не нужен.
* **DNS/подключения**: Firefox использует свой resolver + Happy
  Eyeballs. getaddrinfo + первый адрес — практическая разница есть
  только в сетевом поведении до TLS.

## Проверка отпечатка

1. Поднимите TLS-эхо и снимите ClientHello: `tcpdump`/Wireshark,
   либо tshark-фильтр `tls.handshake.type == 1`.
2. Сравните с реальным Firefox (та же машина):
   * https://tls.browserleaks.com/json — «Ja3/Ja4» и список расширений;
   * `openssl s_client -connect host:443 -tls1_3` — не годится для
     сравнения, нужен именно захват нашего ClientHello.
3. JA4-строка должна совпасть с Firefox того же канала (desktop vs
   android) при том же NSS.

## Обновление под новый Firefox

1. Посмотрите версию NSS у целевого Firefox: about:buildconfig
   («NSS» в списке библиотек).
2. Обновите тарбол в `scripts/fetch_nss.sh` (URL + sha256).
3. Обновите git-теги neqo/nss-rs в `Cargo.toml` (они двигаются вместе:
   см. зависимость `nss` в neqo-репозитории нужного тега).
4. Сверьте diff `nsNSSIOLayer.cpp`/`nsNSSComponent.cpp` на предмет
   новых опций/шифров/групп → поправьте `fingerprint.rs`.
5. Прогоните сравнение ClientHello (раздел выше).
