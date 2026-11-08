# Ловушки NSS / neqo / NSPR

Всё, что съело нам кровь при написании этой библиотеки, — чтобы
не наступить снова. Порядок — по опасности.

## 1. `PR_Connect` НЕ запускает TLS-handshake

**Симптом:** соединение «установлено», но первый `PR_Write` отправляет
данные ОТКРЫТЫМ ТЕКСТОМ (или сервер рвёт соединение), а `SSL_PeerCertificate`
возвращает NULL.

**Причина:** в стеке NSPR/NSS SSL — это слой НАД сокетом (`SSL_ImportFD`).
`PR_Connect` завершает только TCP-часть. Handshake запускается лениво:
при первом read/write ИЛИ явно через `SSL_ForceHandshake`.

**Решение (реализовано в `tls.rs`):**

```c
fd = PR_NewTCPSocket();
ssl = SSL_ImportFD(NULL, fd);      /* надеваем SSL-слой          */
/* ... конфигурация ДО handshake ... */
PR_Connect(ssl, &addr, timeout);   /* TCP                        */
SSL_ResetHandshake(ssl, PR_FALSE); /* клиент                     */
SSL_SetURL(ssl, host);             /* SNI + имя для проверки     */
SSL_ForceHandshake(ssl);           /* <- ВОТ ОН, handshake       */
```

Firefox вызывает `SSL_ForceHandshake` из nsSSLIOLayer (PSM) до того,
как отдать сокет necko. Не повторить эту ошибку — главная причина,
по которой «NSS-прокси» обычно ловят.

## 2. Системный NSS слишком старый → молчаливый неправильный отпечаток

`nss-rs 0.16.3` требует NSS **>= 3.130** и при сборке через pkg-config
явно падает («requirement >=3.130, found 3.98»). Но если связать
библиотеку со СТАРЫМ системным NSS в рантайме (rpath не указан,
ldd показывает /lib/x86_64-linux-gnu/libnss3.so) — версия проверится
в `nss::init()` и упадёт, но хуже, если кто-то «починит» проверку:
cipher-список и порядок расширений молча разойдутся с Firefox.

**Правило:** всегда бегаем с NSS из пиннованного тарбола
(`scripts/fetch_nss.sh`), .so-шки кладём рядом с библиотекой,
rpath=`$ORIGIN` (делает `scripts/build_linux.sh`).

## 3. Дубликат крейта nss-rs = несовместимые типы

neqo указывает `nss = { package = "nss-rs", git = ... }` **без тега**.
Если наша зависимость — `git = ..., tag = "0.16.3"`, cargo считает это
**двумя разными исходниками** (та же ревизия!), собирает крейт дважды —
и типы `nss::AuthenticationStatus` из двух копий несовместимы
(E0308 «expected X, found X»).

**Решение:** в `Cargo.toml` наша зависимость байт-в-байт совпадает
с neqo (git без тега), точный коммит фиксирует `Cargo.lock`.
Проверка: `cargo tree | grep nss-rs` — должна быть ОНА строка с (*).

## 4. Экспериментальные API NSS — это макросы

`SSL_SetClientEchConfigs`, `SSL_EnableTls13GreaseEch`,
`SSL_PeerCertificateChainDER`, `SSL_SetCertificateCompressionAlgorithm`,
`SSL_GetEchRetryConfigs` — НЕ функции. В C это макросы поверх
`SSL_GetExperimentalAPI("имя")`, возвращающей указатель на функцию.
bindgen их не видит. В `fingerprint.rs`/`tls.rs` они резолвятся по имени
через `resolve_experimental::<fn(...)->...>(c"...")`.

**Ловушка:** сигнатуру надо указывать руками — опечатка = UB при вызове.

## 5. `SSL_CipherPrefSet` не управляет ПОРЯДКОМ шифров

Firefox полагается на порядок шифров, ЗАШИТЫЙ В КОМПИЛЯЦИЮ NSS
(ssl3con.c). `SSL_CipherSuiteOrderGet/Set` существует, но Firefox его
не использует (кроме ARM-свинга ChaCha20). Следствие: **порядок в
ClientHello задаётся версией NSS** — ещё одна причина пиннинга.
Наш список в `set_ciphers()` — только ВКЛ/ВЫКЛ, как у Firefox.

## 6. nss-rs не экспортирует SSL-биндинги

Модуль `ssl` внутри nss-rs приватный (`mod ssl;`) — наружу торчит
только `Opt` и high-level `agent` API (для neqo). Всё, что нужно для
TLS-сокетов (PR_Connect/PR_Read/PR_Poll + SSL_* функции), мы генерируем
своим bindgen'ом в `build.rs` (шим `bindgen-shim/wrapper.h`).

**Ловушка:** bindgen-имена констант зависят от constified-режима:
`_SECStatus_SECSuccess`, `PRStatus_PR_SUCCESS`,
`SSLNamedGroup_ssl_grp_ec_curve25519`,
`SSLSignatureScheme_ssl_sig_rsa_pss_rsae_sha256` (!не `rsa_pss_sha256`
— это C-алиас, который bindgen не вытягивает).

## 7. `#define SSL_RENEGOTIATE_*` с кастами `(PRBool)2` не парсятся

bindgen не оценивает #define с приведениями типов — константы просто
отсутствуют в биндингах. В `set_options()` значение `2`
(REQUIRES_XTN) проставлено литералом с комментарием.

## 8. Версия Rust и edition

`nss-rs 0.16.3` — edition 2024, MSRV **1.95**. На старом stable cargo
упадёт с малопонятной ошибкой про edition. Держите свежий rustup
(у нас отработало на 1.99.1).

## 9. NSS требует gyp

`./build.sh` падает с «Building NSS requires an installation of gyp»,
если gyp не в PATH. `pip3 install --user gyp-next` ставит `~/.local/bin/gyp`
— не забудьте добавить в PATH перед build.sh (в скриптах сделано).

## 10. QUIC: `process_output()` обязан вызываться в цикле

neqo — библиотека без собственного потока: приложение качает цикл
`process_output` → `Output::Datagram` → `send_to`; таймер из
`Output::Callback(d)` → подождать `d`; события — `next_event()`.
Если после `fetch()` не гнать цикл — запрос зависнет (нет ни
отправки, ни приёма). В `quic.rs` это `drive_until()`.

**Похожая ловушка:** `Output::Datagram` может приходить несколько раз
подряд — читать до `Callback`/`None`.

## 11. Верификация QUIC-сертификатов — на приложении

neqo присылает `Http3ClientEvent::AuthenticationNeeded` и ЖДЁТ
`client.authenticated(status, now)`. Если ответить `Ok` без проверки —
MITM незамечен. Наш `drain_events()` снимает цепочку
(`peer_certificate()`) и гоняет её через тот же rustls-верификатор,
что и TLS-путь.

## 12. ALPN: в NSS клиентский API называется `SSL_SetNextProtoNego`

Историческое имя (NPN), но включает именно ALPN
(комментарий в nsNSSComponent.cpp:869). `SSL_ENABLE_ALPN` + список
через `SSL_SetNextProtoNego` — так делает Firefox.

## 13. ECH: GREASE включается даже без ECHConfigList

Firefox с probability=100% шлёт GREASE-ECH во ВСЕХ ClientHello
(TLS 1.3+), а реальный ECHConfigList (из DNS HTTPS-записи) просто
перекрывает GREASE. Порядок в `set_ech()`: сначала GREASE, потом
`SSL_SetClientEchConfigs`. Если сервер отклонил ECH —
`SSL_ERROR_ECH_RETRY_WITH_ECH`; конфиги для ретрая —
`SSL_GetEchRetryConfigs` (у нас: `nb_tls_ech_retry_configs`).

## 14. `SSL_AuthCertificateHook` требует возврата SECStatus + PR_SetError

При отказе нужно позвать `PR_SetError(SSL_ERROR_BAD_CERTIFICATE)` —
иначе NSS не поймёт причину и сгенерирует кривой alert. Ошибка
пробрасывается наружу через сохранённый в контексте `Error`
(см. `auth_certificate_cb`).

## 15. Сжатые сертификаты (RFC 8879) нужны ДЕКОДЕРОМ

Firefox предлагает zlib/brotli/zstd в `compress_certificate`. Если
сервер реально пришлёт сжатый сертификат, а декодера нет — handshake
упадёт. Мы регистрируем свои декодеры (flate2/brotli/zstd крейты) —
это влияет только на локальный разбор, не на отпечаток.

## 16. Threading

* NSS init — глобальный (`OnceLock`), вызывать можно много раз.
* Один дескриптор (NbTls/NbH3/NbWs) — один поток одновременно.
  Разные дескрипторы — разные потоки — можно.
* `nb_last_error_message()` — thread-local.

## 17. Rust-2024-крейты и старые таргеты

i686/armv7 собираются, но `aws-lc-rs` в зависимостях не используется
нами сознательно (ring вместо него) — на 32-битных таргетах aws-lc
часто не собирается. Если добавите зависимость с дефолтным aws-lc —
не забудьте features = ["ring"].
