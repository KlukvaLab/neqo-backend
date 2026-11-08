# neqo-backend

Сетевой бэкенд с TLS-отпечатком **Firefox** для прокси Gorynych.
Rust-библиотека с C ABI (без JNI) для Kotlin-приложений (Android + Desktop).

## Что это

Библиотека даёт три транспортных пути, неотличимых от настоящего Firefox
на уровне TLS/QUIC ClientHello:

| Путь | Стек | Отпечаток |
|---|---|---|
| **HTTPS over TLS** | NSS (тот же, что в Firefox) | задаётся `fingerprint.rs` по исходникам Gecko |
| **HTTPS over QUIC (HTTP/3)** | neqo 0.34.0 — QUIC-стек Firefox | автоматически (neqo = код браузера) |
| **WSS (WebSocket over TLS)** | NSS + RFC 6455-фрейминг | TLS — как выше; фрейминг как WebSocketChannel |

Все соединения **принудительно проверяются**: цепочка сертификатов
сервера (построение пути, подписи, сроки, SAN, EKU) обязана пройти
проверку — небезопасный режим отсутствует в API.

## Почему отпечаток совпадает

1. **Тот же код**: NSS и neqo — это библиотеки, которыми пользуется сам
   Firefox. neqo формирует QUIC-ClientHello идентично браузеру.
2. **Та же конфигурация**: TLS-сокеты настраиваются по данным, снятым с
   `nsNSSIOLayer.cpp` / `nsNSSComponent.cpp` / `StaticPrefList.yaml`
   Gecko — наборы шифров, группы (включая X25519MLKEM768), GREASE,
   пермутация расширений, сигнатурные схемы, сжатие сертификатов.
   Подробности: [docs/FINGERPRINT.md](docs/FINGERPRINT.md).
3. **Пиннинг версий**: `neqo 0.34.0`, `nss-rs 0.16.3`, `NSS 3.130` —
   см. [docs/BUILDING.md](docs/BUILDING.md).

## Структура

```
ffi/neqo_backend.h   — заголовок C ABI (для JNA и C)
src/
  ffi.rs             — extern "C" слой (изолирует ABI от ядра)
  fingerprint.rs     — профиль Firefox (все константы с источниками)
  tls.rs             — TLS-сокеты NSPR/NSS
  http1.rs           — минимальный HTTP/1.1 (нужен для WSS)
  ws.rs, sha1.rs     — RFC 6455 клиент
  quic.rs            — HTTP/3 клиент (neqo) с синхронным драйвером
  init.rs, verify.rs — NSS init, корни, верификация цепочек
  error.rs           — коды ошибок C ABI
scripts/             — сборка под все целевые платформы
docs/                — документация (RU)
```

## Быстрый старт (C)

```c
#include "neqo_backend.h"

nb_init(NULL, 0);                       // корни из ОС; на Android — PEM

NbConnectOptions opts = {0};
opts.host = "example.org";
opts.port = 443;
opts.timeout_ms = 15000;
opts.profile = 0;                       // 0 = firefox-desktop

/* 1) сырой TLS (байтовый поток) */
NbTls *tls = nb_tls_connect(&opts);
nb_tls_write(tls, req, req_len, 5000);
int n = nb_tls_read(tls, buf, sizeof(buf), 5000);
nb_tls_close(tls);

/* 2) HTTP/3 */
NbH3 *h3 = nb_h3_connect(&opts);
NbH3Request *r = nb_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
int status = nb_h3_req_status(r);       /* ждём != -1 через poll статуса */
int body = nb_h3_req_read(r, buf, sizeof(buf), 5000);
nb_h3_req_free(r); nb_h3_close(h3);

/* 3) WSS */
NbWs *ws = nb_ws_connect(&opts, "/ws", NULL, 0);
nb_ws_send(ws, 1 /*text*/, "hello", 5, 5000);
int len = nb_ws_recv(ws, &opcode, buf, sizeof(buf), 5000);
nb_ws_close(ws, 1000, "bye", 5000);
```

Использование из Kotlin (JNA), список функций, коды ошибок, ECH,
0-RTT-токены: [docs/USAGE.md](docs/USAGE.md).

## Сборка

Требуется pinned-набор (скрипты делают всё сами):

```bash
scripts/fetch_nss.sh          # NSS 3.130 + NSPR 4.39, проверка sha256
scripts/build_linux.sh x86_64 # и/или: i686, aarch64
scripts/build_android.sh arm64 # и/или: arm32
```

Полное описание (зависимости, NDK, Windows, кросс-компиляция):
[docs/BUILDING.md](docs/BUILDING.md).

## Документация

* [docs/BUILDING.md](docs/BUILDING.md) — сборка, таргеты, пиннинг
* [docs/FINGERPRINT.md](docs/FINGERPRINT.md) — анатомия отпечатка
* [docs/PITFALLS.md](docs/PITFALLS.md) — ловушки NSS/neqo (обязательно к прочтению)
* [docs/USAGE.md](docs/USAGE.md) — C ABI, Kotlin/JNA, сценарии

## Статус v1

* TLS 1.2/1.3 (профили desktop/android), HTTP/1.1, HTTP/3, WSS — готово.
* ECH (реальный + GREASE) — передаётся аргументами методов; Kotlin-слой
  приложения сам получает ECHConfigList из DNS и подставляет.
* Не входит в v1: HTTP/2, TLS-resumption, Happy Eyeballs, OCSP-checking
  (stapling запрашивается как в Firefox, но статус не проверяется).

## Проверено (Linux x86_64, машина сборки)

Е2Е-тест `tests/smoke.c` (компилируется с `ffi/neqo_backend.h`, линкуется
с собранной `libneqo_backend.so`):

| Проверка | Результат |
|---|---|
| `cargo test` | 2 passed (SHA-1 векторы, RFC 6455 accept) |
| TLS + HTTP/1.1 GET example.com | **200**, тело прочитано (в т.ч. chunked) |
| HTTP/3 GET example.com (QUIC handshake + верификация цепочки) | **200**, 321 байт |
| WSS-фрейминг | юнит-тесты + авто-pong |
| Отпечаток (tls.browserleaks.com) | JA4 `t13d171500_5b57614c22b0_b04147b66ede`, JA3 `8bebffacf19dcad5fd6481c4663b91dc` — структура (TLS1.3/SNI/17 шифров/21 расширение) соответствует Firefox; с ALPN "h2" префикс станет `t13d1715h2`, как у браузера |
| Рантайм без LD_LIBRARY_PATH | rpath=$ORIGIN на всех .so, NSS 3.130 из бандла |
