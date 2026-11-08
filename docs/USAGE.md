# Использование neqo-backend

## Модель API

Библиотека — набор C-функций с непрозрачными дескрипторами. Всё
блокирующее, с таймаутами в миллисекундах: никаких колбэков из
библиотеки в приложение (кроме возвратов), никаких потоков внутри
(кроме тех, что создаёт сам NSS внутренне). Это делает интеграцию
с Kotlin/JNA тривиальной.

```
nb_init ──► nb_tls_connect ──► nb_tls_read/write ──► nb_tls_close
              │
              ├─► nb_http1_fetch (запрос+ответ целиком)
              ├─► nb_ws_connect ──► nb_ws_send/recv ──► nb_ws_close
              └─► nb_h3_connect ──► nb_h3_fetch ──► nb_h3_req_read ──► nb_h3_close
```

## Коды возврата

`>= 0` — успех (байты/длина/статус), `< 0` — ошибка:

| Код | Имя | Значение |
|---|---|---|
| -1 | Generic | внутренняя ошибка, детали в `nb_last_error_message()` |
| -2 | InvalidArgument | NULL-указатель, кривая строка |
| -3 | NotInitialized | `nb_init` не вызван/не удался |
| -4 | DnsFailure | имя не разрешилось |
| -5 | ConnectFailed | TCP не соединился |
| -6 | HandshakeFailed | TLS/QUIC handshake, alert |
| -7 | CertificateInvalid | цепочка не прошла проверку |
| -8 | Timeout | истёк таймаут операции |
| -9 | Closed | соединение закрыто (EOF) |
| -10 | ProtocolError | HTTP/WS/H3 framing |
| -11 | Unsupported | не поддерживается сборкой |
| -12 | EchRetryWithEch | сервер отклонил ECH → обновить `ech=` по DNS HTTPS-записи и повторить connect |

Функции «сколько нужно байт»: если буфер мал, возвращают `-(need+1)`.
Заголовки: имя и значение пишутся с NUL-терминатором.

Для функций, возвращающих указатель (`nb_tls_connect`, `nb_ws_connect`,
`nb_h3_connect`, `nb_http1_fetch`, `nb_h3_fetch`; NULL при ошибке), код
ошибки недоступен в возврате — берите его из `nb_last_error_code()`
(1..12; читать ДО `nb_last_error_message()`, тот очищает слот).

## nb_init: корневые сертификаты

* **Desktop (Linux/Windows):** `nb_init(NULL, 0)` — корни берутся из
  хранилища ОС (`rustls-native-certs`).
* **Android:** системного PEM-пути нет — Kotlin-слой читает хранилище
  доверенных ЦС (или бандлит Mozilla CA bundle) и передаёт байты PEM:

```kotlin
val pem = readAsset("mozilla-ca-bundle.pem") // или из системы
nbInit(pem.toByteArray(), pem.size)
```

Повторный вызов `nb_init` — no-op; смешивать нельзя (первый выигрывает).

## ECH и параметры — кто их подставляет

По договорённости, **Kotlin-слой приложения сам** автоматически
подставляет параметры:

* `NbConnectOptions.ech_config_list` — байты `ech=` из DNS HTTPS-записи
  (resolver приложения). Нет записи → NULL (библиотека всё равно шлёт
  GREASE ECH, как Firefox);
* `NbConnectOptions.ip` — предрезолвленный адрес (если приложение хочет
  свой DNS/кеш). NULL → библиотека резолвит `host`;
* `NbConnectOptions.profile` — 0 (desktop) / 1 (android) — выбирается
  по платформе;
* `resumption_token` — 0-RTT токен из прошлого соединения
  (`nb_h3_take_resumption_token`), если приложение хочет ускорить.

## C: сырой TLS-туннель (для прокси)

```c
NbConnectOptions o = {0};
o.host = "target.example";
o.port = 443;
o.timeout_ms = 15000;
o.profile = 0;

NbTls *t = nb_tls_connect(&o);
if (!t) die(nb_last_error_message());

/* дальше — любые байты (протокол прокси Gorynych поверх TLS) */
nb_tls_write(t, payload, len, 5000);
int n = nb_tls_read(t, buf, sizeof buf, 5000); /* 0=EOF, <0=ошибка */
nb_tls_close(t);
```

ALPN при необходимости: `o.alpn = "h2,http/1.1"` (wire-формат: через
запятую). Согласованный протокол — `nb_tls_alpn`.

## C: HTTP/1.1 (полный запрос-ответ)

```c
NbHeader hs[] = {
    { "User-Agent", ua, strlen(ua) },
    { "Accept", "*/*", 3 },
};
NbHttpResponse *r = nb_http1_fetch(t, "POST", "/api/v1/x",
                                   hs, 2, body, body_len, 15000);
int status = nb_http1_response_status(r);          /* 200 */
int n = nb_http1_response_header_count(r);
/* ... nb_http1_response_header(r, i, name, val) ... */
uint8_t body[65536];
int len = nb_http1_response_body(r, body, sizeof body);
nb_http1_response_free(r);
```

Тело ответа буферизуется целиком (v1); для стриминга используйте
сырой TLS + свой HTTP, или HTTP/3-путь (он стриминговый).

## C: HTTP/3 (стриминговое тело)

```c
NbH3 *h = nb_h3_connect(&o);
NbH3Request *r = nb_h3_fetch(h, "GET", "/big.bin", NULL, 0, NULL, 0, 15000);

int status = nb_h3_req_status(r);            /* -1, пока заголовки не пришли */
uint8_t chunk[16384];
for (;;) {
    int n = nb_h3_req_read(r, chunk, sizeof chunk, 5000);
    if (n == 0) break;                        /* fin */
    if (n < 0) die(nb_last_error_message());
    fwrite(chunk, 1, n, out);
}

uint8_t tok[512];
int tl = nb_h3_take_resumption_token(h, tok, sizeof tok); /* для 0-RTT */
nb_h3_req_free(r);
nb_h3_close(h);
```

`nb_h3_req_read` блокирует до появления данных или таймаута — цикл
событий QUIC крутится внутри. Одно соединение → много последовательных
запросов (новый `nb_h3_fetch` без реконнекта).

## C: WebSocket (WSS)

```c
NbHeader hs[] = {
    { "User-Agent", ua, strlen(ua) },
    { "Sec-WebSocket-Protocol", "chat", 4 },
};
NbWs *w = nb_ws_connect(&o, "/ws", hs, 2);

nb_ws_send(w, 1 /* text */, "hello", 5, 5000);

uint8_t op;
uint8_t buf[16384];
int n = nb_ws_recv(w, &op, buf, sizeof buf, 5000);
/* op: 1=text, 2=binary, 8=close(первые 2 байта payload = код), 10=pong */
/* ping сервера библиотека отрабатывает авто-pong сама, как Firefox */

nb_ws_send(w, 9 /* ping */, NULL, 0, 5000);
nb_ws_close(w, 1000, "bye", 5000);
```

Фрейминг RFC 6455: клиентская маскировка, фрагментация входящих
собирается в сообщения (лимит кадра 64 МБ), auto-pong на ping.

ALPN: по умолчанию WSS предлагает `[h2, http/1.1]` (как Firefox); если
сервер согласовал h2 — ошибка Unsupported (WebSocket v1 идёт по http/1.1).
На h2-агрессивных серверах принудите: `o.alpn = "http/1.1"`.

## Kotlin (JNA)

Библиотека — обычный C ABI, поэтому на JVM/Desktop достаточно
[JNA](https://github.com/java-native-access/jna): функции из
`ffi/neqo_backend.h` объявляются в интерфейсе `Library`, структуры
`NbConnectOptions`/`NbHeader` — классами `Structure` с
`@Structure.FieldOrder` в точном порядке полей C (совпадение layout
проверено: 72/24 байта на x86_64).

Поверх сырого биндинга удобно сделать идиоматичную обёртку с
исключениями и `AutoCloseable`; типичный вид:

```kotlin
// desktop: корни из ОС; Android: передать PEM системных корней
Neqo.init()

// HTTPS (HTTP/1.1) — целиком запрос-ответ
Neqo.tls(ConnectOptions(host = "example.org")).use { tls ->
    val resp = tls.fetch("GET", "/", headers = mapOf("User-Agent" to UA))
    println("HTTP ${resp.status}, тело ${resp.body.size} байт")
}

// HTTP/3 — стриминговое тело + resumption-токен для 0-RTT
Neqo.h3(ConnectOptions(host = "cloudflare-quic.com")).use { h3 ->
    h3.fetch("GET", "/").use { req ->
        val status = req.awaitHeaders()
        val body = req.readAll()
    }
    val token = h3.takeResumptionToken()
}

// WSS
Neqo.ws(ConnectOptions(host = "echo.example"), path = "/ws").use { ws ->
    ws.sendText("привет")
    when (val m = ws.receive()) { is WsMessage.Text -> println(m.text) ... }
    ws.close(1000, "bye")
}

// ECH: конфиг берём из DNS HTTPS-записи (приложение отвечает за это само)
val ech = dohFetchEch("crypto.cloudflare.com")   // байты ech= из JSON DoH
Neqo.tls(ConnectOptions(host = "crypto.cloudflare.com", echConfigList = ech)).use { ... }
// при EchRetryWithEch — исключение EchRetryException: обновите конфиг
// по DNS и повторите подключение
```

## Потоки и время жизни

* Дескриптор можно передавать между потоками, но не использовать
  одновременно из двух.
* `nb_*_close/free` освобождают дескриптор; повторное использование
  указателя после — UB.
* `nb_h3_req_free` до `nb_h3_close`; запросы живут внутри соединения.
* Строки из `nb_last_error_message()`/`nb_version()` валидны до
  следующего вызова библиотеки в том же потоке.

## Ограничения v1

* HTTP/1.1-ответ буферизуется целиком (стриминг — TLS/H3-пути).
* TLS-resumption (0-RTT) есть только в QUIC-пути.
* WSS-over-HTTP/3 (WebTransport CONNECT) — не реализован (v2).
* Happy Eyeballs (параллельный v4/v6) — нет: берётся первый адрес.
