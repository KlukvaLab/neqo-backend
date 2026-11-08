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
| -12 | EchRetryWithEch | сервер отклонил ECH → `nb_tls_ech_retry_configs` |

Функции «сколько нужно байт»: если буфер мал, возвращают `-(need)`.
Заголовки: имя и значение пишутся с NUL-терминатором.

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

## Kotlin (JNA)

```kotlin
// build.gradle: implementation("net.java.dev.jna:jna:5.14@aar")

@Structure.FieldOrder("host", "ip", "port", "alpn",
    "ech_config_list", "ech_config_list_len",
    "resumption_token", "resumption_token_len",
    "timeout_ms", "profile", "reserved")
class NbConnectOptions : Structure() {
    @JvmField var host: String? = null
    @JvmField var ip: String? = null
    @JvmField var port: Short = 443
    @JvmField var alpn: String? = null
    @JvmField var ech_config_list: Pointer? = null
    @JvmField var ech_config_list_len: Int = 0
    @JvmField var resumption_token: Pointer? = null
    @JvmField var resumption_token_len: Int = 0
    @JvmField var timeout_ms: Int = 15000
    @JvmField var profile: Byte = 0
    @JvmField var reserved: ByteArray = ByteArray(7)
}

class NbHeader : Structure() { // по одному на заголовок, в массиве
    @JvmField var name: String? = null
    @JvmField var value: Pointer? = null
    @JvmField var value_len: Int = 0
}

interface NeqoBackend : Library {
    fun nb_init(pem: Pointer?, len: Int): Int
    fun nb_last_error_message(): String
    fun nb_version(): String
    fun nb_tls_connect(o: NbConnectOptions): Pointer?
    fun nb_tls_read(t: Pointer, buf: ByteArray, len: Int, ms: Int): Int
    fun nb_tls_write(t: Pointer, buf: ByteArray, len: Int, ms: Int): Int
    fun nb_tls_close(t: Pointer)
    fun nb_h3_connect(o: NbConnectOptions): Pointer?
    fun nb_h3_fetch(h: Pointer, method: String, target: String,
                    hs: Array<NbHeader>?, n: Int,
                    body: ByteArray?, bodyLen: Int, ms: Int): Pointer?
    fun nb_h3_req_status(r: Pointer): Int
    fun nb_h3_req_read(r: Pointer, buf: ByteArray, cap: Int, ms: Int): Int
    fun nb_h3_req_free(r: Pointer)
    fun nb_h3_close(h: Pointer)
    fun nb_ws_connect(o: NbConnectOptions, path: String,
                      hs: Array<NbHeader>?, n: Int): Pointer?
    fun nb_ws_send(w: Pointer, opcode: Byte, data: ByteArray?, len: Int, ms: Int): Int
    fun nb_ws_recv(w: Pointer, opcodeOut: ByteArray, buf: ByteArray, cap: Int, ms: Int): Int
    fun nb_ws_close(w: Pointer, code: Short, reason: String?, ms: Int): Int
}

val nb: NeqoBackend = Native.load("neqo_backend", NeqoBackend::class.java)

// Использование:
val opts = NbConnectOptions().apply {
    host = "example.org"
    port = 443
    profile = if (isAndroid) 1 else 0
    // ech_config_list = Memory(...).apply { write(0, echBytes, 0, echBytes.size) }
    // ech_config_list_len = echBytes.size
}
nb.nb_init(pemMemory, pemLen)   // Android: передать PEM корней
val h3 = nb.nb_h3_connect(opts)!!
val req = nb.nb_h3_fetch(h3, "GET", "/", null, 0, null, 0, 15000)!!
val status = nb.nb_h3_req_status(req)
```

`.so` для Android кладите в `app/src/main/jniLibs/<abi>/`
(все библиотеки из `dist/android-<abi>/`).

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
