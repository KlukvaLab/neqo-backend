/*
 * neqo_backend.h — C ABI библиотеки neqo-backend.
 *
 * TLS / HTTP/1.1 / HTTP/3 (QUIC) / WSS с отпечатком Firefox на NSS+neqo.
 * Для Kotlin подключается через JNA/JNI-обёртку; для C — напрямую.
 *
 * Правила:
 *  - дескрипторы (NbTls*, NbWs*, NbH3*, NbH3Request*, NbHttpResponse*)
 *    создаются *_connect / *_fetch и освобождаются *_close / *_free;
 *  - возвращаемые int: >= 0 — успех/размер, < 0 — код ошибки
 *    (nb_errno из комментария ниже); текст — nb_last_error_message();
 *  - строки — UTF-8 NUL-terminated; буферы «сколько нужно» возвращаются
 *    как -(need+1);
 *  - вызовы из разных потоков по РАЗНЫМ дескрипторам безопасны;
 *    один дескриптор — один поток одновременно.
 */

#ifndef NEQO_BACKEND_H
#define NEQO_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Коды ошибок (отрицательные возвраты) ----
 *  0  OK
 * -1  Generic — внутренняя ошибка (см. nb_last_error_message)
 * -2  InvalidArgument
 * -3  NotInitialized (nb_init не вызван/не удался)
 * -4  DnsFailure
 * -5  ConnectFailed
 * -6  HandshakeFailed (TLS/QUIC handshake, alert)
 * -7  CertificateInvalid (цепочка не прошла проверку)
 * -8  Timeout
 * -9  Closed (EOF)
 * -10 ProtocolError (HTTP/WS/H3 framing)
 * -11 Unsupported
 * -12 EchRetryWithEch — сервер отклонил ECH; новые конфиги —
 *      nb_tls_ech_retry_configs()/nb_last_error_message()
 */

typedef struct NbTls NbTls;
typedef struct NbWs NbWs;
typedef struct NbH3 NbH3;
typedef struct NbH3Request NbH3Request;
typedef struct NbHttpResponse NbHttpResponse;

typedef struct NbHeader {
    const char *name;    /* UTF-8 */
    const uint8_t *value;
    uint32_t value_len;
} NbHeader;

typedef struct NbConnectOptions {
    const char *host;             /* имя хоста: SNI + проверка сертификата */
    const char *ip;               /* предрезолвленный IP (NULL => резолв lib) */
    uint16_t port;                /* 0 => 443 */
    const char *alpn;             /* wire-список для TLS: "h2,http/1.1"; NULL => нет */
    const uint8_t *ech_config_list; /* ECHConfigList из DNS HTTPS-записи; NULL => нет */
    uint32_t ech_config_list_len;
    const uint8_t *resumption_token; /* QUIC 0-RTT токен; NULL => нет */
    uint32_t resumption_token_len;
    uint32_t timeout_ms;          /* connect+handshake; 0 => 30000 */
    uint8_t profile;              /* 0 = firefox-desktop, 1 = firefox-android */
    uint8_t reserved[7];
} NbConnectOptions;

/* ---- init / версии -------------------------------------------------- */

/* Инициализация. pem_roots: PEM-корни (Android: отдаёт Kotlin-слой из
 * системного хранилища); NULL — корни из хранилища ОС (desktop).
 * Повторный вызов — no-op. */
int32_t nb_init(const uint8_t *pem_roots, uint32_t pem_roots_len);
int32_t nb_shutdown(void);
const char *nb_last_error_message(void); /* до следующего вызова в потоке */
const char *nb_version(void);            /* статическая строка */

/* ---- HTTPS over TLS -------------------------------------------------- */

NbTls *nb_tls_connect(const NbConnectOptions *opts);
/* >=0 прочитано байт; 0 = EOF; <0 ошибка */
int32_t nb_tls_read(NbTls *s, uint8_t *buf, uint32_t len, uint32_t timeout_ms);
/* >=0 записано; <0 ошибка (пишем всё) */
int32_t nb_tls_write(NbTls *s, const uint8_t *buf, uint32_t len, uint32_t timeout_ms);
/* Согласованный ALPN: >0 длина, 0 нет; buf слишком мал => -(need+1) */
int32_t nb_tls_alpn(NbTls *s, char *buf, uint32_t buf_cap);
/* ECHConfigList после EchRetryWithEch */
int32_t nb_tls_ech_retry_configs(NbTls *s, uint8_t *buf, uint32_t buf_cap);
void nb_tls_close(NbTls *s);

/* Полный HTTP/1.1-запрос по TLS-стриму (response буферизуется целиком). */
NbHttpResponse *nb_http1_fetch(NbTls *s,
                               const char *method,
                               const char *target, /* "/path?query" */
                               const NbHeader *headers, uint32_t nheaders,
                               const uint8_t *body, uint32_t body_len,
                               uint32_t timeout_ms);
int32_t nb_http1_response_status(const NbHttpResponse *r);
int32_t nb_http1_response_header_count(const NbHttpResponse *r);
int32_t nb_http1_response_header(const NbHttpResponse *r, int32_t index,
                                 char *name_buf, uint32_t name_cap,
                                 uint8_t *value_buf, uint32_t value_cap);
int32_t nb_http1_response_body(const NbHttpResponse *r,
                               uint8_t *buf, uint32_t buf_cap);
void nb_http1_response_free(NbHttpResponse *r);

/* ---- WSS (WebSocket over TLS, RFC 6455) ------------------------------- */

/* path: "/ws"; headers: User-Agent, Sec-WebSocket-Protocol, Cookie, ... */
NbWs *nb_ws_connect(const NbConnectOptions *opts,
                    const char *path,
                    const NbHeader *headers, uint32_t nheaders);
/* opcode: 1=text, 2=binary, 9=ping */
int32_t nb_ws_send(NbWs *w, uint8_t opcode,
                   const uint8_t *data, uint32_t len, uint32_t timeout_ms);
/* Ждёт сообщение; opcode_out: 1,2,8(close),10(pong).
 * Возвращает длину payload (>=0) или <0. */
int32_t nb_ws_recv(NbWs *w, uint8_t *opcode_out,
                   uint8_t *buf, uint32_t buf_cap, uint32_t timeout_ms);
/* Отправляет close-кадр, закрывает TLS и освобождает дескриптор. */
int32_t nb_ws_close(NbWs *w, uint16_t code, const char *reason, uint32_t timeout_ms);

/* ---- HTTPS over QUIC (HTTP/3) ----------------------------------------- */

NbH3 *nb_h3_connect(const NbConnectOptions *opts);
NbH3Request *nb_h3_fetch(NbH3 *h,
                         const char *method,
                         const char *target,
                         const NbHeader *headers, uint32_t nheaders,
                         const uint8_t *body, uint32_t body_len,
                         uint32_t timeout_ms);
int32_t nb_h3_req_status(const NbH3Request *r);          /* -1 = ещё нет */
int32_t nb_h3_req_header_count(const NbH3Request *r);
int32_t nb_h3_req_header(const NbH3Request *r, int32_t index,
                         char *name_buf, uint32_t name_cap,
                         uint8_t *value_buf, uint32_t value_cap);
/* >=0 прочитано; 0 = тело закончено (fin); <0 ошибка */
int32_t nb_h3_req_read(NbH3Request *r, uint8_t *buf, uint32_t buf_cap,
                       uint32_t timeout_ms);
void nb_h3_req_free(NbH3Request *r);
/* Токен resumption (0-RTT): >0 длина; 0 нет; слишком мал буфер => -(need+1) */
int32_t nb_h3_take_resumption_token(NbH3 *h, uint8_t *buf, uint32_t buf_cap);
void nb_h3_close(NbH3 *h);

#ifdef __cplusplus
}
#endif

#endif /* NEQO_BACKEND_H */
