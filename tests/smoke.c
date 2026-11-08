/* Дымовой тест neqo-backend: TLS + HTTP/1.1 GET, затем HTTP/3.
 * Сборка: gcc tests/smoke.c -I ffi -o smoke -L target/release -lneqo_backend
 * Запуск: LD_LIBRARY_PATH=...:/target/release ./smoke [host]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "neqo_backend.h"

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "example.com";
    printf("version: %s\n", nb_version());

    if (nb_init(NULL, 0) != 0) {
        printf("nb_init FAILED: %s\n", nb_last_error_message());
        return 1;
    }
    printf("nb_init OK (system roots)\n");

    NbConnectOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.host = host;
    opts.port = 443;
    opts.timeout_ms = 15000;
    opts.profile = 0; /* firefox-desktop */

    NbTls *tls = nb_tls_connect(&opts);
    if (!tls) {
        printf("nb_tls_connect FAILED: %s\n", nb_last_error_message());
        return 2;
    }
    printf("nb_tls_connect OK\n");

    char alpn[64] = {0};
    int al = nb_tls_alpn(tls, alpn, sizeof(alpn));
    printf("alpn: %d (%s)\n", al, al > 0 ? alpn : "-");

    const char *ua =
        "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0";
    NbHeader headers[1] = {
        { "User-Agent", (const uint8_t *)ua, (uint32_t)strlen(ua) },
    };
    NbHttpResponse *resp = nb_http1_fetch(
        tls, "GET", "/", headers, 1, NULL, 0, 15000);
    if (!resp) {
        printf("nb_http1_fetch FAILED: %s\n", nb_last_error_message());
        nb_tls_close(tls);
        return 3;
    }
    printf("HTTP status: %d\n", nb_http1_response_status(resp));
    printf("headers: %d\n", nb_http1_response_header_count(resp));
    char name[128], val[512];
    int hn = nb_http1_response_header_count(resp);
    for (int i = 0; i < hn; i++) {
        nb_http1_response_header(resp, i, name, sizeof(name),
                                  (uint8_t *)val, sizeof(val));
        printf("  %s: %s\n", name, val);
    }
    uint8_t body[16384];
    int bl = nb_http1_response_body(resp, body, sizeof(body) - 1);
    if (bl > 0) {
        body[bl < (int)sizeof(body) - 1 ? bl : (int)sizeof(body) - 1] = 0;
    }
    printf("body(%d bytes): %.*s\n", bl, bl > 0 ? bl : 0, (char *)body);
    nb_http1_response_free(resp);
    nb_tls_close(tls);
    printf("SMOKE TEST TLS OK\n");

    /* HTTP/3 */
    NbH3 *h3 = nb_h3_connect(&opts);
    if (!h3) {
        printf("nb_h3_connect FAILED: %s\n", nb_last_error_message());
        return 4;
    }
    printf("nb_h3_connect OK (QUIC handshake)\n");
    NbH3Request *req = nb_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
    if (!req) {
        printf("nb_h3_fetch FAILED: %s\n", nb_last_error_message());
        nb_h3_close(h3);
        return 5;
    }
    int st = -1;
    for (int i = 0; i < 100 && st < 0; i++) {
        uint8_t b[256];
        int n = nb_h3_req_read(req, b, sizeof(b), 300);
        (void)n;
        st = nb_h3_req_status(req);
    }
    printf("H3 status: %d\n", st);
    uint8_t b3[4096];
    int total = 0;
    for (;;) {
        int n = nb_h3_req_read(req, b3, sizeof(b3), 5000);
        if (n <= 0) break;
        total += n;
    }
    printf("H3 body: %d bytes\n", total);
    nb_h3_req_free(req);
    nb_h3_close(h3);
    printf("SMOKE TEST H3 OK\n");
    return 0;
}
