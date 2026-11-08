/* Тест 0-RTT-флоу из Kotlin-примера (h3Demo): два соединения,
 * во втором передаём resumption-токен из первого.
 * gcc tests/h3_resume.c -I ffi -o /tmp/h3r -L dist/linux-x86_64 -lneqo_backend
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "neqo_backend.h"

static int do_fetch(NbH3 *h3, const char *label) {
    NbH3Request *r = nb_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
    if (!r) {
        printf("[%s] nb_h3_fetch FAILED: %s\n", label, nb_last_error_message());
        return -1;
    }
    /* ждём заголовки: драйв через read с нулевым буфером */
    unsigned char dummy[1];
    int rc = nb_h3_req_read(r, dummy, 0, 15000);
    if (rc < 0) {
        printf("[%s] await FAILED: %s\n", label, nb_last_error_message());
        nb_h3_req_free(r);
        return -1;
    }
    int status = nb_h3_req_status(r);
    if (status < 0) {
        printf("[%s] статус не получен\n", label);
        nb_h3_req_free(r);
        return -1;
    }
    unsigned char buf[16384];
    long total = 0;
    for (;;) {
        int n = nb_h3_req_read(r, buf, sizeof buf, 10000);
        if (n == 0) break;
        if (n < 0) {
            printf("[%s] read FAILED: %s\n", label, nb_last_error_message());
            nb_h3_req_free(r);
            return -1;
        }
        total += n;
    }
    printf("[%s] HTTP/3 %d, заголовков %d, тело %ld байт\n",
           label, status, nb_h3_req_header_count(r), total);
    nb_h3_req_free(r);
    return 0;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "example.com";
    if (nb_init(NULL, 0) != 0) {
        printf("nb_init FAILED: %s\n", nb_last_error_message());
        return 1;
    }

    unsigned char tok[4096];
    int tok_len = 0;

    for (int i = 0; i < 2; i++) {
        NbConnectOptions o;
        memset(&o, 0, sizeof o);
        o.host = host;
        o.port = 443;
        o.timeout_ms = 15000;
        o.profile = 0;
        if (i == 1 && tok_len > 0) {
            o.resumption_token = tok;
            o.resumption_token_len = (uint32_t)tok_len;
            printf("[2] передаю resumption-токен (%d байт)\n", tok_len);
        }
        NbH3 *h3 = nb_h3_connect(&o);
        if (!h3) {
            printf("[%d] nb_h3_connect FAILED: %s\n", i + 1, nb_last_error_message());
            return 2;
        }
        if (do_fetch(h3, i == 0 ? "1" : "2") != 0) {
            nb_h3_close(h3);
            return 3;
        }
        if (i == 0) {
            tok_len = nb_h3_take_resumption_token(h3, tok, sizeof tok);
            if (tok_len < 0) {
                printf("take_resumption_token FAILED: %s\n", nb_last_error_message());
                nb_h3_close(h3);
                return 4;
            }
            printf("[1] resumption-токен: %d байт\n", tok_len);
        }
        nb_h3_close(h3);
    }
    printf("H3 RESUME TEST OK\n");
    return 0;
}
