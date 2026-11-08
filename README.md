# neqo-backend (Workspace)

Workspace на базе [Mozilla Neqo](https://github.com/mozilla/neqo) (v0.34.0)
для сборки `neqo-backend` — сетевого бэкенда с TLS/QUIC-отпечатком Firefox.

Maintained by [KlukvaLab](https://github.com/KlukvaLab).

## Состав

- **`neqo-backend/`** — C-ABI мост (`nb_*` API): TLS 1.2/1.3 (NSS), HTTP/3
  (QUIC), WSS (RFC 6455). Отпечаток Firefox (шифры, группы, GREASE,
  пермутация расширений — константы из исходников Gecko), строгая
  верификация сертификатов (небезопасного режима нет).
  Документация: `neqo-backend/docs/` (README, BUILDING, FINGERPRINT,
  PITFALLS, USAGE).
- **`neqo-transport/`**, **`neqo-http3/`**, **`neqo-common/`**, ... —
  официальный QUIC-стек Mozilla (тот же код, что в Firefox), v0.34.0.

## Требования

```bash
sudo apt update && sudo apt install -y build-essential clang libclang-dev \
    ninja-build python3 python3-pip pkg-config
# NSS 3.130 (пиннинг версий) — собирается один раз:
neqo-backend/scripts/fetch_nss.sh
```

## Сборка

```bash
./build.sh --release
```

Библиотека: `target/release/libneqo_backend.so` (NSS .so копируются рядом,
rpath=$ORIGIN). Заголовок: `neqo-backend/ffi/neqo_backend.h`.

Прочие платформы: `neqo-backend/scripts/build_linux.sh` (i686/aarch64),
`build_android.sh` (arm64/arm32), `build_windows.sh` (x64/x32).
Подробности: `neqo-backend/docs/BUILDING.md`.

## C ABI (кратко)

`nb_version` — версия; `nb_init(pem_roots, len)` — инициализация NSS +
корни (пусто = корни ОС); `nb_tls_connect/read/write/close` — TLS-сокет;
`nb_h3_connect`, `nb_h3_fetch`, `nb_h3_req_*` — HTTP/3; `nb_ws_connect/
send/recv/close` — WSS; `nb_get_last_error` — текст последней ошибки.

Полный список, коды ошибок, ECH/0-RTT-аргументы, Kotlin/JNA — в
`neqo-backend/ffi/neqo_backend.h` и `neqo-backend/docs/USAGE.md`.

## Лицензия

MIT OR Apache-2.0. См. [LICENSE-MIT](LICENSE-MIT),
[LICENSE-APACHE](LICENSE-APACHE).
