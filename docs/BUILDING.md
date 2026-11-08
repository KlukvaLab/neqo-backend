# Сборка neqo-backend

## Состав пиннованного стека

Компоненты зафиксированы так, чтобы отпечаток совпадал с Firefox
и сборка была воспроизводимой:

| Компонент | Версия | Как зафиксирован |
|---|---|---|
| neqo (QUIC/HTTP3) | **0.34.0** | `Cargo.toml`, git-tag `v0.34.0` mozilla/neqo |
| nss-rs (биндинги) | **0.16.3** | `Cargo.toml`, git-tag `v0.16.3` mozilla/nss-rs |
| NSS | **3.130** | тарбол `nss-3.130-with-nspr-4.39.tar.gz` (sha256 сверен с `nss-rs/Cargo.toml`) |
| NSPR | **4.39** | внутри того же тарбола |
| Rust | >= 1.95 (MSRV nss-rs 0.16.3) | tested with 1.99.1 |

> **Важно про отпечаток:** NSS обязан быть той же версии, что и у
> целевого Firefox. NSS 3.130 — минимум для nss-rs 0.16.3/neqo 0.34.
> Когда Firefox обновит NSS, обновите тарбол и версии вместе
> (см. docs/FINGERPRINT.md, раздел «Обновление»).

neqo и nss-rs не публикуются на crates.io — зависимости тянутся с git.
Для офлайн-сборки используйте `cargo vendor` (раздел ниже).

## Зависимости хоста

Linux (Debian/Ubuntu/Mint):

```bash
sudo apt install build-essential clang libclang-dev ninja-build \
     python3 python3-pip python3-venv pkg-config
pip3 install --user gyp-next        # для сборки NSS
```

* `clang/libclang` — нужен bindgen (и в nss-rs, и в neqo-backend).
* `gyp` + `ninja` — сборка NSS из исходников.
* Никаких системных libnss3-dev НЕ требуется — NSS собирается из
  пиннованного тарбола. Системный NSS 3.98 (Ubuntu 24.04) слишком
  стар для nss-rs 0.16.3 (нужен >= 3.130).

Android: дополнительно [Android NDK](https://developer.android.com/ndk)
(r26+/r27, LLVM toolchain) с `ndk-build` не нужен — только clang из NDK.

Windows (MSVC): Visual Studio Build Tools + LLVM (libclang),
`LIBCLANG_PATH` может понадобиться; NSS на Windows собирается в
статике автоматически (см. `nss-rs/build.rs`: debug/Windows → static).

## Шаг 1. NSS (однократно)

```bash
scripts/fetch_nss.sh          # качает тарбол, проверяет sha256, собирает
```

Что делает скрипт:

```
~/gorynych/nss-deps/
  nss-3.130.tar.gz              # исходный тарбол (89 МБ)
  nss-3.130/
    nss/                        # NSS_DIR — на него указывает сборка
    nspr/
    dist/                       # появляется после сборки:
      Release/lib/*.a           # статические библиотеки
      Release/include/nspr/     # заголовки NSPR
      public/nss/               # заголовки NSS
```

Ручной эквивалент:

```bash
mkdir -p ~/gorynych/nss-deps && cd ~/gorynych/nss-deps
curl -LO https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_130_RTM/src/nss-3.130-with-nspr-4.39.tar.gz
echo "d122bd039416254567f2dfe7f4c9b6ed4d202d8c6a3ed91332da0d514d0974c0  nss-3.130-with-nspr-4.39.tar.gz" | sha256sum -c -
tar xf nss-3.130-with-nspr-4.39.tar.gz
cd nss-3.130/nss
./build.sh -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 \
           -Ddisable_ckbi=1 -Ddisable_fips=1 --opt --static
```

Переменные окружения для всех команд cargo (скрипты ставят их сами):

```bash
export NSS_DIR="$HOME/gorynych/nss-deps/nss-3.130/nss"
export NSS_PREBUILT=1          # не пересобирать NSS из cargo
```

## Шаг 2. Проверка компиляции

```bash
cd neqo-backend
NSS_DIR=... NSS_PREBUILT=1 cargo check
```

## Шаг 3. Целевые сборки

### Desktop Linux (x86_64, i686, aarch64)

```bash
scripts/build_linux.sh x86_64    # → target/x86_64-unknown-linux-gnu/release/
scripts/build_linux.sh i686      # 32-битный x86
scripts/build_linux.sh aarch64   # ARM64 (cross: rustup target add + gcc-aarch64-linux-gnu)
```

Артефакт: `libneqo_backend.so` (+ `.a`).
Рантайм-зависимости: `libc`, `libstdc++` (от NSS-статики не зависит:
NSS линкуется статически в debug; в release — динамически к собранному
нами же NSS. Скрипт копирует нужные .so рядом и ставит rpath).

### Android (arm64-v8a, armeabi-v7a)

```bash
scripts/build_android.sh arm64   # aarch64-linux-android
scripts/build_android.sh arm32   # armv7a-linux-androideabi
```

Скрипт:

1. кросс-собирает NSS теми же флагами clang'ом из NDK
   (`$TOOLCHAIN/bin/aarch64-linux-android24-clang` и т.п.);
2. `cargo ndk`-стилем собирает cdylib для нужного API (24+);
3. результат: `libneqo_backend.so` — кладётся в
   `android/app/src/main/jniLibs/<abi>/` проекта Gorynych.

NSS для Android-цели собирается в отдельный `dist_android_<abi>`
(заголовки те же, библиотеки другие).

### Desktop Windows (x64, x32)

```bash
scripts/build_windows.sh x64     # msvc
scripts/build_windows.sh x32
```

Требуется `x86_64-pc-windows-msvc`/`i686-pc-windows-msvc` toolchain,
Visual Studio Build Tools, LLVM (libclang). NSS для Windows собирается
статически (так делает и nss-rs). Артефакт: `neqo_backend.dll` + `.lib`.

## Офлайн-сборка (vendor)

Git-зависимости (neqo, nss-rs) можно зафиксировать в дереве проекта:

```bash
cargo vendor vendor/ > .cargo/config.toml.fragment
# собрать .cargo/config.toml из вывода
```

После этого сборка не ходит в сеть за крейтами (NSS-тарбол всё равно
нужен один раз).

## CI-заметки

* `cargo check` достаточно для проверки ABI-совместимости; полный
  `cargo build --release` нужен для артефактов.
* Тесты: `cargo test` (в т.ч. SHA-1 векторы, ALPN-wire, фрейминг WS).
* Смена таргета не влияет на fingerprint-константы — они в `fingerprint.rs`.

## Траблшутинг

| Симптом | Причина | Решение |
|---|---|---|
| `nss-rs has NSS version requirement >=3.130, found 3.98` | cargo видит системный NSS | задать `NSS_DIR` (+`NSS_PREBUILT=1`) |
| `Building NSS requires an installation of gyp` | нет gyp | `pip3 install --user gyp-next` |
| bindgen `libclang not found` | нет libclang | `apt install libclang-dev` |
| NSS build падает на `--target=arm64` | это флаг macOS | для Linux/Android кросс-сборка через CC/CXX/AR |
| `unsupported platform` при NDK-сборке NSS | старый NDK | r26+ |
