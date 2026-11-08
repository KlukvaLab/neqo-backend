//! build.rs для neqo-backend.
//!
//! Задачи:
//!  1. Найти заголовки NSS/NSPR тем же способом, что и nss-rs:
//!     - env NSS_DIR=/path/to/nss (сборка NSS из исходников; dist-каталог
//!       располагается рядом: $NSS_DIR/../dist);
//!     - иначе pkg-config nss (системный NSS).
//!  2. Сгенерировать биндинги к тем частям NSPR/SSL, которые nss-rs не
//!     экспортирует (модуль `ssl` там приватный): сокетный слой NSPR
//!     (PR_Connect/PR_Read/...) и дополнительные функции SSL.

use std::{
    env,
    path::PathBuf,
};

use bindgen::Builder;

const SHIM: &str = "bindgen-shim/wrapper.h";

fn nss_include_dirs() -> Vec<PathBuf> {
    // 1) Явно указанный каталог исходников NSS (используется nss-rs для
    //    standalone-сборки): заголовки лежат в ../dist относительно NSS_DIR.
    if let Ok(nss_dir) = env::var("NSS_DIR") {
        let nss_dir = PathBuf::from(nss_dir.trim());
        assert!(
            !nss_dir.is_relative(),
            "NSS_DIR must be an absolute path"
        );
        let dist = nss_dir.parent().unwrap().join("dist");
        let nspr_include = dist.join("Release").join("include").join("nspr");
        let nss_include = dist.join("public").join("nss");
        assert!(
            nspr_include.is_dir() && nss_include.is_dir(),
            "NSS_DIR is set, but dist headers not found at {} (did ./build.sh run?)",
            dist.display()
        );
        return vec![nspr_include, nss_include];
    }

    // 2) Системный NSS через pkg-config. Версию не проверяем здесь:
    //    nss-rs сам требует >= 3.130 и упадёт раньше с понятной ошибкой.
    let lib = pkg_config::Config::new()
        .cargo_metadata(false)
        .print_system_cflags(false)
        .statik(false)
        .probe("nss")
        .expect(
            "NSS headers not found: install libnss3-dev (>= 3.130) or set NSS_DIR \
             to a built NSS checkout (see docs/BUILDING.md)",
        );
    lib.include_paths
}

fn main() {
    println!("cargo:rerun-if-env-changed=NSS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-changed={SHIM}");

    let includes = nss_include_dirs();
    let mut clang_args: Vec<String> = includes
        .iter()
        .map(|p| format!("-I{}", p.display()))
        .collect();
    // Как в nss-rs: без NSPR10 и с корректной целевой ОС.
    clang_args.push("-DNO_NSPR_10_SUPPORT".into());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target_os.as_str() {
        "windows" => clang_args.push("-DWIN".into()),
        "macos" => clang_args.push("-DDARWIN".into()),
        "linux" => clang_args.push("-DLINUX".into()),
        "android" => {
            clang_args.push("-DLINUX".into());
            clang_args.push("-DANDROID".into());
        }
        _ => {}
    }

    let bindings = Builder::default()
        .header(SHIM)
        .generate_comments(false)
        .size_t_is_usize(true)
        .clang_args(&clang_args)
        // --- NSPR: сокеты, пуллинг, DNS -----------------------------------
        .allowlist_function("PR_NewTCPSocket")
        .allowlist_function("PR_Connect")
        .allowlist_function("PR_ConnectContinue")
        .allowlist_function("PR_Read")
        .allowlist_function("PR_Write")
        .allowlist_function("PR_Poll")
        .allowlist_function("PR_Shutdown")
        .allowlist_function("PR_Close")
        .allowlist_function("PR_SetSocketOption")
        .allowlist_function("SECITEM_FreeArray")
        .allowlist_function("PR_GetError")
        .allowlist_function("PR_SetError")
        .allowlist_function("PR_ErrorToString")
        .allowlist_function("PR_MillisecondsToInterval")
        .allowlist_function("PR_GetAddrInfoByName")
        .allowlist_function("PR_EnumerateAddrInfo")
        .allowlist_function("PR_FreeAddrInfo")
        .allowlist_function("SECITEM_FreeItem")
        .allowlist_type("PRFileDesc")
        .allowlist_type("PRNetAddr")
        .allowlist_type("PRIOMethods")
        .allowlist_type("PRFilePrivate")
        .allowlist_type("PRSocketOptionData")
        .allowlist_type("PRSockOption")
        .allowlist_var("PR_SockOpt_.*")
        .allowlist_type("PRPollDesc")
        .allowlist_type("PRAddrInfo")
        .allowlist_type("PRStatus")
        .allowlist_type("PRIntervalTime")
        .allowlist_type("PRShutdownHow")
        .allowlist_type("PRSocketOption")
        .allowlist_var("PR_POLL_.*")
        .allowlist_var("PR_AF_INET.*")
        .allowlist_var("PR_AF_INET6")
        .allowlist_var("PR_IpAddrNull")
        .allowlist_var("PR_LANGUAGE_I_DEFAULT")
        .allowlist_var("PR_WOULD_BLOCK_ERROR")
        .allowlist_var("PR_IO_TIMEOUT_ERROR")
        .allowlist_var("PR_IN_PROGRESS_ERROR")
        .allowlist_var("PR_IS_CONNECTED_ERROR")
        .allowlist_var("PR_NOT_CONNECTED_ERROR")
        .allowlist_var("PR_NETWORK_UNREACHABLE_ERROR")
        .allowlist_var("PR_CONNECT_RESET_ERROR")
        .allowlist_var("PR_SOCKET_SHUTDOWN_ERROR")
        .allowlist_var("PR_BAD_ADDRESS_ERROR")
        .allowlist_var("PR_INTERVAL_NO_TIMEOUT")
        .allowlist_var("PR_INTERVAL_NO_WAIT")
        .allowlist_var("PR_PENDING_INTERRUPT_ERROR")
        // --- SSL: всё, что нужно для профиля Firefox ----------------------
        .allowlist_function("SSL_ImportFD")
        .allowlist_function("SSL_ResetHandshake")
        .allowlist_function("SSL_OptionSet")
        .allowlist_function("SSL_VersionRangeSet")
        .allowlist_function("SSL_CipherPrefSet")
        .allowlist_function("SSL_ImplementedCiphers")
        .allowlist_var("SSL_NumImplementedCiphers")
        .allowlist_var("SSL_ImplementedCiphers")
        .allowlist_function("SSL_NamedGroupConfig")
        .allowlist_function("SSL_SendAdditionalKeyShares")
        .allowlist_function("SSL_SignatureSchemePrefSet")
        .allowlist_function("SSL_SetNextProtoNego")
        .allowlist_function("SSL_GetNextProto")
        .allowlist_function("SSL_AuthCertificateHook")
        .allowlist_function("SSL_ForceHandshake")
        .allowlist_function("SSL_SetURL")
        .allowlist_function("SSL_PeerCertificateChainDER")
        .allowlist_function("SSL_GetExperimentalAPI")
        .allowlist_function("SSL_GetPreliminaryChannelInfo")
        .allowlist_function("SSL_GetChannelInfo")
        .allowlist_function("SSL_CipherSuiteOrderGet")
        .allowlist_function("SSL_CipherSuiteOrderSet")
        .allowlist_function("SSL_SetCertificateCompressionAlgorithm")
        .allowlist_type("SSLVersionRange")
        .allowlist_type("SSLSignatureScheme")
        .allowlist_type("SSLNamedGroup")
        .allowlist_type("SSLCertificateCompressionAlgorithm")
        .allowlist_type("SSLAuthCertificate")
        .allowlist_type("SSLExperimentalAPI")
        .allowlist_type("SSLNextProtoState")
        .allowlist_type("SSLProtocolVariant")
        .allowlist_type("SSLChannelInfo")
        .allowlist_type("SSLPreliminaryChannelInfo")
        .allowlist_type("SECStatus")
        .allowlist_type("SECItem")
        .allowlist_type("SECItemArray")
        .allowlist_type("SECErrorCodes")
        .allowlist_type("SSLErrorCodes")
        // Опции SSL_* (#define из ssl.h) и константы шифров/сигнатур/групп.
        .allowlist_var("SSL_ENABLE_.*")
        .allowlist_var("SSL_HANDSHAKE_AS_CLIENT")
        .allowlist_var("SSL_NO_CACHE")
        .allowlist_var("SSL_RENEGOTIATE_.*")
        .allowlist_var("SSL_REQUIRE_CERTIFICATE")
        .allowlist_var("SSL_REQUEST_CERTIFICATE")
        .allowlist_var("SSL_SECURITY")
        .allowlist_var("SSL_LIBRARY_VERSION_TLS_\\d_\\d")
        .allowlist_var("SSL_LIBRARY_VERSION_\\d.*")
        .allowlist_var("SSL_SSLV3")
        .allowlist_var("SSL_NEXT_PROTO_.*")
        .allowlist_var("TLS_.*")
        .allowlist_var("ssl_sig_.*")
        .allowlist_var("ssl_grp_.*")
        .allowlist_var("ssl_variant_stream")
        .allowlist_var("SECFailure")
        .allowlist_var("SECSuccess")
        .allowlist_var("SEC_ERROR_.*")
        .allowlist_var("SSL_ERROR_.*")
        //.Enum-значения ssl_sig_*/ssl_grp_* приходят как константы
        .constified_enum("SSLSignatureScheme")
        .constified_enum("SSLNamedGroup")
        .constified_enum("SSLProtocolVariant")
        .constified_enum("SSLNextProtoState")
        .constified_enum("SECStatus")
        .constified_enum("PRStatus")
        .constified_enum("PRShutdownHow")
        .constified_enum("PRSockOption")
        .constified_enum("PRDescType")
        .constified_enum("SECErrorCodes")
        .constified_enum("SSLErrorCodes")
        .generate()
        .expect("unable to generate nss/nspr bindings");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("nss_extra.rs"))
        .expect("couldn't write bindings");
}
