//! Профиль TLS-отпечатка Firefox.
//!
//! Все константы сняты с исходников Gecko (nsNSSIOLayer.cpp,
//! nsNSSComponent.cpp, StaticPrefList.yaml) и применяются к каждому
//! SSL-сокету так же, как это делает браузер. Документация по каждому
//! элементу — docs/FINGERPRINT.md.
//!
//! ВАЖНО: порядок шифров не задаётся списком — NSS выкладывает их в
//! порядке компиляции (ssl3con.c). Firefox полагается на этот порядок,
//! поэтому NSS обязан быть той же версии, что и у целевого Firefox
//! (см. docs/BUILDING.md, пиннинг версий).

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::{c_int, c_uint};

use crate::error::{Error, ErrorCode, Result};
use crate::nssx;

// Константы статусов (constified_enum в биндингах даёт префиксные имена).
use nssx::_SECStatus_SECFailure as SECFailure;
use nssx::_SECStatus_SECSuccess as SECSuccess;

/// Профиль: какой вариант Firefox имитируем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Desktop (Windows/Linux/macOS): ML-KEM (X25519MLKEM768) включён,
    /// key shares: mlkem768x25519 + x25519 + secp256r1.
    FirefoxDesktop,
    /// Android (release): ML-KEM выключен (pref только для nightly),
    /// key shares: x25519 + secp256r1.
    FirefoxAndroid,
}

impl Profile {
    pub fn from_u8(v: u8) -> Self {
        if v == 1 {
            Self::FirefoxAndroid
        } else {
            Self::FirefoxDesktop
        }
    }
}

/// Дополнительные параметры конфигурации сокета.
pub struct TlsOptions<'a> {
    /// ECHConfigList (сырые байты из DNS HTTPS-записи, поле ech=...).
    /// `None` — реальный ECH не используется; GREASE ECH всё равно включается
    /// (pref security.tls.ech.grease_probability = 100).
    pub ech_config_list: Option<&'a [u8]>,
}

impl<'a> TlsOptions<'a> {
    pub fn new() -> Self {
        Self {
            ech_config_list: None,
        }
    }
}

impl Default for TlsOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Сконфигурировать SSL-сокет под профиль Firefox.
///
/// Вызывать ПОСЛЕ `SSL_ImportFD` и ДО `SSL_ResetHandshake`/handshake.
///
/// # Safety
/// `fd` — валидный SSL-дескриптор.
pub unsafe fn configure_socket(
    fd: *mut nssx::PRFileDesc,
    profile: Profile,
    opts: &TlsOptions<'_>,
) -> Result<()> {
    set_version_range(fd)?;
    set_ciphers(fd)?;
    set_signature_schemes(fd)?;
    set_groups(fd, profile)?;
    set_options(fd)?;
    set_ech(fd, opts)?;
    set_cert_compression(fd)?;
    Ok(())
}

/// TLS 1.2 – 1.3 (pref security.tls.version.min=3, max=4).
unsafe fn set_version_range(fd: *mut nssx::PRFileDesc) -> Result<()> {
    let range = nssx::SSLVersionRange {
        min: nssx::SSL_LIBRARY_VERSION_TLS_1_2 as u16,
        max: nssx::SSL_LIBRARY_VERSION_TLS_1_3 as u16,
    };
    secres(nssx::SSL_VersionRangeSet(fd, &range), "SSL_VersionRangeSet")
}

/// Шифры — точная копия nsNSSComponent::InitializeCipherSuite():
/// сначала выключить ВСЕ реализованные NSS, затем включить ровно те,
/// что разрешают префы Firefox по умолчанию (release-канал).
unsafe fn set_ciphers(fd: *mut nssx::PRFileDesc) -> Result<()> {
    let count = nssx::SSL_NumImplementedCiphers as usize;
    let implemented = nssx::SSL_ImplementedCiphers.as_ptr();
    if count == 0 || implemented.is_null() {
        return Err(Error::new(ErrorCode::Generic, "SSL_ImplementedCiphers пуст"));
    }
    for i in 0..count {
        let id = *implemented.add(i);
        // Отключаем всё подряд; ошибки отдельных наборов не важны.
        let _ = nssx::SSL_CipherPrefSet(fd, id as c_int, 0);
    }
    // Включаемые наборы (StaticPrefList.yaml, значение true в release).
    // Порядок в этом списке НЕ влияет на wire — порядок определяет NSS.
    let enabled: &[u32] = &[
        // TLS 1.3
        nssx::TLS_AES_128_GCM_SHA256,
        nssx::TLS_CHACHA20_POLY1305_SHA256,
        nssx::TLS_AES_256_GCM_SHA384,
        // TLS 1.2 ECDHE AEAD
        nssx::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        nssx::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        nssx::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        nssx::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        nssx::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        nssx::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        // CBC (пrefs true)
        nssx::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        nssx::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        nssx::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        nssx::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        // static RSA (пrefs true)
        nssx::TLS_RSA_WITH_AES_128_GCM_SHA256,
        nssx::TLS_RSA_WITH_AES_256_GCM_SHA384,
        nssx::TLS_RSA_WITH_AES_128_CBC_SHA,
        nssx::TLS_RSA_WITH_AES_256_CBC_SHA,
    ];
    for &id in enabled {
        // Отдельные наборы могли быть удалены из NSS — это допустимо.
        let _ = nssx::SSL_CipherPrefSet(fd, id as c_int, 1);
    }
    Ok(())
}

/// Сигнатурные схемы — sEnabledSignatureSchemes из nsNSSIOLayer.cpp
/// (release-канал: список включает ecdsa_sha1).
unsafe fn set_signature_schemes(fd: *mut nssx::PRFileDesc) -> Result<()> {
    use nssx::*;
    let schemes: &[SSLSignatureScheme] = &[
        SSLSignatureScheme_ssl_sig_ecdsa_secp256r1_sha256,
        SSLSignatureScheme_ssl_sig_ecdsa_secp384r1_sha384,
        SSLSignatureScheme_ssl_sig_ecdsa_secp521r1_sha512,
        SSLSignatureScheme_ssl_sig_rsa_pss_rsae_sha256,
        SSLSignatureScheme_ssl_sig_rsa_pss_rsae_sha384,
        SSLSignatureScheme_ssl_sig_rsa_pss_rsae_sha512,
        SSLSignatureScheme_ssl_sig_rsa_pkcs1_sha256,
        SSLSignatureScheme_ssl_sig_rsa_pkcs1_sha384,
        SSLSignatureScheme_ssl_sig_rsa_pkcs1_sha512,
        SSLSignatureScheme_ssl_sig_ecdsa_sha1,
        SSLSignatureScheme_ssl_sig_rsa_pkcs1_sha1,
    ];
    secres(
        nssx::SSL_SignatureSchemePrefSet(
            fd,
            schemes.as_ptr(),
            schemes.len() as c_uint,
        ),
        "SSL_SignatureSchemePrefSet",
    )
}

/// Named groups + количество key shares (nsNSSIOLayer.cpp:1600-1635).
unsafe fn set_groups(fd: *mut nssx::PRFileDesc, profile: Profile) -> Result<()> {
    use nssx::*;
    let (groups, additional_shares): (&[SSLNamedGroup], u32) = match profile {
        Profile::FirefoxDesktop => {
            // security.tls.enable_kyber=true (desktop) + send_p256_keyshare=true
            let g: &[SSLNamedGroup] = &[
                SSLNamedGroup_ssl_grp_kem_mlkem768x25519,
                SSLNamedGroup_ssl_grp_ec_curve25519,
                SSLNamedGroup_ssl_grp_ec_secp256r1,
                SSLNamedGroup_ssl_grp_ec_secp384r1,
                SSLNamedGroup_ssl_grp_ec_secp521r1,
                SSLNamedGroup_ssl_grp_ffdhe_2048,
                SSLNamedGroup_ssl_grp_ffdhe_3072,
            ];
            // mlkem + x25519 + p256 = 3 share; SSL_SendAdditionalKeyShares
            // принимает число ДОПОЛНИТЕЛЬНЫХ shares поверх первого: 2.
            (g, 2)
        }
        Profile::FirefoxAndroid => {
            let g: &[SSLNamedGroup] = &[
                SSLNamedGroup_ssl_grp_ec_curve25519,
                SSLNamedGroup_ssl_grp_ec_secp256r1,
                SSLNamedGroup_ssl_grp_ec_secp384r1,
                SSLNamedGroup_ssl_grp_ec_secp521r1,
                SSLNamedGroup_ssl_grp_ffdhe_2048,
                SSLNamedGroup_ssl_grp_ffdhe_3072,
            ];
            // x25519 + p256 = 2 share → 1 дополнительный.
            (g, 1)
        }
    };
    secres(
        nssx::SSL_NamedGroupConfig(fd, groups.as_ptr(), groups.len() as c_uint),
        "SSL_NamedGroupConfig",
    )?;
    secres(
        nssx::SSL_SendAdditionalKeyShares(fd, additional_shares),
        "SSL_SendAdditionalKeyShares",
    )
}

/// SSL-опции (nsNSSComponent.cpp CommonInit + nsNSSIOLayer.cpp).
unsafe fn set_options(fd: *mut nssx::PRFileDesc) -> Result<()> {
    use nssx::*;

    let on: &[PRInt32] = &[
        SSL_ENABLE_SESSION_TICKETS as PRInt32,        // pref true
        SSL_ENABLE_EXTENDED_MASTER_SECRET as PRInt32, // nsNSSComponent:864
        SSL_ENABLE_HELLO_DOWNGRADE_CHECK as PRInt32,  // pref true
        SSL_ENABLE_ALPN as PRInt32,                   // pref true
        SSL_ENABLE_0RTT_DATA as PRInt32,              // pref true
        SSL_ENABLE_OCSP_STAPLING as PRInt32,          // pref true
        SSL_ENABLE_SIGNED_CERT_TIMESTAMPS as PRInt32, // CT включён в Firefox
        SSL_ENABLE_DELEGATED_CREDENTIALS as PRInt32,  // pref true
        SSL_ENABLE_TLS13_COMPAT_MODE as PRInt32,      // nsNSSIOLayer:1502 — всегда true
        SSL_ENABLE_GREASE as PRInt32,                 // включён в Firefox
        SSL_ENABLE_CH_EXTENSION_PERMUTATION as PRInt32, // Firefox 124+
        SSL_HANDSHAKE_AS_CLIENT as PRInt32,
    ];
    for &opt in on {
        secres(SSL_OptionSet(fd, opt, 1), "SSL_OptionSet(on)")?;
    }
    // Ренеготиация только с расширением (nsNSSComponent:863).
    // SSL_RENEGOTIATE_* объявлены в ssl.h как ((PRBool)N) — bindgen их
    // не вытягивает, используем значение напрямую: REQUIRES_XTN = 2.
    secres(
        SSL_OptionSet(fd, SSL_ENABLE_RENEGOTIATION as PRInt32, 2),
        "SSL_OptionSet(renegotiate)",
    )?;
    // Без записи сессий (NoDB init).
    secres(SSL_OptionSet(fd, SSL_NO_CACHE as PRInt32, 1), "SSL_OptionSet(no_cache)")?;
    Ok(())
}

/// ECH: GREASE всегда (probability=100, size=100); реальный ECH — если
/// передан ECHConfigList (он имеет приоритет над GREASE).
unsafe fn set_ech(fd: *mut nssx::PRFileDesc, opts: &TlsOptions<'_>) -> Result<()> {
    // GREASE ECH — экспериментальный API NSS (как в nsNSSIOLayer:1586).
    let enable_grease: Option<unsafe extern "C" fn(*mut nssx::PRFileDesc, c_int) -> c_int> =
        resolve_experimental(c"SSL_EnableTls13GreaseEch");
    if let Some(f) = enable_grease {
        secres(f(fd, 1), "SSL_EnableTls13GreaseEch")?;
        let set_size: Option<unsafe extern "C" fn(*mut nssx::PRFileDesc, u8) -> c_int> =
            resolve_experimental(c"SSL_SetTls13GreaseEchSize");
        if let Some(f) = set_size {
            // pref security.tls.ech.grease_size = 100
            secres(f(fd, 100), "SSL_SetTls13GreaseEchSize")?;
        }
    }

    if let Some(list) = opts.ech_config_list {
        if !list.is_empty() {
            let set_cfg: Option<
                unsafe extern "C" fn(*mut nssx::PRFileDesc, *const u8, c_uint) -> c_int,
            > = resolve_experimental(c"SSL_SetClientEchConfigs");
            let f = set_cfg.ok_or_else(|| {
                Error::new(ErrorCode::Unsupported, "эта сборка NSS не поддерживает ECH")
            })?;
            secres(
                f(fd, list.as_ptr(), list.len() as c_uint),
                "SSL_SetClientEchConfigs",
            )?;
        }
    }
    Ok(())
}

/// Сжатие сертификатов (RFC 8879): Firefox декларирует zlib(1)/brotli(2)/
/// zstd(3) — префы security.tls.enable_certificate_compression_* = true.
/// NSS вызывает декодер, зарегистрированный для того ID, который выбрал
/// сервер, поэтому для каждого алгоритма — своя функция.
/// API экспериментальный (макрос SSL_EXPERIMENTAL_API) — резолвим по имени.
unsafe fn set_cert_compression(fd: *mut nssx::PRFileDesc) -> Result<()> {
    let set_alg: Option<
        unsafe extern "C" fn(
            *mut nssx::PRFileDesc,
            *mut nssx::SSLCertificateCompressionAlgorithmStr,
        ) -> c_int,
    > = resolve_experimental(c"SSL_SetCertificateCompressionAlgorithm");
    let set_alg = match set_alg {
        Some(f) => f,
        None => return Ok(()), // старый NSS — просто без сжатия
    };

    // NSS хранит указатели на структуры и имена → 'static через Box::leak
    // (по одному разу на процесс — приемлемо).
    let zlib = nssx::SSLCertificateCompressionAlgorithmStr {
        id: 1,
        name: CString::new("zlib").unwrap().into_raw(),
        encode: None,
        decode: Some(decompress_zlib),
    };
    let brotli_alg = nssx::SSLCertificateCompressionAlgorithmStr {
        id: 2,
        name: CString::new("brotli").unwrap().into_raw(),
        encode: None,
        decode: Some(decompress_brotli),
    };
    let zstd_alg = nssx::SSLCertificateCompressionAlgorithmStr {
        id: 3,
        name: CString::new("zstd").unwrap().into_raw(),
        encode: None,
        decode: Some(decompress_zstd),
    };
    for alg in [zlib, brotli_alg, zstd_alg] {
        let ptr = Box::into_raw(Box::new(alg));
        let rv = set_alg(fd, ptr);
        if rv != SECSuccess {
            // Не фатально: потеряем один алгоритм в compress_certificate,
            // handshake с несжатыми сертификатами пройдёт.
            let _ = nssx::PR_GetError();
        }
    }
    Ok(())
}

unsafe extern "C" fn decompress_zlib(
    input: *const nssx::SECItem,
    output: *mut u8,
    output_len: usize,
    used_len: *mut usize,
) -> c_int {
    decompress(input, output, output_len, used_len, |src, _dst| {
        let mut d = flate2::read::ZlibDecoder::new(src);
        let mut out = Vec::new();
        d.read_to_end(&mut out)?;
        Ok(out)
    })
}

unsafe extern "C" fn decompress_brotli(
    input: *const nssx::SECItem,
    output: *mut u8,
    output_len: usize,
    used_len: *mut usize,
) -> c_int {
    decompress(input, output, output_len, used_len, |src, _dst| {
        let mut out = Vec::with_capacity(64 * 1024);
        let mut d = brotli::Decompressor::new(src, 4096);
        d.read_to_end(&mut out)?;
        Ok(out)
    })
}

unsafe extern "C" fn decompress_zstd(
    input: *const nssx::SECItem,
    output: *mut u8,
    output_len: usize,
    used_len: *mut usize,
) -> c_int {
    decompress(input, output, output_len, used_len, |src, _dst| {
        let mut d = zstd::bulk::Decompressor::new()?;
        let out = d.decompress(src, 1 << 16)?;
        Ok(out)
    })
}

/// Общая часть декодеров: проверка аргументов, вызов, копирование в буфер NSS.
unsafe fn decompress(
    input: *const nssx::SECItem,
    output: *mut u8,
    output_len: usize,
    used_len: *mut usize,
    f: impl FnOnce(&[u8], &mut [u8]) -> std::io::Result<Vec<u8>>,
) -> c_int {
    if input.is_null()
        || (*input).data.is_null()
        || (*input).len == 0
        || output.is_null()
        || output_len == 0
        || used_len.is_null()
    {
        nssx::PR_SetError(nssx::SECErrorCodes_SEC_ERROR_INVALID_ARGS as i32, 0);
        return SECFailure;
    }
    let src = std::slice::from_raw_parts((*input).data, (*input).len as usize);
    let dst = std::slice::from_raw_parts_mut(output, output_len);

    match f(src, dst) {
        Ok(out) if out.len() <= dst.len() => {
            dst[..out.len()].copy_from_slice(&out);
            *used_len = out.len();
            SECSuccess
        }
        _ => {
            nssx::PR_SetError(nssx::SECErrorCodes_SEC_ERROR_BAD_DATA as i32, 0);
            SECFailure
        }
    }
}

/// Экспериментальные API NSS разрешаются по имени в функции-указатели
/// (в C это раскрывается макросом SSL_EXPERIMENTAL_API).
unsafe fn resolve_experimental<F: Copy>(name: &CStr) -> Option<F> {
    let p = nssx::SSL_GetExperimentalAPI(name.as_ptr());
    if p.is_null() {
        return None;
    }
    // SSLExperimentalAPI = указатель на функцию; приводим к нужной
    // сигнатуре (раскладка указателей одинакова).
    let raw: unsafe extern "C" fn() = std::mem::transmute(p);
    Some(unsafe { std::mem::transmute_copy::<_, F>(&raw) })
}

/// Преобразование SECStatus в Result с текстом ошибки NSPR.
unsafe fn secres(rv: c_int, what: &str) -> Result<()> {
    if rv == SECSuccess {
        Ok(())
    } else {
        let code = nssx::PR_GetError();
        let msg = {
            let p = nssx::PR_ErrorToString(code, nssx::PR_LANGUAGE_I_DEFAULT);
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        Err(Error::new(
            ErrorCode::HandshakeFailed,
            format!("{what}: {msg} (NSPR/{code})"),
        ))
    }
}

/// Хелпер для FFI: перевод профиля в строку.
pub fn profile_name(p: Profile) -> &'static str {
    match p {
        Profile::FirefoxDesktop => "firefox-desktop",
        Profile::FirefoxAndroid => "firefox-android",
    }
}
