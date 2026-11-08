//! Коды ошибок библиотеки (стабильные значения для C ABI)
//! и внутренний тип ошибки с сообщением.

use std::{cell::RefCell, fmt};

/// Коды ошибок, возвращаемые через C ABI. Значения фиксированы —
/// менять нумерацию между версиями нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0,
    /// Внутренняя ошибка (см. nb_last_error_message)
    Generic = 1,
    InvalidArgument = 2,
    NotInitialized = 3,
    /// Разрешение имени не удалось / некорректный адрес
    DnsFailure = 4,
    /// TCP-соединение не установлено
    ConnectFailed = 5,
    /// TLS/QUIC handshake не завершён (в т.ч.Fatal alert)
    HandshakeFailed = 6,
    /// Цепочка сертификатов не прошла проверку
    CertificateInvalid = 7,
    /// Истёк таймаут операции
    Timeout = 8,
    /// Соединение закрыто (EOF)
    Closed = 9,
    /// Нарушение протокола (HTTP/WS/H3 framing)
    ProtocolError = 10,
    /// Функция не поддерживается в этой сборке
    Unsupported = 11,
    /// Сервер отклонил ECH и прислал новую ECHConfigList — нужен ретрай
    /// (конфиги можно получить через nb_tls_ech_retry_configs).
    EchRetryWithEch = 12,
}

impl ErrorCode {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Ok,
            2 => Self::InvalidArgument,
            3 => Self::NotInitialized,
            4 => Self::DnsFailure,
            5 => Self::ConnectFailed,
            6 => Self::HandshakeFailed,
            7 => Self::CertificateInvalid,
            8 => Self::Timeout,
            9 => Self::Closed,
            10 => Self::ProtocolError,
            11 => Self::Unsupported,
            12 => Self::EchRetryWithEch,
            _ => Self::Generic,
        }
    }
}

/// Полная ошибка: код + человекочитаемое сообщение.
#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
        }
    }

    pub fn generic(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Generic, msg)
    }

    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, msg)
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Timeout, msg)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
            std::io::ErrorKind::UnexpectedEof => ErrorCode::Closed,
            _ => ErrorCode::Generic,
        };
        Self::new(code, format!("io: {e}"))
    }
}

// --- Последняя ошибка для FFI ----------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Записать сообщение последней ошибки (для nb_last_error_message).
pub fn set_last_error(err: &Error) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(format!("{err}"));
    });
}

/// Прочитать и очистить последнее сообщение об ошибке в этом потоке.
pub fn take_last_error() -> Option<String> {
    LAST_ERROR.with(|slot| slot.borrow_mut().take())
}

/// Записать произвольное сообщение (для ошибок, обнаруженных в FFI-обёртке).
pub fn set_last_error_str(msg: impl Into<String>) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(msg.into());
    });
}
