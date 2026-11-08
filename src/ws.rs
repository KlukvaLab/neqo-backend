//! WebSocket (RFC 6455) поверх TLS — «WSS».
//!
//! Реализован клиентский фрейминг: handshake (HTTP/1.1 Upgrade), маскировка
//! исходящих кадров (клиент обязан), разбор входящих, ping/pong/close.
//! Поведение выравнено под WebSocketChannel из Gecko: авто-ответ pong на
//! ping, close-кадр с кодом, фрагментация входящих сообщений собирается.

use std::time::{Duration, Instant};

use crate::error::{Error, ErrorCode, Result};
use crate::http1::{self, HeaderPair};
use crate::sha1::{base64, sha1};
use crate::tls::{ConnectParams, TlsStream};

pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    fn from_u8(v: u8) -> Result<Self> {
        match v & 0x0F {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(Error::new(ErrorCode::ProtocolError, "неизвестный opcode")),
        }
    }
}

/// Полностью собранное входящее сообщение.
pub struct WsMessage {
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

pub struct WsStream {
    tls: TlsStream,
    /// Текущий фрагментируемый кадр (opcode первого кадра).
    fragment: Option<Opcode>,
    fragment_buf: Vec<u8>,
}

impl WsStream {
    /// Установить WSS-соединение: TLS + HTTP/1.1 Upgrade.
    ///
    /// `extra_headers` — дополнительные заголовки handshake
    /// (User-Agent, Cookie, Sec-WebSocket-Protocol, ...).
    pub fn connect(
        params: &ConnectParams<'_>,
        path: &str,
        extra_headers: &[HeaderPair],
        timeout: Duration,
    ) -> Result<WsStream> {
        // ALPN для WSS: как Firefox, предлагаем [h2, http/1.1]; WebSocket
        // в v1 идёт через http/1.1. Если вызывающий задал свой список в
        // NbConnectOptions.alpn — используем его (например "http/1.1",
        // чтобы гарантировать WSS на h2-серверах).
        let default_alpn: [&str; 2] = ["h2", "http/1.1"];
        let user_alpn: Vec<&str> = params.alpn.map(|s| s.to_vec()).unwrap_or_default();
        let alpn: &[&str] = if user_alpn.is_empty() {
            &default_alpn
        } else {
            &user_alpn
        };
        let tls_params = ConnectParams {
            host: params.host,
            addr: params.addr,
            port: params.port,
            alpn: Some(alpn),
            ech_config_list: params.ech_config_list,
            profile: params.profile,
            timeout: params.timeout,
        };
        let mut tls = TlsStream::connect(&tls_params)?;

        // Если согласовали h2 — WebSocket невозможен (v1); сообщаем ясно.
        if let Some(proto) = tls.negotiated_alpn()? {
            if proto != "http/1.1" {
                tls.close();
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!("ALPN согласовал {proto:?}, для WSS нужен http/1.1"),
                ));
            }
        }

        // Ключ handshake: 16 случайных байтов от NSS PRNG.
        let key_bytes = nss::p11::random::<16>();
        let key = base64(&key_bytes);

        let authority = authority_of(params.host, params.port);
        let headers: Vec<HeaderPair> = {
            let mut v: Vec<HeaderPair> = vec![
                ("Upgrade".into(), "websocket".into()),
                ("Sec-WebSocket-Version".into(), "13".into()),
                ("Sec-WebSocket-Key".into(), key.clone()),
            ];
            v.extend_from_slice(extra_headers);
            v
        };

        let req = http1::Request {
            method: "GET",
            target: path,
            authority: &authority,
            headers: &headers,
            body: None,
            // RFC 6455 §4.1: Connection обязан содержать Upgrade.
            connection: http1::ConnectionHeader::Upgrade,
        };
        let mut resp = http1::send_request_and_read_head(&mut tls, &req, timeout)?;
        if resp.status != 101 {
            tls.close();
            return Err(Error::new(
                ErrorCode::ProtocolError,
                format!("WS handshake: статус {}", resp.status),
            ));
        }
        // Проверяем Sec-WebSocket-Accept.
        let accept = resp.header("Sec-WebSocket-Accept").unwrap_or("");
        let expect = base64(&sha1(format!("{key}{WS_GUID}").as_bytes()));
        if !accept.eq_ignore_ascii_case(&expect) {
            tls.close();
            return Err(Error::new(
                ErrorCode::ProtocolError,
                "Sec-WebSocket-Accept не совпал",
            ));
        }
        let _ = &mut resp;
        Ok(WsStream {
            tls,
            fragment: None,
            fragment_buf: Vec::new(),
        })
    }

    /// Отправить один кадр (маскируется автоматически).
    pub fn send(&mut self, opcode: Opcode, payload: &[u8], timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mask = nss::p11::random::<4>();
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (opcode as u8)); // FIN=1
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        self.tls.write_all(&frame, deadline.saturating_duration_since(Instant::now()))
    }

    /// Прочитать следующее СООБЩЕНИЕ (фрагменты собираются; ping
    /// отрабатывается авто-pong; close возвращает Opcode::Close с
    /// payload = код + причина).
    pub fn recv(&mut self, timeout: Duration) -> Result<WsMessage> {
        let deadline = Instant::now() + timeout;
        loop {
            let hdr = self.read_exact(2, deadline)?;
            let fin = hdr[0] & 0x80 != 0;
            let opcode_raw = hdr[0] & 0x0F;
            let masked = hdr[1] & 0x80 != 0;
            let mut len = (hdr[1] & 0x7F) as u64;
            if len == 126 {
                let b = self.read_exact(2, deadline)?;
                len = u16::from_be_bytes([b[0], b[1]]) as u64;
            } else if len == 127 {
                let b = self.read_exact(8, deadline)?;
                len = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            }
            const MAX_FRAME: u64 = 64 * 1024 * 1024;
            if len > MAX_FRAME {
                return Err(Error::new(ErrorCode::ProtocolError, "кадр WS слишком большой"));
            }
            let mask = if masked {
                Some(self.read_exact(4, deadline)?)
            } else {
                None
            };
            let mut payload = self.read_exact(len as usize, deadline)?;
            if let Some(m) = &mask {
                // Серверные кадры по RFC не маскируются, но раз маска есть —
                // снимаем (как это делает Gecko).
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= m[i & 3];
                }
            }

            let opcode = Opcode::from_u8(opcode_raw)?;
            match opcode {
                Opcode::Ping => {
                    // Авто-pong (WebSocketChannel делает то же).
                    let rem = deadline.saturating_duration_since(Instant::now());
                    self.send(Opcode::Pong, &payload, rem)?;
                    continue;
                }
                Opcode::Pong => continue,
                Opcode::Close => {
                    return Ok(WsMessage {
                        opcode: Opcode::Close,
                        payload,
                    });
                }
                Opcode::Continuation => {
                    let op = self.fragment.take().ok_or_else(|| {
                        Error::new(ErrorCode::ProtocolError, "continuation без начала")
                    })?;
                    self.fragment_buf.extend_from_slice(&payload);
                    if fin {
                        return Ok(WsMessage {
                            opcode: op,
                            payload: std::mem::take(&mut self.fragment_buf),
                        });
                    }
                    self.fragment = Some(op);
                }
                op => {
                    if fin {
                        return Ok(WsMessage {
                            opcode: op,
                            payload,
                        });
                    }
                    self.fragment = Some(op);
                    self.fragment_buf = payload;
                }
            }
        }
    }

    /// Закрывающий кадр + закрытие TLS.
    pub fn close(&mut self, code: u16, reason: &str, timeout: Duration) -> Result<()> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        let _ = self.send(Opcode::Close, &payload, timeout);
        self.tls.close();
        Ok(())
    }

    fn read_exact(&mut self, n: usize, deadline: Instant) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut got = 0usize;
        while got < n {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::timeout("ws: таймаут чтения"));
            }
            let r = self.tls.read(&mut buf[got..], deadline - now)?;
            if r == 0 {
                return Err(Error::new(ErrorCode::Closed, "TLS закрыт при чтении кадра"));
            }
            got += r;
        }
        Ok(buf)
    }
}

fn authority_of(host: &str, port: u16) -> String {
    let default = matches!(port, 80 | 443);
    if host.contains(':') && !host.starts_with('[') {
        // IPv6-литерал
        if default {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}
