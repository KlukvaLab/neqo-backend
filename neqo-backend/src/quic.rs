//! HTTP/3 клиент на neqo — «HTTPS over QUIC».
//!
//! neqo — это QUIC/HTTP3-стек Firefox, поэтому ClientHello QUIC-ветки
//! автоматически совпадает с браузерным (порядок расширений, параметры
//! транспорта, ALPN "h3"). Синхронный драйвер: UDP-сокет std, цикл
//! process_output/process_input, события drain'ятся внутри операций.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::rc::Rc;
use std::time::{Duration, Instant};

use neqo_common::{Datagram, event::Provider, Tos};
use neqo_http3::{
    Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority,
};
use neqo_transport::{
    Connection, Output, RandomConnectionIdGenerator, StreamId,

};

use crate::error::{Error, ErrorCode, Result};
use crate::verify;

const H3_ALPN: &str = "h3";
const RECV_BUF: usize = 64 * 1024;

pub struct H3ConnectParams<'a> {
    pub host: &'a str,
    pub addr: Option<SocketAddr>,
    pub port: u16,
    /// ECHConfigList (байты ech= из DNS HTTPS-записи).
    pub ech_config_list: Option<&'a [u8]>,
    /// Токен resumption из предыдущего соединения (0-RTT).
    pub resumption_token: Option<&'a [u8]>,
    pub timeout: Duration,
}

/// Один HTTP/3 запрос.
pub struct H3RequestState {
    pub stream_id: StreamId,
    pub status: Option<u16>,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub body_fin: bool,
    pub headers_ready: bool,
}

pub struct H3Connection {
    udp: UdpSocket,
    client: Http3Client,
    local: SocketAddr,
    remote: SocketAddr,
    host: String,
    resumption_token: Option<Vec<u8>>,
    requests: HashMap<StreamId, H3RequestState>,
}

impl H3Connection {
    pub fn connect(p: &H3ConnectParams<'_>) -> Result<H3Connection> {
        let _ = crate::init::global()?;
        let remote = resolve(p)?;
        let deadline = Instant::now() + p.timeout;

        let bind: SocketAddr = if remote.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind)
            .map_err(|e| Error::new(ErrorCode::Generic, format!("UDP bind: {e}")))?;
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let local = udp
            .local_addr()
            .map_err(|e| Error::generic(format!("local_addr: {e}")))?;

        // CID-генератор: Firefox использует случайные 8-байтовые CID.
        let cid_gen: Rc<RefCell<dyn neqo_transport::ConnectionIdGenerator>> =
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8)));

        let mut conn = Connection::new_client(
            p.host,
            &[H3_ALPN],
            cid_gen,
            local,
            remote,
            neqo_transport::ConnectionParameters::default(),
            Instant::now(),
        )
        .map_err(map_neqo("Connection::new_client"))?;

        // TLS-шифры QUIC-ветки — как у Firefox (те же три TLS 1.3 набора).
        conn.set_ciphers(&[
            nss::TLS_AES_128_GCM_SHA256,
            nss::TLS_CHACHA20_POLY1305_SHA256,
            nss::TLS_AES_256_GCM_SHA384,
        ])
        .map_err(map_neqo("set_ciphers"))?;

        let mut client = Http3Client::new_with_conn(
            conn,
            Http3Parameters::default()
                // QPACK-настройки как в neqo/Firefox по умолчанию.
                .max_table_size_encoder(0)
                .max_table_size_decoder(0)
                .max_blocked_streams(0),
        );

        if let Some(ech) = p.ech_config_list {
            client
                .enable_ech(ech)
                .map_err(map_neqo("enable_ech"))?;
        }
        if let Some(token) = p.resumption_token {
            client
                .enable_resumption(Instant::now(), token)
                .map_err(map_neqo("enable_resumption"))?;
        }

        let mut me = H3Connection {
            udp,
            client,
            local,
            remote,
            host: p.host.to_string(),
            resumption_token: None,
            requests: HashMap::new(),
        };

        // Гоняем до Connected (или ZeroRtt).
        me.drive_until(deadline, |me| {
            matches!(
                me.client.state(),
                Http3State::Connected | Http3State::ZeroRtt
            )
        })?;
        match me.client.state() {
            Http3State::Connected | Http3State::ZeroRtt => Ok(me),
            st => Err(Error::new(
                ErrorCode::HandshakeFailed,
                format!("QUIC handshake: {st:?}"),
            )),
        }
    }

    /// Выполнить запрос (метод/путь/заголовки/тело) и дождаться заголовков
    /// ответа. Возвращает stream_id; тело читается read_body.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(String, Vec<u8>)],
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<StreamId> {
        let deadline = Instant::now() + timeout;

        // Дожидаемся готовности создавать запросы.
        self.drive_until(deadline, |me| {
            matches!(me.client.state(), Http3State::Connected)
        })?;

        let mut h3_headers: Vec<Header> = Vec::with_capacity(headers.len() + 1);
        for (n, v) in headers {
            h3_headers.push(Header::new(n.clone(), v.clone()));
        }

        let authority = authority_of(&self.host, self.remote.port());
        let stream_id = self
            .client
            .fetch(
                Instant::now(),
                method,
                ("https", authority.as_str(), path),
                &h3_headers,
                Priority::default(),
            )
            .map_err(map_neqo("fetch"))?;

        if let Some(b) = body {
            if !b.is_empty() {
                let mut sent = 0usize;
                while sent < b.len() {
                    self.drive_until(deadline, |_| true)?;
                    let n = self
                        .client
                        .send_data(stream_id, &b[sent..], Instant::now())
                        .map_err(map_neqo("send_data"))?;
                    sent += n;
                    if n == 0 {
                        self.pump_output()?;
                    }
                }
            }
        }
        self.client
            .stream_close_send(stream_id, Instant::now())
            .map_err(map_neqo("stream_close_send"))?;

        self.requests.insert(
            stream_id,
            H3RequestState {
                stream_id,
                status: None,
                headers: Vec::new(),
                body: Vec::new(),
                body_fin: false,
                headers_ready: false,
            },
        );
        Ok(stream_id)
    }

    /// Дождаться заголовков ответа (status + headers).
    pub fn wait_response(&mut self, stream_id: StreamId, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.drive_until(deadline, |me| {
            me.requests
                .get(&stream_id)
                .is_some_and(|r| r.headers_ready || r.body_fin)
        })?;
        let st = self
            .requests
            .get(&stream_id)
            .ok_or_else(|| Error::invalid_arg("неизвестный stream_id"))?;
        if !st.headers_ready {
            return Err(Error::new(
                ErrorCode::ProtocolError,
                "ответ без заголовков",
            ));
        }
        Ok(())
    }

    /// Прочитать до buf.len() байт тела. 0 = тело закончено.
    pub fn read_body(
        &mut self,
        stream_id: StreamId,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize> {
        let deadline = Instant::now() + timeout;
        self.drive_until(deadline, |me| {
            me.requests
                .get(&stream_id)
                .is_some_and(|r| !r.body.is_empty() || r.body_fin)
        })?;
        let st = self
            .requests
            .get_mut(&stream_id)
            .ok_or_else(|| Error::invalid_arg("неизвестный stream_id"))?;
        if st.body.is_empty() {
            return Ok(0); // fin
        }
        let n = buf.len().min(st.body.len());
        buf[..n].copy_from_slice(&st.body[..n]);
        st.body.drain(..n);
        Ok(n)
    }

    /// Состояние запроса (заголовки/статус).
    pub fn request(&self, stream_id: StreamId) -> Option<&H3RequestState> {
        self.requests.get(&stream_id)
    }

    /// Снять токен resumption (для следующего соединения / 0-RTT).
    pub fn take_resumption_token(&mut self) -> Option<Vec<u8>> {
        self.resumption_token.take()
    }

    pub fn close(&mut self) {
        self.client.close(Instant::now(), 0, "nb");
    }

    // --- драйвер -------------------------------------------------------------

    /// Гонять сетевой цикл, пока `pred` не станет true (или дедлайн).
    fn drive_until(
        &mut self,
        deadline: Instant,
        pred: impl Fn(&mut Self) -> bool,
    ) -> Result<()> {
        loop {
            if pred(self) {
                self.drain_events()?;
                if pred(self) {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::timeout("h3: таймаут операции"));
            }
            self.pump_output()?;
            self.pump_input(deadline)?;
            self.drain_events()?;
        }
    }

    /// Забрать все исходящие датаграммы (Output::Datagram → UDP).
    fn pump_output(&mut self) -> Result<()> {
        loop {
            let out = self.client.process_output(Instant::now());
            match out {
                Output::Datagram(dg) => {
                    let dst = dg.destination();
                    self.udp
                        .send_to(&dg, dst)
                        .map_err(|e| Error::generic(format!("UDP send: {e}")))?;
                }
                Output::Callback(d) => {
                    // Ждать данные или таймер (handled в pump_input).
                    self.wait_readable(Some(d))?;
                    return Ok(());
                }
                Output::None => return Ok(()),
            }
        }
    }

    /// Прочитать датаграммы из сокета (до дедлайна) и скормить neqo.
    fn pump_input(&mut self, deadline: Instant) -> Result<()> {
        loop {
            if Instant::now() >= deadline {
                return Ok(());
            }
            let cb = self.client.process_output(Instant::now());
            let timer = match cb {
                Output::Callback(d) => Some(d),
                Output::Datagram(dg) => {
                    let dst = dg.destination();
                    self.udp
                        .send_to(&dg, dst)
                        .map_err(|e| Error::generic(format!("UDP send: {e}")))?;
                    continue;
                }
                Output::None => return Ok(()),
            };
            if !self.wait_readable(timer)? {
                return Ok(()); // таймер вышел
            }
            let mut buf = [0u8; RECV_BUF];
            let (n, from) = self
                .udp
                .recv_from(&mut buf)
                .map_err(|e| Error::generic(format!("UDP recv: {e}")))?;
            let dg = Datagram::new(
                from,
                self.local,
                Tos::default(),
                buf[..n].to_vec(),
            );
            self.client.process_input(dg, Instant::now());
        }
    }

    /// Ждать читаемости сокета. `timer` — сколько готов ждать neqo.
    /// Возвращает false, если ожидание прервано по таймеру.
    fn wait_readable(&self, timer: Option<Duration>) -> Result<bool> {
        let wait = timer
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(200))
            .max(Duration::from_millis(1));
        self.udp.set_read_timeout(Some(wait)).ok();
        // 1 байт достаточно: MSG_PEEK не потребляет данные.
        let mut probe = [0u8; 1];
        match self.udp.peek_from(&mut probe) {
            Ok(_) => Ok(true),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(Error::generic(format!("UDP peek: {e}"))),
        }
    }

    /// Разобрать события neqo (верификация, заголовки, данные, токены).
    fn drain_events(&mut self) -> Result<()> {
        while let Some(event) = self.client.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    let chain: Vec<Vec<u8>> = self
                        .client
                        .peer_certificate()
                        .map(|info| info.into_iter().map(|c| c.to_vec()).collect())
                        .unwrap_or_default();
                    let status = if verify::verify_server_chain(&chain, &self.host).is_ok() {
                        nss::AuthenticationStatus::Ok
                    } else {
                        // Детали ошибки уже в nb_last_error_message;
                        // neqo требует лишь «доверяем/не доверяем».
                        nss::AuthenticationStatus::CertUntrusted
                    };
                    self.client.authenticated(status, Instant::now());
                }
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    interim,
                    ..
                } => {
                    if let Some(st) = self.requests.get_mut(&stream_id) {
                        if !interim {
                            // Псевдозаголовок :status → код ответа,
                            // остальные псевдозаголовки наружу не отдаём.
                            for h in headers {
                                let name = h.name();
                                if name == ":status" {
                                    st.status =
                                        String::from_utf8_lossy(h.value()).parse().ok();
                                } else if name.starts_with(':') {
                                    continue;
                                } else {
                                    st.headers
                                        .push((name.to_string(), h.value().to_vec()));
                                }
                            }
                            st.headers_ready = true;
                        }
                    }
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut chunk = vec![0u8; RECV_BUF];
                    loop {
                        let (n, fin) = self
                            .client
                            .read_data(Instant::now(), stream_id, &mut chunk)
                            .map_err(map_neqo("read_data"))?;
                        if let Some(st) = self.requests.get_mut(&stream_id) {
                            st.body.extend_from_slice(&chunk[..n]);
                            if fin {
                                st.body_fin = true;
                            }
                        }
                        if n == 0 || fin {
                            break;
                        }
                    }
                }
                Http3ClientEvent::Reset { stream_id, .. }
                | Http3ClientEvent::StopSending { stream_id, .. } => {
                    if let Some(st) = self.requests.get_mut(&stream_id) {
                        st.body_fin = true;
                    }
                }
                Http3ClientEvent::ResumptionToken(token) => {
                    self.resumption_token = Some(token.as_ref().to_vec());
                }
                Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::StateChange(Http3State::ZeroRtt) => {}
                Http3ClientEvent::ZeroRttRejected => {
                    // 0-RTT отклонён — запросы придётся повторить;
                    // для v1 сигнализируем ошибкой активные запросы.
                    for st in self.requests.values_mut() {
                        st.body_fin = true;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn resolve(p: &H3ConnectParams<'_>) -> Result<SocketAddr> {
    if let Some(a) = p.addr {
        return Ok(a);
    }
    let host = p.host.trim_start_matches('[').trim_end_matches(']');
    match (host, p.port).to_socket_addrs() {
        Ok(mut addrs) => addrs
            .next()
            .ok_or_else(|| Error::new(ErrorCode::DnsFailure, "адрес не разрешён")),
        Err(e) => Err(Error::new(
            ErrorCode::DnsFailure,
            format!("DNS {host}: {e}"),
        )),
    }
}

fn authority_of(host: &str, port: u16) -> String {
    let default = port == 443;
    if host.contains(':') && !host.starts_with('[') {
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

fn map_neqo<E: std::fmt::Debug>(what: &'static str) -> impl Fn(E) -> Error {
    move |e| Error::new(ErrorCode::ProtocolError, format!("{what}: {e:?}"))
}
