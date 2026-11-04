use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use neqo_common::event::Provider;
use neqo_common::{Datagram, Tos};
use neqo_transport::{
    Connection, ConnectionEvent, ConnectionParameters, Output, RandomConnectionIdGenerator, State,
    StreamId, StreamType,
};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::crypto::verify_peer_certificate;
use crate::mimicry::{StreamReadBuffer, chunk_payload};

pub struct QuicStream {
    tx_write: mpsc::Sender<Vec<u8>>,
    rx_read: Mutex<StreamReadBuffer>,
    closed: Arc<tokio::sync::Notify>,
}

impl QuicStream {
    pub async fn connect(host: &str, port: u16, alpn: &[&str]) -> Result<Self, String> {
        let addr_str = format!("{host}:{port}");
        let remote_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {addr_str}: {e}"))?
            .next()
            .ok_or_else(|| format!("Could not resolve address {addr_str}"))?;

        let local_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        };

        let udp_socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| format!("Failed to bind local UDP socket: {e}"))?;

        let local_bound = udp_socket
            .local_addr()
            .map_err(|e| format!("Failed to get local addr: {e}"))?;

        let (tx_write, mut rx_write) = mpsc::channel::<Vec<u8>>(128);
        let (tx_read, rx_read) = mpsc::channel::<Vec<u8>>(128);
        let closed = Arc::new(tokio::sync::Notify::new());
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

        let server_name = host.to_string();
        let alpn_owned: Vec<String> = if alpn.is_empty() {
            vec!["h3".to_string(), "hq-interop".to_string()]
        } else {
            alpn.iter().map(|s| (*s).to_string()).collect()
        };

        let closed_clone = closed.clone();

        // Spawn dedicated thread for Neqo connection (Connection is !Send because it uses Rc/RefCell)
        std::thread::spawn(move || {
            let local_rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("Failed to build thread runtime: {e}")));
                    return;
                }
            };

            local_rt.block_on(async move {
                let cid_gen = Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8)));
                let alpn_refs: Vec<&str> = alpn_owned.iter().map(String::as_str).collect();

                let now = Instant::now();
                // 20s idle timeout enables Neqo's browser keepalive PING probe at 10s idle
                let params =
                    ConnectionParameters::default().idle_timeout(std::time::Duration::from_secs(20));

                let mut conn = match Connection::new_client(
                    &server_name,
                    &alpn_refs,
                    cid_gen,
                    local_bound,
                    remote_addr,
                    params,
                    now,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("Neqo new_client error: {e:?}")));
                        return;
                    }
                };

                let mut active_stream: Option<StreamId> = None;
                let mut ready_notifier = Some(ready_tx);
                let mut buf_in = [0u8; 65535];

                loop {
                    let now = Instant::now();

                    // 1. Process outgoing datagrams and capture scheduled timers
                    let mut next_timer = None;
                    loop {
                        match conn.process_output(now) {
                            Output::Datagram(dgram) => {
                                let _ = udp_socket.send_to(dgram.as_ref(), remote_addr).await;
                            }
                            Output::Callback(delay) => {
                                next_timer = Some(delay);
                                break;
                            }
                            Output::None => break,
                        }
                    }

                    // 2. Check connection events
                    while let Some(event) = conn.next_event() {
                        match event {
                            ConnectionEvent::AuthenticationNeeded => {
                                // Strict Mozilla CA root certificate verification
                                let cert_info = conn.peer_certificate();
                                let status =
                                    verify_peer_certificate(cert_info.as_ref(), &server_name);
                                conn.authenticated(status, now);
                            }
                            ConnectionEvent::RecvStreamReadable { stream_id } => {
                                if Some(stream_id) == active_stream {
                                    let mut temp = [0u8; 8192];
                                    while let Ok((read_bytes, fin)) =
                                        conn.stream_recv(stream_id, &mut temp)
                                    {
                                        if read_bytes == 0 {
                                            break;
                                        }
                                        if tx_read.send(temp[..read_bytes].to_vec()).await.is_err() {
                                            break;
                                        }
                                        if fin {
                                            break;
                                        }
                                    }
                                }
                            }
                            ConnectionEvent::RecvStreamReset { .. } => {
                                break;
                            }
                            _ => {}
                        }
                    }

                    // 3. Activate stream and register browser keepalive
                    if conn.state().connected() && active_stream.is_none() {
                        log::info!("[QUIC] Connected to {}", server_name);
                        match conn.stream_create(StreamType::BiDi) {
                            Ok(sid) => {
                                active_stream = Some(sid);
                                // Register stream for native Neqo idle keep-alive PING probes
                                if let Err(e) = conn.stream_keep_alive(sid, true) {
                                    log::warn!("[QUIC] Failed to enable stream keepalive: {e:?}");
                                }
                                if let Some(notifier) = ready_notifier.take() {
                                    let _ = notifier.send(Ok(()));
                                }
                            }
                            Err(e) => {
                                if let Some(notifier) = ready_notifier.take() {
                                    let _ = notifier.send(Err(format!(
                                        "Failed to create BiDi stream: {e:?}"
                                    )));
                                }
                            }
                        }
                    }

                    // Check termination conditions
                    match conn.state() {
                        State::Closed(err) => {
                            if let Some(notifier) = ready_notifier.take() {
                                let _ =
                                    notifier.send(Err(format!("QUIC connection closed: {err:?}")));
                            }
                            break;
                        }
                        State::Closing { .. } | State::Draining { .. } => {
                            if let Some(notifier) = ready_notifier.take() {
                                let _ = notifier.send(Err(
                                    "QUIC connection closed before handshake completed"
                                        .to_string(),
                                ));
                            }
                            break;
                        }
                        _ => {}
                    }

                    // 4. Drive asynchronous I/O and timers with adaptive sleep
                    let sleep_duration = next_timer
                        .unwrap_or(std::time::Duration::from_millis(20))
                        .min(std::time::Duration::from_millis(25));

                    tokio::select! {
                        recv_res = udp_socket.recv_from(&mut buf_in) => {
                            match recv_res {
                                Ok((len, from_addr)) => {
                                    let dgram = Datagram::new(from_addr, local_bound, Tos::from(0), &buf_in[..len]);
                                    conn.process_input(dgram, Instant::now());
                                }
                                Err(_) => break,
                            }
                        }
                        write_opt = rx_write.recv() => {
                            match write_opt {
                                Some(data) => {
                                    if let Some(sid) = active_stream {
                                        // MTU-friendly chunking to dirty packet sizes
                                        let chunks = chunk_payload(&data);
                                        for chunk in chunks {
                                            let _ = conn.stream_send(sid, chunk);
                                        }
                                    }
                                }
                                None => {
                                    if let Some(sid) = active_stream {
                                        let _ = conn.stream_close_send(sid);
                                    }
                                    break;
                                }
                            }
                        }
                        _ = closed_clone.notified() => {
                            conn.close(Instant::now(), 0, "kthxbye");
                            break;
                        }
                        _ = tokio::time::sleep(sleep_duration) => {
                            // Tick connection timer / send scheduled keepalive ping
                        }
                    }
                }

                closed_clone.notify_waiters();
            });
        });

        // Wait for handshake completion with deterministic timeout
        let handshake_timeout = std::time::Duration::from_secs(10);
        match tokio::time::timeout(handshake_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                tx_write,
                rx_read: Mutex::new(StreamReadBuffer::new(rx_read)),
                closed,
            }),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err("QUIC handshake worker terminated unexpectedly".to_string()),
            Err(_) => {
                closed.notify_waiters();
                Err(format!(
                    "QUIC connection to {host}:{port} timed out after {}s",
                    handshake_timeout.as_secs()
                ))
            }
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut rx = self.rx_read.lock().await;
        rx.read(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.tx_write
            .send(buf.to_vec())
            .await
            .map_err(|e| format!("Send error: {e}"))?;
        Ok(buf.len())
    }

    pub fn close(&self) {
        self.closed.notify_waiters();
    }
}
