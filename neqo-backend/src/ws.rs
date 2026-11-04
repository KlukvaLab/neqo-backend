//! WebSocket (RFC 6455) transport with Firefox-shaped behaviour.
//!
//! Runs over any [`WireTransport`] — either plaintext TCP (test mode) or
//! NSS-backed TLS (production; genuine Firefox TLS fingerprint).
//!
//! Firefox mimicry details:
//! * HTTP/1.1 upgrade request with Firefox header order (JA4H) and defaults.
//! * `Sec-WebSocket-Extensions: permessage-deflate` is always offered — real
//!   Firefox does this unconditionally, and a missing offer is a strong
//!   non-Firefox signal for DPI.
//! * First flight after the 101: a variable-length Ping frame (probing-noise).
//! * Periodic keep-alive Pings with jittered interval and payload.
//! * Polite Close frame on shutdown.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use rand::{Rng, RngCore};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

use crate::mimicry::{StreamReadBuffer, chunk_payload};

/// Current Firefox stable (2026-11). Keep in sync with the TLS stack era:
/// NSS 3.132 + neqo 0.34 ship in this Firefox generation.
pub const FIREFOX_DEFAULT_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0";

/// Hard cap on a single decompressed WS message (zip-bomb protection).
const MAX_MESSAGE_LEN: usize = 256 * 1024 * 1024;
/// Hard cap on a single frame payload from the server.
const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;
/// Hard cap on the HTTP 101 response head.
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

// =========================================================================
// Wire transport abstraction
// =========================================================================

/// Byte-stream transport under the WebSocket framing.
/// Implemented by plaintext TCP (tests) and NSS TLS (production).
#[async_trait::async_trait]
pub trait WireTransport: Send + Sync {
    /// Reads up to `buf.len()` bytes. Returns Ok(0) on EOF.
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String>;
    async fn write_all(&self, buf: &[u8]) -> Result<(), String>;
    /// Politely tears the transport down; safe to call multiple times.
    fn shutdown(&self);
}

/// Plaintext TCP transport (for local tests and debugging only).
pub struct TcpTransport {
    reader: Mutex<tokio::net::tcp::OwnedReadHalf>,
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl TcpTransport {
    pub async fn connect(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{host}:{port}");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Failed to connect to {addr}: {e}"))?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }
}

/// Sends one masked client frame over the transport.
async fn send_ws_frame(
    t: &dyn WireTransport,
    payload: &[u8],
    opcode: u8,
    rsv1: bool,
) -> Result<(), String> {
    let frame = encode_client_ws_frame(payload, opcode, rsv1);
    t.write_all(&frame).await
}

#[async_trait::async_trait]
impl WireTransport for TcpTransport {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut r = self.reader.lock().await;
        r.read(buf).await.map_err(|e| e.to_string())
    }

    async fn write_all(&self, buf: &[u8]) -> Result<(), String> {
        let mut w = self.writer.lock().await;
        w.write_all(buf).await.map_err(|e| e.to_string())
    }

    fn shutdown(&self) {
        // Halves are closed on drop.
    }
}

// =========================================================================
// Firefox-shaped handshake
// =========================================================================

/// Headers managed exclusively by this module. User-supplied entries with
/// these names are ignored to prevent duplicate-header fingerprint damage.
const MANAGED_HEADERS: [&str; 11] = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-websocket-version",
    "origin",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "connection",
    "upgrade",
];

/// Builds the HTTP/1.1 WebSocket upgrade request adhering strictly to
/// Firefox's header order (JA4H).
#[must_use]
pub fn build_firefox_ws_handshake(
    host: &str,
    port: u16,
    path: &str,
    sec_key: &str,
    extra_headers: &HashMap<String, String>,
    probing_marker: Option<&str>,
) -> String {
    let mut req = String::with_capacity(1024);
    let path = if path.is_empty() { "/" } else { path };

    // Request line
    req.push_str("GET ");
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\n");

    // 1. Host (IPv6 literals need brackets)
    let host_hdr = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 80 || port == 443 {
        req.push_str(&format!("Host: {host_hdr}\r\n"));
    } else {
        req.push_str(&format!("Host: {host_hdr}:{port}\r\n"));
    }

    // 2. User-Agent
    let ua = extra_headers
        .get("User-Agent")
        .map(|s| s.as_str())
        .unwrap_or(FIREFOX_DEFAULT_UA);
    req.push_str(&format!("User-Agent: {ua}\r\n"));

    // 3. Accept (Firefox defaults)
    req.push_str("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");

    // 4. Accept-Language
    let lang = extra_headers
        .get("Accept-Language")
        .map(|s| s.as_str())
        .unwrap_or("en-US,en;q=0.5");
    req.push_str(&format!("Accept-Language: {lang}\r\n"));

    // 5. Accept-Encoding
    req.push_str("Accept-Encoding: gzip, deflate, br, zstd\r\n");

    // 6. Sec-WebSocket-Version
    req.push_str("Sec-WebSocket-Version: 13\r\n");

    // 7. Origin
    let origin = extra_headers
        .get("Origin")
        .cloned()
        .unwrap_or_else(|| format!("https://{host}"));
    req.push_str(&format!("Origin: {origin}\r\n"));

    // 8. Sec-WebSocket-Extensions — Firefox offers permessage-deflate always.
    req.push_str("Sec-WebSocket-Extensions: permessage-deflate\r\n");

    // 9. Sec-WebSocket-Key
    req.push_str(&format!("Sec-WebSocket-Key: {sec_key}\r\n"));

    // 10. Optional active-probing marker (first-flight auth). NOTE: this is a
    // deliberate deviation from a stock Firefox handshake.
    if let Some(marker) = probing_marker {
        req.push_str(&format!("X-Probe-Auth: {marker}\r\n"));
    }

    // Custom headers (managed ones are filtered out to avoid duplicates)
    for (k, v) in extra_headers {
        if !MANAGED_HEADERS.contains(&k.to_lowercase().as_str()) {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }

    // 11/12. Connection & Upgrade
    req.push_str("Connection: keep-alive, Upgrade\r\n");
    req.push_str("Upgrade: websocket\r\n\r\n");

    req
}

/// Expected value of `Sec-WebSocket-Accept` for a given key (RFC 6455 §1.3).
#[must_use]
pub fn expected_ws_accept(sec_key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(sec_key.as_bytes());
    hasher.update(GUID.as_bytes());
    BASE64.encode(hasher.finalize())
}

// =========================================================================
// RFC 6455 framing
// =========================================================================

/// Encodes an RFC 6455 client frame (always masked, RFC 6455 §5.3).
/// `rsv1` marks the first frame of a permessage-deflate compressed message.
#[must_use]
pub fn encode_client_ws_frame(payload: &[u8], opcode: u8, rsv1: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    let rsv = if rsv1 { 0x40 } else { 0x00 };
    frame.push(0x80 | rsv | (opcode & 0x0F)); // FIN + RSV1? + opcode

    let len = payload.len();
    if len <= 125 {
        frame.push(0x80 | (len as u8)); // MASK bit + len
    } else if len <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }

    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    frame.extend_from_slice(&mask);

    let masked_start = frame.len();
    frame.extend_from_slice(payload);
    for i in 0..payload.len() {
        frame[masked_start + i] ^= mask[i % 4];
    }

    frame
}

/// A parsed server frame.
pub struct ServerFrame {
    pub consumed: usize,
    pub payload: Vec<u8>,
    pub opcode: u8,
    pub fin: bool,
    pub rsv1: bool,
}

/// Attempts to decode one frame from `buffer`. Returns `None` if more bytes
/// are needed, or `Err` on protocol violations (oversized frame, reserved
/// bits set on control frames, etc.).
pub fn parse_server_ws_frame(buffer: &[u8]) -> Option<Result<ServerFrame, String>> {
    if buffer.len() < 2 {
        return None;
    }

    let b0 = buffer[0];
    let fin = (b0 & 0x80) != 0;
    let rsv1 = (b0 & 0x40) != 0;
    let rsv2 = (b0 & 0x20) != 0;
    let rsv3 = (b0 & 0x10) != 0;
    let opcode = b0 & 0x0F;
    let b1 = buffer[1];
    let is_masked = (b1 & 0x80) != 0;
    let mut payload_len = (b1 & 0x7F) as usize;
    let mut header_len = 2;

    if payload_len == 126 {
        if buffer.len() < 4 {
            return None;
        }
        payload_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        header_len = 4;
    } else if payload_len == 127 {
        if buffer.len() < 10 {
            return None;
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&buffer[2..10]);
        payload_len = u64::from_be_bytes(len_bytes) as usize;
        header_len = 10;
    }

    if payload_len > MAX_FRAME_PAYLOAD {
        return Some(Err(format!("Frame payload too large: {payload_len} bytes")));
    }

    // RFC 6455 §5.2: reserved bits must be zero unless negotiated, and
    // control frames must never be fragmented or compressed.
    if opcode >= 0x08 && (rsv1 || rsv2 || rsv3 || !fin) {
        return Some(Err(
            "Invalid reserved bits / fragmentation on control frame".into(),
        ));
    }
    if (rsv2 || rsv3) && opcode < 0x08 {
        return Some(Err("Unsupported RSV2/RSV3 on data frame".into()));
    }

    let mask_len = if is_masked { 4 } else { 0 };
    let total_len = header_len + mask_len + payload_len;
    if buffer.len() < total_len {
        return None;
    }

    let mask_bytes = if is_masked {
        Some(&buffer[header_len..header_len + 4])
    } else {
        None
    };

    let payload_start = header_len + mask_len;
    let mut payload = buffer[payload_start..payload_start + payload_len].to_vec();

    if let Some(mask) = mask_bytes {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }

    Some(Ok(ServerFrame {
        consumed: total_len,
        payload,
        opcode,
        fin,
        rsv1,
    }))
}

// =========================================================================
// permessage-deflate (RFC 7692)
// =========================================================================

/// Negotiated PMCE parameters we understand.
#[derive(Debug, Clone, Copy)]
pub struct PmceConfig {
    /// May we reuse our compression context across messages?
    pub client_context_takeover: bool,
    /// Does the server reuse its compression context?
    pub server_context_takeover: bool,
}

impl PmceConfig {
    /// Parses the server's `Sec-WebSocket-Extensions` header value.
    /// Returns `None` if PMCE was not negotiated, or `Err` on parameters we
    /// cannot honour (fail-fast beats silently corrupting the stream).
    pub fn negotiate(header_value: &str) -> Result<Option<Self>, String> {
        let mut saw_pmce = false;
        let mut cfg = Self {
            client_context_takeover: true,
            server_context_takeover: true,
        };

        for ext in header_value.split(',') {
            let mut parts = ext.split(';').map(str::trim);
            let Some(name) = parts.next() else { continue };
            if name.eq_ignore_ascii_case("permessage-deflate") {
                saw_pmce = true;
                for param in parts {
                    let p = param.trim();
                    match p {
                        "server_no_context_takeover" => cfg.server_context_takeover = false,
                        "client_no_context_takeover" => cfg.client_context_takeover = false,
                        _ => {
                            if let Some((k, v)) = p.split_once('=') {
                                let bits: u32 = v.trim().parse().map_err(|_| {
                                    format!("Bad permessage-deflate parameter: {p}")
                                })?;
                                match k.trim() {
                                    // Informational: inflate handles any window ≤ 15.
                                    "server_max_window_bits" if (8..=15).contains(&bits) => {}
                                    // Our compressor (flate2) cannot shrink its window.
                                    "client_max_window_bits" if bits == 15 => {}
                                    _ => {
                                        return Err(format!(
                                            "Unsupported permessage-deflate parameter: {p} \
                                             (client_max_window_bits < 15 is not supported)"
                                        ));
                                    }
                                }
                            } else {
                                return Err(format!(
                                    "Unsupported permessage-deflate parameter: {p}"
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(if saw_pmce { Some(cfg) } else { None })
    }
}

/// Outgoing-message compressor (raw DEFLATE + RFC 7692 framing).
pub struct PmceCompressor {
    compress: Compress,
    takeover: bool,
}

impl PmceCompressor {
    #[must_use]
    pub fn new(cfg: PmceConfig) -> Self {
        Self {
            compress: Compress::new(Compression::new(6), false),
            takeover: cfg.client_context_takeover,
        }
    }

    /// Compresses one message. The trailing empty DEFLATE block produced by
    /// the sync flush is stripped per RFC 7692 §7.2.1.
    ///
    /// NOTE on the loop: miniz_oxide reports "all input consumed" even when
    /// the sync flush was interrupted by a full output buffer, so completion
    /// is detected by the presence of the `00 00 FF FF` marker, not by input
    /// exhaustion. The initial capacity covers the worst case
    /// (incompressible input + stored-block overhead) so one call normally
    /// suffices; the loop is a safety net.
    pub fn compress_message(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        const MARKER: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
        if !self.takeover {
            self.compress.reset();
        }
        let mut out = Vec::with_capacity(data.len() + 128);
        let mut input = data;
        for _ in 0..4096 {
            let before_in = self.compress.total_in();
            let before_out = out.len();
            self.compress
                .compress_vec(input, &mut out, FlushCompress::Sync)
                .map_err(|e| format!("deflate error: {e}"))?;
            let consumed = (self.compress.total_in() - before_in) as usize;
            let produced = out.len() - before_out;
            input = &input[consumed..];

            if out.ends_with(&MARKER) && input.is_empty() {
                // Sync flush complete: strip the empty stored block.
                out.truncate(out.len() - 4);
                return Ok(out);
            }
            if input.is_empty() && consumed == 0 && produced == 0 {
                return Err("deflate stalled without sync marker".to_string());
            }
            // Flush was interrupted by a full output buffer: make room and
            // continue (next call finishes the interrupted marker).
            if out.len() == out.capacity() {
                out.reserve(16 * 1024);
            }
        }
        Err("deflate did not complete".to_string())
    }
}

/// Incoming-message decompressor.
pub struct PmceDecompressor {
    decompress: Decompress,
    takeover: bool,
}

impl PmceDecompressor {
    #[must_use]
    pub fn new(cfg: PmceConfig) -> Self {
        Self {
            decompress: Decompress::new(false),
            takeover: cfg.server_context_takeover,
        }
    }

    /// Decompresses one complete message (with the RFC 7692 tail appended).
    ///
    /// NOTE on the loop: miniz_oxide may report "all input consumed" while
    /// decompressed output is still pending in its internal window because
    /// the output buffer was full. Completion is therefore detected by
    /// "no progress" (nothing consumed AND nothing produced), not by input
    /// exhaustion.
    pub fn decompress_message(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.takeover {
            self.decompress.reset(false);
        }
        // Append the empty-block tail that the sender stripped.
        let mut input = data.to_vec();
        input.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);

        let mut out = Vec::with_capacity(data.len().saturating_mul(2) + 256);
        let mut pos = 0usize;
        for _ in 0..65536 {
            if out.len() == out.capacity() {
                if out.len() > MAX_MESSAGE_LEN {
                    return Err("Decompressed message exceeds limit".into());
                }
                out.reserve(16 * 1024);
            }
            let before_in = self.decompress.total_in();
            let before_out = out.len();
            self.decompress
                .decompress_vec(&input[pos..], &mut out, FlushDecompress::None)
                .map_err(|e| format!("inflate error: {e}"))?;
            let consumed = (self.decompress.total_in() - before_in) as usize;
            let produced = out.len() - before_out;
            pos += consumed;

            if consumed == 0 && produced == 0 {
                if pos < input.len() {
                    return Err("inflate stalled".to_string());
                }
                return Ok(out); // drained: message complete
            }
            if out.len() > MAX_MESSAGE_LEN {
                return Err("Decompressed message exceeds limit".into());
            }
        }
        Err("inflate did not complete".to_string())
    }
}

// =========================================================================
// WebSocket stream
// =========================================================================

#[derive(Debug)]
pub enum WsWriteMsg {
    Data(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

pub struct WebSocketStream {
    tx_write: mpsc::Sender<WsWriteMsg>,
    rx_read: Mutex<StreamReadBuffer>,
    closed: Arc<tokio::sync::Notify>,
}

impl WebSocketStream {
    /// Performs the WebSocket handshake over `transport` and returns a stream.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        transport: Arc<dyn WireTransport>,
        host: &str,
        port: u16,
        path: &str,
        headers: HashMap<String, String>,
        probing_marker: Option<&str>,
    ) -> Result<Self, String> {
        // Generate Sec-WebSocket-Key
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let sec_key = BASE64.encode(key_bytes);

        // Build Firefox-shaped handshake
        let request =
            build_firefox_ws_handshake(host, port, path, &sec_key, &headers, probing_marker);
        transport.write_all(request.as_bytes()).await?;

        // Read the full response head (until CRLFCRLF), preserving any bytes
        // that arrive together with the tail as frame data (no data loss).
        let mut head = Vec::with_capacity(2048);
        let head_end;
        loop {
            let mut chunk = [0u8; 4096];
            let n = transport.read(&mut chunk).await?;
            if n == 0 {
                return Err("Connection closed during WebSocket handshake".to_string());
            }
            head.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&head, b"\r\n\r\n") {
                head_end = pos + 4;
                break;
            }
            if head.len() > MAX_HANDSHAKE_RESPONSE {
                return Err("WebSocket handshake response too large".to_string());
            }
        }
        let leftover = head[head_end..].to_vec();
        let head_str = String::from_utf8_lossy(&head[..head_end]).to_string();
        let mut lines = head_str.split("\r\n");

        // Status line
        let status = lines.next().unwrap_or_default();
        if !(status.starts_with("HTTP/1.1 101") || status.starts_with("HTTP/1.0 101")) {
            return Err(format!("Server rejected WebSocket upgrade: {status}"));
        }

        // Headers (lowercased name -> value)
        let mut resp_headers: HashMap<String, String> = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                resp_headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Validate Sec-WebSocket-Accept (RFC 6455 §4.2.2 — mandatory).
        match resp_headers.get("sec-websocket-accept") {
            Some(accept) if *accept == expected_ws_accept(&sec_key) => {}
            Some(accept) => {
                return Err(format!(
                    "Sec-WebSocket-Accept mismatch: server sent {accept:?}"
                ));
            }
            None => {
                return Err("Missing Sec-WebSocket-Accept in 101 response".to_string());
            }
        }

        // Negotiate permessage-deflate if the server accepted our offer.
        let pmce = match resp_headers.get("sec-websocket-extensions") {
            Some(extensions) => PmceConfig::negotiate(extensions)?,
            None => None,
        };

        let (tx_write, mut rx_write) = mpsc::channel::<WsWriteMsg>(128);
        let (tx_read, rx_read) = mpsc::channel::<Vec<u8>>(128);
        let closed = Arc::new(tokio::sync::Notify::new());

        // 1. First-flight noise: an authentic Ping with a variable-length
        // random payload right after the upgrade — breaks DPI heuristics that
        // expect a fixed-size first packet from proxy clients.
        let initial_ping_len = rand::thread_rng().gen_range(16..=48);
        let mut initial_noise = vec![0u8; initial_ping_len];
        rand::thread_rng().fill_bytes(&mut initial_noise);
        let initial_ping_frame = encode_client_ws_frame(&initial_noise, 0x09, false);
        transport.write_all(&initial_ping_frame).await?;

        // 2. Writer task: serialises all client→server frames, applies PMCE,
        //    sends the browser-like keep-alive Ping and the Close frame.
        let closed_w = closed.clone();
        let writer_transport = transport.clone();
        tokio::spawn(async move {
            let mut compressor = pmce.map(PmceCompressor::new);
            let keepalive_dur =
                std::time::Duration::from_secs(rand::thread_rng().gen_range(15..=25));
            let mut keepalive_interval = tokio::time::interval(keepalive_dur);
            keepalive_interval.tick().await; // consume immediate first tick

            loop {
                tokio::select! {
                    msg_opt = rx_write.recv() => {
                        match msg_opt {
                            Some(WsWriteMsg::Data(data)) => {
                                keepalive_interval.reset();
                                let chunks = chunk_payload(&data);
                                let mut abort = false;
                                for chunk in chunks {
                                    let result = match &mut compressor {
                                        Some(c) => c.compress_message(chunk),
                                        None => Ok(chunk.to_vec()),
                                    };
                                    match result {
                                        Ok(bytes) => {
                                            let rsv1 = compressor.is_some();
                                            if send_ws_frame(writer_transport.as_ref(), &bytes, 0x02, rsv1).await.is_err() {
                                                abort = true;
                                                break;
                                            }
                                        }
                                        Err(_) => {
                                            abort = true;
                                            break;
                                        }
                                    }
                                }
                                if abort {
                                    break;
                                }
                            }
                            Some(WsWriteMsg::Pong(payload)) => {
                                if send_ws_frame(writer_transport.as_ref(), &payload, 0x0A, false).await.is_err() {
                                    break;
                                }
                            }
                            Some(WsWriteMsg::Close) | None => break,
                        }
                    }
                    _ = keepalive_interval.tick() => {
                        // Keep-alive Ping with random payload (8..32 bytes).
                        let ping_len = rand::thread_rng().gen_range(8..=32);
                        let mut ping_noise = vec![0u8; ping_len];
                        rand::thread_rng().fill_bytes(&mut ping_noise);
                        if send_ws_frame(writer_transport.as_ref(), &ping_noise, 0x09, false).await.is_err() {
                            break;
                        }
                    }
                    _ = closed_w.notified() => break,
                }
            }
            // Polite Close frame (opcode 0x08, status 1000), then transport down.
            let close_payload = [0x03, 0xE8];
            let _ = send_ws_frame(writer_transport.as_ref(), &close_payload, 0x08, false).await;
            writer_transport.shutdown();
            closed_w.notify_waiters();
        });

        // 3. Reader task: frame reassembly, PMCE decompression, Ping/Pong,
        //    Close handling. Started with the handshake leftover bytes.
        let tx_write_pong = tx_write.clone();
        let closed_r = closed.clone();
        let reader_transport = transport;
        tokio::spawn(async move {
            let mut decompressor = pmce.map(PmceDecompressor::new);
            let mut read_buf = leftover;
            let mut pending_message = Vec::new();
            let mut pending_compressed = false;
            let mut temp = [0u8; 4096];
            loop {
                // Parse as many complete frames as the buffer allows.
                let mut fatal = false;
                while let Some(frame_res) = parse_server_ws_frame(&read_buf) {
                    match frame_res {
                        Ok(frame) => {
                            read_buf.drain(..frame.consumed);
                            match frame.opcode {
                                0x01 | 0x02 => {
                                    if frame.fin && pending_message.is_empty() {
                                        // Single-frame fast path.
                                        let out = finish_message(
                                            frame.payload,
                                            frame.rsv1,
                                            &mut decompressor,
                                        );
                                        match out {
                                            Ok(msg) => {
                                                if tx_read.send(msg).await.is_err() {
                                                    fatal = true;
                                                    break;
                                                }
                                            }
                                            Err(_) => {
                                                fatal = true;
                                                break;
                                            }
                                        }
                                    } else {
                                        pending_compressed = frame.rsv1;
                                        pending_message = frame.payload;
                                    }
                                }
                                0x00 => {
                                    pending_message.extend_from_slice(&frame.payload);
                                    if frame.fin {
                                        let out = finish_message(
                                            std::mem::take(&mut pending_message),
                                            pending_compressed,
                                            &mut decompressor,
                                        );
                                        match out {
                                            Ok(msg) => {
                                                if tx_read.send(msg).await.is_err() {
                                                    fatal = true;
                                                    break;
                                                }
                                            }
                                            Err(_) => {
                                                fatal = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                0x08 => {
                                    // Server Close → reply in kind, then exit.
                                    let _ = tx_write_pong.send(WsWriteMsg::Close).await;
                                    fatal = true;
                                    break;
                                }
                                0x09 => {
                                    // Ping → Pong with the same payload.
                                    let _ =
                                        tx_write_pong.send(WsWriteMsg::Pong(frame.payload)).await;
                                }
                                0x0A => { /* Pong: absorb */ }
                                _ => { /* Unknown opcode: ignore (be liberal) */ }
                            }
                        }
                        Err(e) => {
                            log::warn!("[WS] Protocol error from server: {e}");
                            fatal = true;
                            break;
                        }
                    }
                }
                if fatal {
                    break;
                }

                match reader_transport.read(&mut temp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => read_buf.extend_from_slice(&temp[..n]),
                }
            }
            closed_r.notify_waiters();
        });

        Ok(Self {
            tx_write,
            rx_read: Mutex::new(StreamReadBuffer::new(rx_read)),
            closed,
        })
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut rx = self.rx_read.lock().await;
        rx.read(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.tx_write
            .send(WsWriteMsg::Data(buf.to_vec()))
            .await
            .map_err(|e| format!("Send error: {e}"))?;
        Ok(buf.len())
    }

    pub fn close(&self) {
        self.closed.notify_waiters();
    }
}

/// Applies PMCE decompression to a fully assembled message if needed.
fn finish_message(
    payload: Vec<u8>,
    compressed: bool,
    decompressor: &mut Option<PmceDecompressor>,
) -> Result<Vec<u8>, String> {
    match (compressed, decompressor) {
        (true, Some(d)) => d.decompress_message(&payload),
        (true, None) => Err("Server sent compressed frame without negotiating PMCE".into()),
        (false, _) => {
            if payload.len() > MAX_MESSAGE_LEN {
                return Err("Message too large".into());
            }
            Ok(payload)
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_parse_ping_pong() {
        let ping_payload = b"test-probe-ping-data";
        let frame = encode_client_ws_frame(ping_payload, 0x09, false);
        assert_eq!(frame[0], 0x89); // FIN + opcode 9, no RSV1

        let parsed = parse_server_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(parsed.consumed, frame.len());
        assert_eq!(parsed.opcode, 0x09);
        assert!(parsed.fin);
        assert!(!parsed.rsv1);
        assert_eq!(parsed.payload, ping_payload);
    }

    #[test]
    fn test_encode_and_parse_binary_frame_with_rsv1() {
        let data = vec![0x33; 300];
        let frame = encode_client_ws_frame(&data, 0x02, true);
        assert_eq!(frame[0], 0xC2); // FIN + RSV1 + opcode 2

        let parsed = parse_server_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(parsed.consumed, frame.len());
        assert_eq!(parsed.opcode, 0x02);
        assert!(parsed.rsv1);
        assert_eq!(parsed.payload, data);
    }

    #[test]
    fn test_reject_oversized_frame() {
        let mut buf = vec![0x82, 127];
        buf.extend_from_slice(&(u64::MAX).to_be_bytes());
        let res = parse_server_ws_frame(&buf).unwrap();
        assert!(res.is_err());
    }

    #[test]
    fn test_reject_control_frame_with_rsv() {
        let frame = encode_client_ws_frame(b"x", 0x09, true);
        let res = parse_server_ws_frame(&frame).unwrap();
        assert!(res.is_err(), "control frames must not be compressed");
    }

    #[test]
    fn test_ws_handshake_order() {
        let mut extra = HashMap::new();
        extra.insert("X-Custom".to_string(), "CustomVal".to_string());
        extra.insert("Accept".to_string(), "DUPLICATE-ACCEPT".to_string());
        let req = build_firefox_ws_handshake(
            "example.com",
            443,
            "/ws",
            "dGhlIHNhbXBsZSBub25jZQ==",
            &extra,
            Some("auth123"),
        );

        let lines: Vec<&str> = req.lines().collect();
        assert_eq!(lines[0], "GET /ws HTTP/1.1");
        assert_eq!(lines[1], "Host: example.com");
        assert!(lines[2].starts_with("User-Agent: Mozilla/5.0"));
        assert_eq!(
            lines[3],
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        );
        assert!(lines[4].starts_with("Accept-Language:"));
        assert_eq!(lines[5], "Accept-Encoding: gzip, deflate, br, zstd");
        assert_eq!(lines[6], "Sec-WebSocket-Version: 13");
        assert_eq!(lines[7], "Origin: https://example.com");
        assert_eq!(lines[8], "Sec-WebSocket-Extensions: permessage-deflate");
        assert_eq!(lines[9], "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(lines[10], "X-Probe-Auth: auth123");
        assert_eq!(lines[11], "X-Custom: CustomVal");
        assert_eq!(lines[12], "Connection: keep-alive, Upgrade");
        assert_eq!(lines[13], "Upgrade: websocket");
        // No duplicate Accept leaked from the caller's header map.
        assert!(!req.contains("DUPLICATE-ACCEPT"));
    }

    #[test]
    fn test_ipv6_host_gets_brackets() {
        let req = build_firefox_ws_handshake("::1", 8080, "/", "k", &HashMap::new(), None);
        assert!(req.contains("Host: [::1]:8080\r\n"));
    }

    #[test]
    fn test_expected_ws_accept_rfc_vector() {
        // RFC 6455 §1.3 example vector.
        assert_eq!(
            expected_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn test_pmce_negotiation() {
        assert!(
            PmceConfig::negotiate("permessage-deflate")
                .unwrap()
                .is_some()
        );
        assert!(
            PmceConfig::negotiate("permessage-deflate; server_no_context_takeover")
                .unwrap()
                .unwrap()
                .server_context_takeover
                == false
        );
        // Not negotiated:
        assert!(
            PmceConfig::negotiate("x-webkit-deflate-frame")
                .unwrap()
                .is_none()
        );
        // Unsupported client window:
        assert!(PmceConfig::negotiate("permessage-deflate; client_max_window_bits=10").is_err());
        // Supported client window:
        assert!(PmceConfig::negotiate("permessage-deflate; client_max_window_bits=15").is_ok());
    }

    #[test]
    fn test_pmce_roundtrip_with_context_takeover() {
        let cfg = PmceConfig {
            client_context_takeover: true,
            server_context_takeover: true,
        };
        let mut comp = PmceCompressor::new(cfg);
        let mut dec = PmceDecompressor::new(cfg);

        let messages: Vec<Vec<u8>> = vec![
            b"hello hello hello hello hello".to_vec(),
            b"hello hello hello hello hello".to_vec(),
            vec![0xAB; 4096],
            Vec::new(),
            b"final".to_vec(),
        ];
        for msg in &messages {
            let compressed = comp.compress_message(msg).unwrap();
            let decompressed = dec.decompress_message(&compressed).unwrap();
            assert_eq!(&decompressed, msg);
        }
    }

    #[test]
    fn test_pmce_roundtrip_no_context_takeover() {
        let cfg = PmceConfig {
            client_context_takeover: false,
            server_context_takeover: false,
        };
        let mut comp = PmceCompressor::new(cfg);
        let mut dec = PmceDecompressor::new(cfg);

        for msg in [
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
            b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".as_slice(),
        ] {
            let compressed = comp.compress_message(msg).unwrap();
            let decompressed = dec.decompress_message(&compressed).unwrap();
            assert_eq!(decompressed, msg);
        }
    }

    #[test]
    fn test_pmce_fuzz_roundtrip() {
        // Deterministic pseudo-random corpus: sizes from 0 to ~100 KB,
        // compressible and incompressible patterns, both takeover modes.
        let mut seed = 0x1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for takeover in [true, false] {
            let cfg = PmceConfig {
                client_context_takeover: takeover,
                server_context_takeover: takeover,
            };
            let mut comp = PmceCompressor::new(cfg);
            let mut dec = PmceDecompressor::new(cfg);
            for case in 0..64 {
                let len = (next() % 100_000) as usize;
                let msg: Vec<u8> = match case % 3 {
                    0 => (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect(),
                    1 => vec![(next() % 256) as u8; len],
                    _ => (0..len).map(|_| (next() % 256) as u8).collect(),
                };
                let compressed = comp.compress_message(&msg).unwrap();
                let decompressed = dec.decompress_message(&compressed).unwrap();
                assert_eq!(
                    decompressed, msg,
                    "case {case} (len {len}, takeover {takeover})"
                );
            }
        }
    }
}
