use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

pub const FIREFOX_DEFAULT_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0";

/// Builds the HTTP/1.1 WebSocket upgrade request adhering strictly to Firefox's header order (JA4H).
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
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));

    // Firefox JA4H order:
    // 1. Host
    if port == 80 || port == 443 {
        req.push_str(&format!("Host: {host}\r\n"));
    } else {
        req.push_str(&format!("Host: {host}:{port}\r\n"));
    }

    // 2. User-Agent
    let ua = extra_headers
        .get("User-Agent")
        .map(|s| s.as_str())
        .unwrap_or(FIREFOX_DEFAULT_UA);
    req.push_str(&format!("User-Agent: {ua}\r\n"));

    // 3. Accept
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

    // 8. Sec-WebSocket-Key
    req.push_str(&format!("Sec-WebSocket-Key: {sec_key}\r\n"));

    // 9. Active probing marker (first flight auth) if specified
    if let Some(marker) = probing_marker {
        req.push_str(&format!("X-Probe-Auth: {marker}\r\n"));
    }

    // Custom additional headers
    for (k, v) in extra_headers {
        if !["user-agent", "accept-language", "origin", "host"].contains(&k.to_lowercase().as_str())
        {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }

    // 10. Connection & Upgrade
    req.push_str("Connection: keep-alive, Upgrade\r\n");
    req.push_str("Upgrade: websocket\r\n\r\n");

    req
}

/// Encodes an RFC 6455 client frame (always masked).
pub fn encode_client_ws_frame(payload: &[u8], is_binary: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    let opcode = if is_binary { 0x02 } else { 0x01 };
    frame.push(0x80 | opcode); // FIN + opcode

    let len = payload.len();
    if len <= 125 {
        frame.push(0x80 | (len as u8)); // MASK bit + length
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

/// Decodes frames from incoming server stream.
pub fn parse_server_ws_frame(buffer: &[u8]) -> Option<(usize, Vec<u8>, u8)> {
    if buffer.len() < 2 {
        return None;
    }

    let b0 = buffer[0];
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

    Some((total_len, payload, opcode))
}

pub struct WebSocketStream {
    tx_write: mpsc::Sender<Vec<u8>>,
    rx_read: Mutex<mpsc::Receiver<Vec<u8>>>,
    closed: Arc<tokio::sync::Notify>,
}

impl WebSocketStream {
    pub async fn connect(
        host: &str,
        port: u16,
        path: &str,
        headers: HashMap<String, String>,
        probing_marker: Option<&str>,
    ) -> Result<Self, String> {
        let addr = format!("{host}:{port}");
        let mut tcp_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Failed to connect to {addr}: {e}"))?;

        // Generate Sec-WebSocket-Key
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let sec_key = BASE64.encode(key_bytes);

        // Build Firefox-shaped handshake
        let request =
            build_firefox_ws_handshake(host, port, path, &sec_key, &headers, probing_marker);
        tcp_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send handshake: {e}"))?;

        // Read handshake response
        let mut resp_buf = vec![0u8; 4096];
        let n = tcp_stream
            .read(&mut resp_buf)
            .await
            .map_err(|e| format!("Failed to read handshake response: {e}"))?;
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

        if !resp_str.starts_with("HTTP/1.1 101") && !resp_str.starts_with("HTTP/1.0 101") {
            return Err(format!(
                "Server rejected WebSocket upgrade: {}",
                resp_str.lines().next().unwrap_or("")
            ));
        }

        let (tx_write, mut rx_write) = mpsc::channel::<Vec<u8>>(128);
        let (tx_read, rx_read) = mpsc::channel::<Vec<u8>>(128);
        let closed = Arc::new(tokio::sync::Notify::new());
        let (mut reader, mut writer) = tcp_stream.into_split();

        // Writer task
        let closed_w = closed.clone();
        tokio::spawn(async move {
            while let Some(data) = rx_write.recv().await {
                let frame = encode_client_ws_frame(&data, true);
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
            closed_w.notify_waiters();
        });

        // Reader task
        let closed_r = closed.clone();
        tokio::spawn(async move {
            let mut read_buf = Vec::with_capacity(8192);
            let mut temp = [0u8; 4096];
            loop {
                tokio::select! {
                    res = reader.read(&mut temp) => {
                        match res {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                read_buf.extend_from_slice(&temp[..n]);
                                while let Some((consumed, payload, opcode)) = parse_server_ws_frame(&read_buf) {
                                    read_buf.drain(..consumed);
                                    if (opcode == 0x01 || opcode == 0x02)
                                        && tx_read.send(payload).await.is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = closed_r.notified() => break,
                }
            }
            closed_r.notify_waiters();
        });

        Ok(Self {
            tx_write,
            rx_read: Mutex::new(rx_read),
            closed,
        })
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut rx = self.rx_read.lock().await;
        match rx.recv().await {
            Some(data) => {
                let to_copy = std::cmp::min(buf.len(), data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                Ok(to_copy)
            }
            None => Ok(0), // EOF
        }
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
