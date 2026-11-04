use rand::Rng;
use tokio::sync::mpsc;

/// Helper to break down payloads into MTU-friendly randomized chunk slices.
///
/// This prevents static packet size signatures (e.g. constant 40-70 byte proxy handshakes,
/// or uniform 4096-byte chunk boundaries) from being fingerprinted by DPI/ТСПУ heuristics.
#[must_use]
pub fn chunk_payload(payload: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let remaining = payload.len() - offset;
        if remaining <= 1400 {
            chunks.push(&payload[offset..]);
            break;
        }
        // Dirty the packet sizes between 768 and 1360 bytes
        let chunk_size = rand::thread_rng().gen_range(768..=1360).min(remaining);
        chunks.push(&payload[offset..offset + chunk_size]);
        offset += chunk_size;
    }
    chunks
}

/// A stream read buffer that preserves unread leftover bytes across calls.
///
/// If an incoming packet or frame is larger than the caller's read buffer,
/// the unread portion is buffered rather than dropped, guaranteeing zero data loss.
pub struct StreamReadBuffer {
    rx: mpsc::Receiver<Vec<u8>>,
    leftover: Vec<u8>,
    leftover_offset: usize,
}

impl StreamReadBuffer {
    #[must_use]
    pub fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            leftover: Vec::new(),
            leftover_offset: 0,
        }
    }

    /// Reads up to `buf.len()` bytes into `buf`.
    /// Returns the number of bytes read, or 0 on EOF / channel closed.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.is_empty() {
            return Ok(0);
        }

        // 1. Drain leftover if present
        if self.leftover_offset < self.leftover.len() {
            let available = self.leftover.len() - self.leftover_offset;
            let to_copy = std::cmp::min(buf.len(), available);
            buf[..to_copy].copy_from_slice(
                &self.leftover[self.leftover_offset..self.leftover_offset + to_copy],
            );
            self.leftover_offset += to_copy;
            if self.leftover_offset == self.leftover.len() {
                self.leftover.clear();
                self.leftover_offset = 0;
            }
            return Ok(to_copy);
        }

        // 2. Await next incoming chunk from channel
        match self.rx.recv().await {
            Some(data) => {
                if data.is_empty() {
                    return Ok(0);
                }
                let to_copy = std::cmp::min(buf.len(), data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.leftover = data;
                    self.leftover_offset = to_copy;
                }
                Ok(to_copy)
            }
            None => Ok(0), // Channel closed / EOF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_payload_small() {
        let data = vec![0x42; 500];
        let chunks = chunk_payload(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 500);
        assert_eq!(chunks[0], &data[..]);
    }

    #[test]
    fn test_chunk_payload_large() {
        let data = vec![0xAB; 5000];
        let chunks = chunk_payload(&data);
        assert!(chunks.len() >= 4);

        let mut combined = Vec::new();
        for chunk in chunks {
            assert!(chunk.len() >= 768 || combined.len() + chunk.len() == data.len());
            combined.extend_from_slice(chunk);
        }
        assert_eq!(combined, data);
    }

    #[tokio::test]
    async fn test_stream_read_buffer_leftover() {
        let (tx, rx) = mpsc::channel(10);
        let mut buffer = StreamReadBuffer::new(rx);

        // Send a 100-byte packet
        let payload: Vec<u8> = (0..100).collect();
        tx.send(payload.clone()).await.unwrap();

        // Read with a 30-byte buffer: should read 30, leftover has 70
        let mut read_buf = [0u8; 30];
        let n1 = buffer.read(&mut read_buf).await.unwrap();
        assert_eq!(n1, 30);
        assert_eq!(&read_buf[..30], &payload[..30]);

        // Next read with 40-byte buffer: should read 40 from leftover
        let mut read_buf2 = [0u8; 40];
        let n2 = buffer.read(&mut read_buf2).await.unwrap();
        assert_eq!(n2, 40);
        assert_eq!(&read_buf2[..40], &payload[30..70]);

        // Next read with 50-byte buffer: should read remaining 30 from leftover
        let mut read_buf3 = [0u8; 50];
        let n3 = buffer.read(&mut read_buf3).await.unwrap();
        assert_eq!(n3, 30);
        assert_eq!(&read_buf3[..30], &payload[70..100]);

        // Channel empty, drop tx to trigger EOF
        drop(tx);
        let n4 = buffer.read(&mut read_buf3).await.unwrap();
        assert_eq!(n4, 0);
    }
}
