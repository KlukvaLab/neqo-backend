#!/usr/bin/env python3
"""TLS WebSocket echo server for integration tests.

Usage: echo_server_tls.py <cert.pem> <key.pem>

Prints `PORT=<port>` on stdout, then serves sequential TLS WebSocket
connections on a random loopback port. Selects ALPN "http/1.1" and reports
the client's offered ALPN list back in the first echoed message
(`ALPN=<list>;ECHO:<payload>`), which lets tests assert the exact ClientHello
ALPN order. Echoes data frames verbatim; Pings get Pongs; Close gets Close.
"""
import base64
import hashlib
import socket
import ssl
import struct
import sys


def ws_accept(key):
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed mid-frame")
        buf += chunk
    return buf


def read_frame(sock):
    hdr = read_exact(sock, 2)
    opcode = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    ln = hdr[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", read_exact(sock, 2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if masked else b""
    payload = bytearray(read_exact(sock, ln))
    if mask:
        for i in range(ln):
            payload[i] ^= mask[i % 4]
    return opcode, bytes(payload)


def send_frame(sock, opcode, payload):
    ln = len(payload)
    hdr = bytearray([0x80 | opcode])
    if ln <= 125:
        hdr.append(ln)
    elif ln <= 65535:
        hdr.append(126)
        hdr += struct.pack(">H", ln)
    else:
        hdr.append(127)
        hdr += struct.pack(">Q", ln)
    sock.sendall(bytes(hdr) + payload)


def handle(conn, alpn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return
        data += chunk
    head = data.decode("utf-8", "replace")
    key = None
    for line in head.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    if key is None:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    print(f"[srv] WS handshake ok; client offered ALPN={alpn}", flush=True)
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n"
    )
    conn.sendall(resp.encode())

    first = True
    while True:
        opcode, payload = read_frame(conn)
        if opcode == 0x8:  # Close
            send_frame(conn, 0x8, payload)
            return
        if opcode == 0x9:  # Ping -> Pong
            send_frame(conn, 0xA, payload)
            continue
        if opcode == 0xA:  # Pong: absorb
            continue
        # Only the FIRST echoed message carries the ALPN report prefix, so the
        # concatenated stream is exactly "ALPN=<sel>;ECHO:" + payload.
        prefix = f"ALPN={','.join(alpn)};ECHO:".encode() if first else b""
        first = False
        send_frame(conn, 0x02, prefix + payload)


def read_client_hello_alpn(sock):
    """Reads a TLS ClientHello and returns the offered ALPN list in order."""
    buf = b""
    while True:
        # Need at least the record header.
        while len(buf) < 5:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed before record header")
            buf += chunk
        if buf[0] != 0x16:
            raise ValueError("not a handshake record")
        rec_len = int.from_bytes(buf[3:5], "big")
        while len(buf) < 5 + rec_len:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed mid-record")
            buf += chunk
        body = buf[5:5 + rec_len]
        # Walk handshake messages in the record (ClientHello is normally first).
        pos = 0
        while pos + 4 <= len(body):
            htype = body[pos]
            hlen = int.from_bytes(body[pos + 1:pos + 4], "big")
            if htype == 0x01 and pos + 4 + hlen <= len(body):
                ch = body[pos + 4:pos + 4 + hlen]
                # ClientHello: ver(2) random(32) sid_len(1) sid cs_len(2) cs comp_len(1) comp ext_len(2)
                q = 2 + 32
                sid_len = ch[q]; q += 1 + sid_len
                cs_len = int.from_bytes(ch[q:q + 2], "big"); q += 2 + cs_len
                comp_len = ch[q]; q += 1 + comp_len
                ext_total = int.from_bytes(ch[q:q + 2], "big"); q += 2
                end = q + ext_total
                while q + 4 <= min(end, len(ch)):
                    etype = int.from_bytes(ch[q:q + 2], "big")
                    elen = int.from_bytes(ch[q + 2:q + 4], "big")
                    data = ch[q + 4:q + 4 + elen]
                    if etype == 0x0010:  # ALPN
                        plen = int.from_bytes(data[0:2], "big")
                        r = 2
                        protos = []
                        while r < 2 + plen and r < len(data):
                            nlen = data[r]
                            protos.append(data[r + 1:r + 1 + nlen].decode())
                            r += 1 + nlen
                        return protos
                    q += 4 + elen
                raise ValueError("no ALPN extension in ClientHello")
            pos += 4 + hlen
        # ClientHello might be in the next record; keep reading.
        buf = buf[5 + rec_len:]
        if not buf:
            buf = sock.recv(65536)
            if not buf:
                raise ConnectionError("closed before ClientHello")


def sniff_mode():
    """Accepts one TLS connection, prints OFFERED_ALPN=<list>, exits."""
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("127.0.0.1", 0))
    port = ssock.getsockname()[1]
    print(f"PORT={port}", flush=True)
    ssock.listen(1)
    conn, _ = ssock.accept()
    try:
        protos = read_client_hello_alpn(conn)
        print(f"OFFERED_ALPN={','.join(protos)}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"SNIFF_ERROR={type(e).__name__}: {e}", flush=True)
    finally:
        conn.close()
        ssock.close()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "sniff":
        sniff_mode()
        return
    if len(sys.argv) < 3:
        print("usage: echo_server_tls.py <cert.pem> <key.pem> | sniff", file=sys.stderr)
        sys.exit(2)
    cert, key = sys.argv[1], sys.argv[2]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("127.0.0.1", 0))
    port = ssock.getsockname()[1]
    print(f"PORT={port}", flush=True)
    ssock.listen(8)

    while True:
        conn, _ = ssock.accept()
        tls = None
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            selected = tls.selected_alpn_protocol()
            alpn = [selected] if selected else []
            handle(tls, alpn)
        except Exception as e:  # noqa: BLE001 - test server must keep running
            print(f"[srv] {type(e).__name__}: {e}", flush=True)
        finally:
            try:
                if tls is not None:
                    tls.close()
                else:
                    conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
