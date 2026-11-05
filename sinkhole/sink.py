"""Tool Quarantine sinkhole.

Runs next to a sandbox on an isolated Docker network with no route to the internet.
  * UDP 53  - answers every DNS A query with the sinkhole's own IP, so any hostname
              the tool looks up "resolves" here instead of the real internet.
  * TCP 80  - accepts any HTTP request, records method/host/path/body, replies 200.
  * TCP 443 - reads the TLS ClientHello to learn the SNI hostname, then hangs up.
Every observation is printed to stdout as one JSON line; the host collects them
with `docker logs` before destroying the network.
"""
import json
import os
import socket
import struct
import sys
import threading
import time

MY_IP = os.environ.get("SINK_IP") or socket.gethostbyname(socket.gethostname())
MAX_BODY = 4096
_lock = threading.Lock()


def emit(kind, **fields):
    rec = {"ts": time.time(), "kind": kind, **fields}
    with _lock:
        sys.stdout.write(json.dumps(rec) + "\n")
        sys.stdout.flush()


# ---------------------------------------------------------------- DNS
def parse_qname(data, off):
    labels = []
    while True:
        n = data[off]
        off += 1
        if n == 0:
            break
        labels.append(data[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), off


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    ip = socket.inet_aton(MY_IP)
    while True:
        data, addr = s.recvfrom(1500)
        try:
            tid = data[:2]
            name, off = parse_qname(data, 12)
            qtype, qclass = struct.unpack("!HH", data[off:off + 4])
            question = data[12:off + 4]
            emit("dns", name=name, qtype=qtype, src=addr[0])
            if qtype == 1:  # A
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + ip
                resp = tid + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + question + answer
            else:  # no AAAA etc: empty NOERROR answer
                resp = tid + b"\x81\x80" + struct.pack("!HHHH", 1, 0, 0, 0) + question
            s.sendto(resp, addr)
        except Exception as e:  # malformed packet
            emit("dns_error", error=str(e))


# ---------------------------------------------------------------- HTTP
def handle_http(conn, addr):
    conn.settimeout(5)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = (lines[0].split(" ", 2) + ["", "", ""])[:3]
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
        want = int(headers.get("content-length", "0") or 0)
        while len(body) < min(want, MAX_BODY):
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        emit("http", src=addr[0], method=method, host=headers.get("host", ""), path=path,
             user_agent=headers.get("user-agent", ""),
             body=body[:MAX_BODY].decode("utf-8", "replace"))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}")
    except Exception as e:
        emit("http_error", src=addr[0], error=str(e))
    finally:
        conn.close()


def parse_sni(data):
    try:
        if data[0] != 0x16 or data[5] != 0x01:
            return None
        off = 43
        off += 1 + data[off]                                  # session id
        off += 2 + struct.unpack("!H", data[off:off + 2])[0]  # cipher suites
        off += 1 + data[off]                                  # compression
        end = off + 2 + struct.unpack("!H", data[off:off + 2])[0]
        off += 2
        while off + 4 <= end:
            etype, elen = struct.unpack("!HH", data[off:off + 4])
            off += 4
            if etype == 0:
                nlen = struct.unpack("!H", data[off + 3:off + 5])[0]
                return data[off + 5:off + 5 + nlen].decode("ascii", "replace")
            off += elen
    except Exception:
        return None
    return None


def handle_tls(conn, addr):
    conn.settimeout(5)
    try:
        data = conn.recv(4096)
        emit("tls", src=addr[0], sni=parse_sni(data) or "", bytes=len(data))
    except Exception as e:
        emit("tls_error", src=addr[0], error=str(e))
    finally:
        conn.close()


def tcp_server(port, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(32)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    threading.Thread(target=dns_server, daemon=True).start()
    threading.Thread(target=tcp_server, args=(80, handle_http), daemon=True).start()
    threading.Thread(target=tcp_server, args=(443, handle_tls), daemon=True).start()
    emit("ready", ip=MY_IP)
    while True:
        time.sleep(3600)
