#!/usr/bin/env python3
"""
Minimal DNS-over-TLS proxy for bootstrapping stubby on Raspberry Pi.
Listens for plain DNS queries on UDP 127.0.0.1:5300, forwards them to
Quad9 over TLS port 853, returns the response. Replaced by stubby once
apt-get install stubby completes.
"""

import logging
import socket
import ssl
import struct
import threading

UPSTREAM_SERVERS = [
    ('9.9.9.9',         853, 'dns.quad9.net'),
    ('149.112.112.112', 853, 'dns.quad9.net'),
]
LISTEN_ADDR = '127.0.0.1'
LISTEN_PORT = 5300
CONNECT_TIMEOUT = 5   # TCP connection establishment
DATA_TIMEOUT    = 15  # TLS handshake + query/response (DNSSEC responses can be large)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

ctx = ssl.create_default_context()


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('upstream closed connection mid-response')
        buf += chunk
    return buf


def forward(query, addr, udp_sock):
    for host, port, hostname in UPSTREAM_SERVERS:
        for attempt in range(2):
            try:
                with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
                    raw.settimeout(DATA_TIMEOUT)
                    with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                        tls.sendall(struct.pack('!H', len(query)) + query)
                        length = struct.unpack('!H', recv_exact(tls, 2))[0]
                        response = recv_exact(tls, length)
                udp_sock.sendto(response, addr)
                return
            except ConnectionError as exc:
                log.warning('upstream %s:%d attempt %d: %s', host, port, attempt + 1, exc)
            except Exception as exc:
                log.warning('upstream %s:%d failed: %s', host, port, exc)
                break  # non-recoverable (TLS error, timeout, etc.) — try next server
    log.error('all upstream servers failed for query from %s', addr)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    log.info('DoT proxy listening on %s:%d', LISTEN_ADDR, LISTEN_PORT)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=forward, args=(data, addr, sock), daemon=True).start()
        except Exception as exc:
            log.error('recv error: %s', exc)


if __name__ == '__main__':
    main()
