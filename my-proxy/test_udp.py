#!/usr/bin/env python3
"""
UDP relay test for the SOCKS5 proxy (src/main.rs).

Usage:
    Terminal 1: cargo run
    Terminal 2: python3 test_udp.py
"""

import socket
import struct
import threading
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080


# ---------------------------------------------------------------------------
# Tiny UDP echo server (runs in a background daemon thread)
# ---------------------------------------------------------------------------

def create_echo_server():
    """Start a UDP echo server in a daemon thread. Returns (socket, address)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    addr = sock.getsockname()

    def _echo():
        while True:
            try:
                data, client = sock.recvfrom(65536)
                sock.sendto(data, client)
                print(f"    [echo]  {client} -> {len(data)} bytes echoed")
            except OSError:
                break

    threading.Thread(target=_echo, daemon=True).start()
    return sock, addr


def create_fixed_reply_server(reply_data):
    """Start a UDP server that always replies with fixed data. Returns (socket, address)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    addr = sock.getsockname()

    def _serve():
        while True:
            try:
                data, client = sock.recvfrom(65536)
                sock.sendto(reply_data, client)
                print(f"    [fixed]  {client} <- {len(reply_data)} bytes")
            except OSError:
                break

    threading.Thread(target=_serve, daemon=True).start()
    return sock, addr


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def print_header(name):
    print(f"\n{'='*60}\n  {name}\n{'='*60}")


# ---------------------------------------------------------------------------
# SOCKS5 helpers
# ---------------------------------------------------------------------------

def socks5_handshake(tcp):
    """SOCKS5 handshake: no authentication (0x00)."""
    tcp.sendall(b"\x05\x01\x00")
    resp = tcp.recv(2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"Handshake failed: {resp.hex()}")


def socks5_udp_associate(tcp):
    """Request UDP ASSOCIATE (CMD=0x03) and return the allocated UDP port."""
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = tcp.recv(10)
    if len(resp) < 10:
        raise RuntimeError(f"UDP ASSOCIATE reply too short: {len(resp)} bytes")
    if resp[1] != 0x00:
        raise RuntimeError(f"UDP ASSOCIATE rejected, REP={resp[1]:#04x}")

    port = struct.unpack("!H", resp[8:10])[0]
    bind_addr = ".".join(str(b) for b in resp[4:8])
    print(f"    UDP port allocated: {bind_addr}:{port}")
    return port


def build_udp_request_ipv4(dst_ip, dst_port, payload):
    """Build a SOCKS5 UDP request packet with IPv4 destination."""
    header = b"\x00\x00\x00\x01"
    ip_bytes = socket.inet_aton(dst_ip)
    port_bytes = struct.pack("!H", dst_port)
    return header + ip_bytes + port_bytes + payload


def build_udp_request_domain(domain, dst_port, payload):
    """Build a SOCKS5 UDP request packet with domain-name destination."""
    header = b"\x00\x00\x00\x03"
    domain_bytes = domain.encode("ascii")
    return header + bytes([len(domain_bytes)]) + domain_bytes + struct.pack("!H", dst_port) + payload


def parse_udp_reply(data):
    """Parse a SOCKS5 UDP reply. Returns (src_ip, src_port, payload)."""
    if len(data) < 10:
        raise RuntimeError(f"UDP reply too short: {len(data)} bytes")
    if data[0:2] != b"\x00\x00":
        raise RuntimeError(f"UDP reply RSV mismatch: {data[0:2].hex()}")
    atyp = data[3]
    if atyp != 0x01:
        raise RuntimeError(f"UDP reply has unexpected ATYP: {atyp:#04x}")
    src_ip = socket.inet_ntoa(data[4:8])
    src_port = struct.unpack("!H", data[8:10])[0]
    payload = data[10:]
    return src_ip, src_port, payload


# ---------------------------------------------------------------------------
# Common test helper
# ---------------------------------------------------------------------------

def _send_and_check(sock, packet, expected, desc, udp_port):
    """Send one UDP datagram via proxy, expect echoed payload. Returns (passed, failed)."""
    sock.sendto(packet, (PROXY_HOST, udp_port))
    print(f"    Sent {len(expected)} bytes {desc}")
    try:
        reply, _ = sock.recvfrom(65536)
        _, _, echoed = parse_udp_reply(reply)
        print(f"    Reply: {len(echoed)} bytes")
        if echoed == expected:
            print(f"  ✅ Payload matches (expected {len(expected)}B, got {len(echoed)}B)")
            return 1, 0
        else:
            print(f"  ❌ Payload mismatch (expected {len(expected)}B, got {len(echoed)}B)")
            return 0, 1
    except socket.timeout:
        print(f"  ❌ Timeout waiting for reply")
        return 0, 1


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_ipv4_destination(sock, echo_addr, udp_port):
    print_header("Test 1: IPv4 destination")
    payload = b"Hello from IPv4 test!"
    packet = build_udp_request_ipv4(echo_addr[0], echo_addr[1], payload)
    return _send_and_check(sock, packet, payload, "via IPv4 ATYP", udp_port)


def test_domain_destination(sock, echo_addr, udp_port):
    print_header("Test 2: Domain-name destination")
    payload = "Hello from domain-name test! 🎉".encode()
    packet = build_udp_request_domain("localhost", echo_addr[1], payload)
    return _send_and_check(sock, packet, payload, f"via domain ATYP (localhost:{echo_addr[1]})", udp_port)


def test_multiple_packets(sock, echo_addr, udp_port):
    print_header("Test 3: Multiple packets")
    messages = [f"Packet #{i:02d} — echo this back!".encode() for i in range(5)]
    passed = failed = 0

    for i, msg in enumerate(messages):
        if i % 2 == 0:
            packet = build_udp_request_ipv4(echo_addr[0], echo_addr[1], msg)
        else:
            packet = build_udp_request_domain("localhost", echo_addr[1], msg)

        sock.sendto(packet, (PROXY_HOST, udp_port))
        try:
            reply, _ = sock.recvfrom(65536)
            _, _, echoed = parse_udp_reply(reply)
            if echoed == msg:
                passed += 1
                print(f"    Packet #{i} ✅ ({len(msg)}B round-trip)")
            else:
                failed += 1
                print(f"    Packet #{i} ❌ payload mismatch")
        except socket.timeout:
            failed += 1
            print(f"    Packet #{i} ❌ timeout")

    return passed, failed


def test_invalid_frag(sock, udp_port):
    print_header("Test 4: Non-zero FRAG (should be ignored)")
    packet = b"\x00\x00\xFF\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 9999) + b"should be dropped"

    sock.sendto(packet, (PROXY_HOST, udp_port))
    try:
        reply, _ = sock.recvfrom(65536)
        print(f"  ❌ Unexpected reply to fragmented packet: {len(reply)}B")
        return 0, 1
    except socket.timeout:
        print(f"  ✅ Proxy correctly ignored fragmented packet (no reply)")
        return 1, 0


def _client_roundtrip(client_id, echo_addr):
    """One client: TCP connect → UDP ASSOCIATE → send → recv → close."""
    tcp = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
    try:
        socks5_handshake(tcp)
        udp_port = socks5_udp_associate(tcp)

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(3)
        try:
            payload = f"Client #{client_id} says hello!".encode()
            packet = build_udp_request_ipv4(echo_addr[0], echo_addr[1], payload)
            udp_sock.sendto(packet, (PROXY_HOST, udp_port))
            reply, _ = udp_sock.recvfrom(65536)
            _, _, echoed = parse_udp_reply(reply)
            ok = echoed == payload
            status = "✅" if ok else "❌"
            print(f"  Client #{client_id}: {status} ({len(payload)}B round-trip)")
            return (1, 0) if ok else (0, 1)
        except socket.timeout:
            print(f"  Client #{client_id}: ❌ timeout")
            return 0, 1
        finally:
            udp_sock.close()
    finally:
        tcp.close()


def test_bidirectional(sock, echo_addr, udp_port):
    """Client sends 'ping', server replies with 'pong' — proves both directions work independently."""
    print_header("Test 5: Bidirectional (server replies with different data)")

    reply_sock, reply_addr = create_fixed_reply_server(b"pong")
    try:
        payload = b"ping"
        packet = build_udp_request_ipv4(reply_addr[0], reply_addr[1], payload)
        sock.sendto(packet, (PROXY_HOST, udp_port))
        try:
            reply, _ = sock.recvfrom(65536)
            _, _, echoed = parse_udp_reply(reply)
            ok = echoed == b"pong"
            print(f"  {'✅' if ok else '❌'} Sent 'ping', received {echoed!r}")
            return (1, 0) if ok else (0, 1)
        except socket.timeout:
            print(f"  ❌ Timeout waiting for reply")
            return 0, 1
    finally:
        reply_sock.close()


def test_multi_client(echo_addr):
    print_header("Test 6: Multi-client concurrent")
    results = []

    def worker(i):
        results.append(_client_roundtrip(i, echo_addr))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    passed = sum(r[0] for r in results)
    failed = sum(r[1] for r in results)
    print(f"  All {len(threads)} clients: {passed} passed, {failed} failed")
    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("SOCKS5 UDP Relay Test")
    print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}\n")

    echo_sock, echo_addr = create_echo_server()
    print(f"Echo server: {echo_addr[0]}:{echo_addr[1]}\n")

    udp_sock = None
    try:
        tcp = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
        print("Connected to proxy")
        socks5_handshake(tcp)
        print("SOCKS5 handshake OK (no-auth)")
        udp_port = socks5_udp_associate(tcp)
        print(f"UDP ASSOCIATE OK (port={udp_port})")

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(3)

        total_passed = total_failed = 0
        p, f = test_ipv4_destination(udp_sock, echo_addr, udp_port)
        total_passed += p; total_failed += f
        p, f = test_domain_destination(udp_sock, echo_addr, udp_port)
        total_passed += p; total_failed += f
        p, f = test_multiple_packets(udp_sock, echo_addr, udp_port)
        total_passed += p; total_failed += f

        udp_sock.settimeout(2)
        p, f = test_invalid_frag(udp_sock, udp_port)
        total_passed += p; total_failed += f

        udp_sock.settimeout(3)
        p, f = test_bidirectional(udp_sock, echo_addr, udp_port)
        total_passed += p; total_failed += f

        p, f = test_multi_client(echo_addr)
        total_passed += p; total_failed += f

    except ConnectionRefusedError:
        print("\n❌ Could not connect to proxy — is `cargo run` running?")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
    finally:
        echo_sock.close()
        if udp_sock:
            udp_sock.close()
        try:
            tcp.close()
        except Exception:
            pass

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"  Results: {total_passed}/{total} passed")
    if total_failed == 0:
        print(f"  🎉 All tests passed!")
    else:
        print(f"  ⚠️  {total_failed} test(s) failed")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
