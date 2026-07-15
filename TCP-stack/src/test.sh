#!/bin/bash
# TCP-stack test script for OrbStack Linux VM
# Usage: bash src/test.sh <phase>
# Phases: p1 | p2 | p3 | p4 | p5 | p6
# Run from the TCP-stack/ directory

set -euo pipefail

TAP="tap0"
TAP_IP="10.0.0.1/24"
STACK_IP="10.0.0.2"
STACK_PORT="8080"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

check_deps() {
    local missing=""
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "'$cmd' not found"
            missing="$missing $cmd"
        fi
    done
    if [ -n "$missing" ]; then
        info "Install missing tools: sudo apt install -y${missing}"
    fi
}

setup_tap() {
    sudo ip link delete "$TAP" 2>/dev/null || true
    sudo ip tuntap add "$TAP" mode tap
    sudo ip addr add "$TAP_IP" dev "$TAP"
    sudo ip link set "$TAP" up
    info "TAP '$TAP' ready ($TAP_IP)"
}

teardown_tap() {
    sudo ip link delete "$TAP" 2>/dev/null || true
    info "TAP '$TAP' removed"
}

# ── Phase 1: TAP + Ethernet ──
run_p1() {
    info "=== Phase 1: TAP + Ethernet ==="
    setup_tap
    info "Stack starting — prints incoming EtherType."
    info "In another shell: sudo arping -I $TAP $STACK_IP"
    info "Ctrl+C to stop."
    echo ""
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP"
}

# ── Phase 2: ARP ──
run_p2() {
    info "=== Phase 2: ARP ==="
    check_deps arping
    setup_tap
    info "Stack starting — should reply to ARP requests."
    info "In another shell: sudo arping -I $TAP $STACK_IP"
    echo ""
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP"
}

# ── Phase 3: IP + ICMP Echo ──
run_p3() {
    info "=== Phase 3: IP + ICMP Echo ==="
    check_deps ping
    setup_tap
    info "Stack starting — should reply to ping."
    info "In another shell: ping $STACK_IP"
    echo ""
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP"
}

# ── Phase 4: TCP Handshake ──
run_p4() {
    info "=== Phase 4: TCP 3-Way Handshake ==="
    setup_tap
    info "Stack listening on $STACK_IP:$STACK_PORT"
    info "In another shell: nc $STACK_IP $STACK_PORT"
    echo ""
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP" --listen "$STACK_PORT"
}

# ── Phase 5: TCP Data + FIN ──
run_p5() {
    info "=== Phase 5: TCP Data + FIN ==="
    setup_tap
    info "Stack listening on $STACK_IP:$STACK_PORT (echo mode)"
    info "In another shell: echo 'hello' | nc -q 0 $STACK_IP $STACK_PORT"
    echo ""
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP" --listen "$STACK_PORT"
}

# ── Phase 6: HTTP Demo ──
run_p6() {
    info "=== Phase 6: HTTP GET (Client Mode) ==="
    warn "Ensure NAT is configured:"
    echo "  sudo sysctl -w net.ipv4.ip_forward=1"
    echo "  sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE"
    echo "  sudo iptables -A FORWARD -i $TAP -o eth0 -j ACCEPT"
    echo "  sudo iptables -A FORWARD -i eth0 -o $TAP -m state --state ESTABLISHED,RELATED -j ACCEPT"
    echo ""
    info "This requires a local HTTP server on the other side."
    info "For testing, run in another shell: python3 -m http.server 8000 -b 10.0.0.1"
    info "Then the stack will connect to 10.0.0.1:8000 and send a GET request."
    echo ""
    setup_tap
    cd /Users/audience/program/PPCA/network
    cargo run -p TCP-stack -- "$TAP" --ip "$STACK_IP" --connect "${1:-10.0.0.1:8000}"
}

PHASE="${1:-p1}"
case "$PHASE" in
    p1|p2|p3|p4|p5|p6)
        trap teardown_tap EXIT
        "run_$PHASE"
        ;;
    *)
        echo "Usage: bash src/test.sh <phase>"
        echo "  p1 - TAP + Ethernet"
        echo "  p2 - ARP"
        echo "  p3 - IP + ICMP Echo"
        echo "  p4 - TCP handshake"
        echo "  p5 - TCP data transfer"
        echo "  p6 - HTTP GET demo"
        exit 1
        ;;
esac
