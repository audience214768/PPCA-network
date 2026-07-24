# TCP-stack Demo Guide

## 环境要求

- macOS + OrbStack (Linux VM)
- OrbStack Linux 中有 Rust 工具链

## 快速开始

### 1. 进入 OrbStack Linux

```bash
orb
```

### 2. 配置 TAP 设备

```bash
sudo ip link delete tap0 2>/dev/null
sudo ip tuntap add tap0 mode tap
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set tap0 up
```

### 3. 启动 HTTP 服务器（终端 1）

```bash
orb
python3 -m http.server 9999 -b 10.0.0.1
```

### 4. 运行协议栈客户端（终端 2）

```bash
orb
cd /Users/audience/program/PPCA/network
cargo run -p TCP-stack -- tap0 --ip 10.0.0.2 --connect 10.0.0.1:9999
```

### 预期输出

```
TCP-stack: tap='tap0' mac=ee:80:f0:88:c9:a1 ip=10.0.0.2
TCP: connecting to 10.0.0.1:9999
connecting to 10.0.0.1:9999...
> ARP: reply 10.0.0.1 is-at ee:80:f0:88:c9:a1
TCP: connection established 10.0.0.2:40000 -> 10.0.0.1:9999
connected
request sent (53 bytes)
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.4
Content-type: text/html; charset=utf-8
Content-Length: 729

<!DOCTYPE HTML>
<html lang="en">
...
</html>
TCP: closing ...
TCP: connection closed
connection closed.
```

## 工作原理

```
 OrbStack Linux VM
 ┌────────────────────────────────────────────────┐
 │                                                │
 │  [Python HTTP Server]                          │
 │       ↓ bind :9999                             │
 │  [内核 TCP/IP 栈]                               │
 │       ↓                                        │
 │    tap0 (10.0.0.1) ←── MAC ee:80:f0:88:c9:a1   │
 │       │                                        │
 │       │    TAP 虚拟网线 (Ethernet 帧)            │
 │       │                                        │
 │  /dev/net/tun                                  │
 │       ↑                                        │
 │  [我们的协议栈] (10.0.0.2)                       │
 │   纯 Rust 手写:                                 │
 │   ethernet.rs → arp.rs → ip.rs → tcp.rs        │
 │       ↑                                        │
 │  [demo 程序 main.rs]                            │
 │   stack.connect() → stack.send() → stack.recv()│
 └────────────────────────────────────────────────┘
```

## 架构

```
main.rs       应用层 — HTTP GET demo
stack.rs      总控层 — poll() 事件循环 + 对外 API
socket.rs     Socket API — TcpSocket (connect/send/recv/close)
tcp.rs        TCP — 状态机、连接管理、重传、流控
ip.rs         IPv4 — 包构造/解析、checksum、ICMP
arp.rs        ARP — 地址解析、缓存、待发送队列
ethernet.rs   以太网 — 帧解析/构造
tap.rs        TAP 设备 — /dev/net/tun 读写
util.rs       checksum (RFC 1071)
```

## 自定义请求

通过 `--data` 参数发送自定义内容：

```bash
cargo run -p TCP-stack -- tap0 --ip 10.0.0.2 --connect 10.0.0.1:9999 \
  --data "HEAD / HTTP/1.0\r\nHost: test\r\n\r\n"
```

## 测试外部服务器

如果 OrbStack VM 能访问外网，可以 NAT 转发后连接公网：

```bash
# 配置 NAT（只需一次）
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# 连接外部 HTTP 服务器
cargo run -p TCP-stack -- tap0 --ip 10.0.0.2 --connect 93.184.216.34:80
```

## 协议验证（逐层）

| 层 | 命令 | 验证方式 |
|----|------|---------|
| Ethernet | `cargo run ... tap0` | `sudo arping -I tap0 10.0.0.2` |
| ARP |同上 | arping 收到 reply |
| IP + ICMP |同上 | `ping 10.0.0.2` 收到 reply |
| TCP 握手 | `... --connect` | `nc 10.0.0.2 <port>` 建立连接 |
| HTTP | `... --connect 10.0.0.1:9999` | 收到 HTTP 200 |

## 代码量

| 文件 | 代码行 | 功能 |
|------|--------|------|
| `tcp.rs` | ~800 | TCP 状态机、连接管理、重传 |
| `stack.rs` | ~280 | 事件循环、协议整合 |
| `main.rs` | ~80 | HTTP GET demo |
| `arp.rs` | ~230 | ARP + 缓存 |
| `ip.rs` | ~190 | IPv4 + ICMP |
| `tap.rs` | ~110 | TAP 设备 |
| `socket.rs` | ~60 | Socket API |
| `ethernet.rs` | ~40 | 以太网帧 |
| `util.rs` | ~50 | checksum |
| **总计** | **~1840** | |
