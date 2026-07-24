# My-Proxy Demo 流程

## 前置条件

- Rust 工具链 (`rustc` + `cargo`)
- `curl`（SOCKS5 TCP 测试，macOS 自带）
- Python 3（UDP relay 测试脚本）
- Linux + `nftables`（TPROXY 透明代理，仅 Linux；macOS 跳过）

## 第一步：构建

```bash
cd /Users/audience/program/PPCA/network
cargo build --release
```

二进制位置：`target/release/my-proxy`

## 第二步：SOCKS5 TCP CONNECT 演示

### 2.1 启动代理

代理通过环境变量配置，无需配置文件：

```bash
cd /Users/audience/program/PPCA/network
SOCKS5_ADDR=127.0.0.1:1080 target/release/my-proxy
```

输出：
```
SOCKS5 代理已启动：127.0.0.1:1080
```

### 2.2 配置说明

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `SOCKS5_ADDR` | （无，不启用） | SOCKS5 监听地址，如 `127.0.0.1:1080` |
| `TPROXY_ADDR` | （无，不启用） | TPROXY 透明代理监听地址，如 `:12345` |
| `UDP_IDLE_TIMEOUT` | `30` | UDP 关联空闲超时（秒） |

### 2.3 启动本地 HTTP 测试服务器

在另一个终端启动 Python HTTP 服务器作为测试目标：

```bash
python3 -m http.server 9999 --bind 127.0.0.1
```

### 2.4 IPv4 目标

```bash
# 直接使用 IPv4 地址
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:1080 http://127.0.0.1:9999/

# 代理日志输出：
# SOCKS5 CONNECT → Ipv4(127.0.0.1, 9999)
# SOCKS5 透传结束
```

### 2.5 域名目标（代理端解析）

```bash
# socks5h:// — 域名由代理端解析（域名 ATYP 0x03）
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:1080 http://localhost:9999/

# socks5://  — 域名由 curl 本地解析，代理收到的是 IPv4 地址
curl -s -o /dev/null -w '%{http_code}\n' -x socks5://127.0.0.1:1080 http://127.0.0.1:9999/
```

代理日志会显示：
```
SOCKS5 CONNECT → Domain("localhost", 9999)    # socks5h：域名 ATYP
SOCKS5 CONNECT → Ipv4(127.0.0.1, 9999)        # socks5：IPv4 ATYP
```

> 说明：`socks5h://` 将域名通过 SOCKS5 Domain ATYP (`0x03`) 发给代理，由代理端做 DNS 解析；`socks5://` 则由 curl 本地解析后以 IPv4 ATYP 发送。

### 2.6 公网站点测试

对应 socks5.zh.md 要求的测试方法：

```bash
# HTTP — 域名由代理端解析
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:1080 http://example.com
# 代理日志：SOCKS5 CONNECT → Domain("example.com", 80)
```

HTTPS 通过 SOCKS5 CONNECT 建立 TCP 隧道后，TLS 握手直接在客户端与目标之间完成，代理不参与加密：

```bash
# HTTPS
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:1080 https://www.baidu.com
# 代理日志：SOCKS5 CONNECT → Domain("www.baidu.com", 443)
```

> 注意：`https://www.google.com` 在国内不可达；`http://ipv6.google.com` 需要本机有 IPv6 全球连接。可替换为任意可达的 HTTP/HTTPS 站点测试。

### 2.7 并发连接

```bash
# 同时发起 5 个请求，验证 per-connection spawn 模式
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "请求 #$i: %{http_code}\n" --connect-timeout 5 \
    -x socks5h://127.0.0.1:1080 http://127.0.0.1:9999/ &
done
wait
```

预期 5 个请求均返回 200，代理日志显示 5 条独立的连接处理。

### 2.8 错误处理

```bash
# 目标不可达 → 返回 ConnectionRefused (REP=0x05)
curl -s -o /dev/null -w '%{http_code}\n' \
  -x socks5h://127.0.0.1:1080 http://127.0.0.1:1/
# curl 报错：Connection refused（代理日志：连接失败）

# DNS 解析失败 → 返回 HostUnreachable (REP=0x04)
curl -s -o /dev/null -w '%{http_code}\n' \
  -x socks5h://127.0.0.1:1080 http://nonexistent.invalid/
# curl 报错：Could not resolve host（代理日志：DNS 失败）
```

## 第三步：SOCKS5 UDP ASSOCIATE 演示

### 3.1 启动代理

```bash
SOCKS5_ADDR=127.0.0.1:1080 cargo run --release
```

### 3.2 运行测试脚本

在另一个终端：

```bash
cd /Users/audience/program/PPCA/network/my-proxy
python3 test_udp.py
```

### 3.3 测试用例说明

| 测试 | 内容 | 验证点 |
|------|------|--------|
| Test 1 | IPv4 destination | UDP 请求通过 IPv4 ATYP 发送到 echo server，回包 payload 一致 |
| Test 2 | Domain-name destination | 目标地址以域名 (`0x03`) 编码，代理端做 DNS 解析 |
| Test 3 | Multiple packets (5) | 交替使用 IPv4 和域名 ATYP，验证连续收发包不丢、不乱序 |
| Test 4 | Non-zero FRAG | 发送 FRAG ≠ 0 的包，代理应直接丢弃（无回复），验证不崩溃 |
| Test 5 | Bidirectional | 客户端发 `ping`，固定回复 server 回 `pong`，验证双向数据路径独立 |
| Test 6 | Multi-client (3) | 3 个客户端各自完成 TCP 握手 → UDP ASSOCIATE → 收发 → 关闭 |

### 3.4 预期输出

```
============================================================
  Test 1: IPv4 destination
============================================================
    Sent 21 bytes via IPv4 ATYP
    Reply: 21 bytes
  ✅ Payload matches (expected 21B, got 21B)

============================================================
  Test 2: Domain-name destination
============================================================
    Sent 33 bytes via domain ATYP (localhost:xxxxx)
    Reply: 33 bytes
  ✅ Payload matches (expected 33B, got 33B)

============================================================
  Test 3: Multiple packets
============================================================
    Packet #0 ✅ (26B round-trip)
    Packet #1 ✅ (26B round-trip)
    Packet #2 ✅ (26B round-trip)
    Packet #3 ✅ (26B round-trip)
    Packet #4 ✅ (26B round-trip)

============================================================
  Test 4: Non-zero FRAG (should be ignored)
============================================================
  ✅ Proxy correctly ignored fragmented packet (no reply)

============================================================
  Test 5: Bidirectional (server replies with different data)
============================================================
    Sent 'ping', received b'pong'
  ✅ Sent 'ping', received b'pong'

============================================================
  Test 6: Multi-client concurrent
============================================================
  Client #0: ✅ (26B round-trip)
  Client #1: ✅ (26B round-trip)
  Client #2: ✅ (26B round-trip)
  All 3 clients: 3 passed, 0 failed

============================================================
  Results: 6/6 passed
  🎉 All tests passed!
============================================================
```

## 第四步：TPROXY 透明代理演示（仅 Linux）

> macOS 不支持 `IP_TRANSPARENT`，此步骤需要在 Linux 上执行。

### 4.1 启动代理

```bash
TPROXY_ADDR=:12345 cargo run --release
```

输出：
```
TPROXY TCP 透明代理已启动：0.0.0.0:12345
```

如果同时启用 SOCKS5：
```bash
SOCKS5_ADDR=127.0.0.1:1080 TPROXY_ADDR=:12345 cargo run --release
```

### 4.2 加载 nftables 规则

`tproxy_rules.nft` 文件位于项目根目录：

```bash
cd /Users/audience/program/PPCA/network/my-proxy
sudo nft -f tproxy_rules.nft
```

规则说明：

| 链 | 类型 | 作用 |
|----|------|------|
| `prerouting_chain` | filter prerouting | 将带有 mark 1 的 TCP 包 TPROXY 到 `:12345` |
| `output_chain` | route output | 匹配本机发出的 `tcp dport 80`，打 mark 1 后重路由到 TPROXY |

> 注意：`output_chain` 跳过 root (`skuid 0`) 和本地地址（`127.0.0.0/8`、`10.0.0.0/8`、`192.168.0.0/16`），避免回环。

### 4.3 测试透明代理

```bash
# 本机发出的 HTTP 请求会被透明代理拦截
curl -s -o /dev/null -w '%{http_code}\n' http://httpbin.org/ip
```

代理日志：
```
TPROXY → 目标服务器：httpbin.org:80
TPROXY 透传结束
```

代理通过 `TcpStream::local_addr()` 获取原始目标地址（TPROXY 模式下该地址为连接原始目标而非代理自身地址），然后建立到目标的连接并双向转发。

### 4.4 清理 nftables 规则

```bash
sudo nft flush ruleset
```

## 第五步：清理

```bash
pkill -f "target/release/my-proxy"
```

## 代码导读（请求全链路）

### 启动链路

1. **[main.rs:10-11](src/main.rs#L10-L11)** — `Config::from_env()` 读取环境变量
2. **[main.rs:14-21](src/main.rs#L14-L21)** — 若设置 `SOCKS5_ADDR`，spawn SOCKS5 监听任务
3. **[main.rs:23-30](src/main.rs#L23-L30)** — 若设置 `TPROXY_ADDR`，spawn TPROXY 监听任务
4. **[main.rs:32](src/main.rs#L32)** — 等待 Ctrl-C 优雅关闭

### SOCKS5 TCP CONNECT 链路

1. **[inbounds/socks5.rs:13-23](src/inbounds/socks5.rs#L13-L23)** — `TcpListener::bind` + accept 循环，per-connection spawn
2. **[socks5_proto.rs:177-196](src/socks5_proto.rs#L177-L196)** — `handshake()`：版本校验 + 方法协商（仅支持 NO AUTH `0x00`）
3. **[socks5_proto.rs:227-244](src/socks5_proto.rs#L227-L244)** — `read_request()`：解析 VER/CMD/ATYP + 目标地址
4. **[socks5_proto.rs:198-224](src/socks5_proto.rs#L198-L224)** — `read_address()`：按 ATYP 读取 IPv4(7B)/域名(变长)/IPv6(19B)
5. **[socks5_proto.rs:16-72](src/socks5_proto.rs#L16-L72)** — `Address::from_socks5()`：字节 → 结构化地址
6. **[socks5_proto.rs:104-121](src/socks5_proto.rs#L104-L121)** — `resolve_all()`：域名类型走 `tokio::net::lookup_host`，收集全部地址（IPv4 优先）
7. **[inbounds/socks5.rs:35-68](src/inbounds/socks5.rs#L35-L68)** — 遍历候选地址逐个尝试连接，全部失败才返回 `ConnectionRefused`
8. **[relay/tcp.rs:5-8](src/relay/tcp.rs#L5-L8)** — `tokio::io::copy_bidirectional` 双向透传

### SOCKS5 UDP ASSOCIATE 链路

1. **[inbounds/socks5.rs:74-83](src/inbounds/socks5.rs#L74-L83)** — `UdpSocket::bind("0.0.0.0:0")` 分配随机端口，回复 BND.ADDR
2. **[inbounds/socks5.rs:86-101](src/inbounds/socks5.rs#L86-L101)** — `tokio::select!` 等待 TCP 关闭或 UDP relay 退出
3. **[relay/udp.rs:27-41](src/relay/udp.rs#L27-L41)** — `UdpRelay::run()`：收包 → 按来源分派（client vs server）
4. **[relay/udp.rs:43-72](src/relay/udp.rs#L43-L72)** — `handle_client_packet()`：解析 SOCKS5 UDP 头（RSV/FRAG/ATYP/ADDR），转发 payload 到目标
5. **[relay/udp.rs:75-97](src/relay/udp.rs#L75-L97)** — `handle_server_packet()`：给回包加 SOCKS5 UDP 响应头（Full Cone NAT），发回客户端
6. **[relay/udp.rs:99-103](src/relay/udp.rs#L99-L103)** — `cleanup()`：按 `UDP_IDLE_TIMEOUT` 清理超时的目标映射

### TPROXY 透明代理链路

1. **[inbounds/tproxy.rs:11](src/inbounds/tproxy.rs#L11)** — `Socket::new(IPV4, STREAM, TCP)` 创建原始 socket
2. **[inbounds/tproxy.rs:18-28](src/inbounds/tproxy.rs#L18-L28)** — `setsockopt(IP_TRANSPARENT)` 允许绑定非本地地址
3. **[inbounds/tproxy.rs:31-34](src/inbounds/tproxy.rs#L31-L34)** — bind + listen + 转为 tokio `TcpListener`
4. **[inbounds/tproxy.rs:49](src/inbounds/tproxy.rs#L49)** — `client_stream.local_addr()` 获取原始目标地址
5. **[relay/tcp.rs:5-8](src/relay/tcp.rs#L5-L8)** — 同上，双向透传

### 协议层（独立模块）

- **[socks5_proto.rs:10-142](src/socks5_proto.rs#L10-L142)** — `Address` 枚举：三种地址类型 + DNS 解析（`from_socks5`、`resolve_all`、`resolve_ipv4`）
- **[socks5_proto.rs:149-168](src/socks5_proto.rs#L149-L168)** — `Socks5Request` / `Command`：请求结构 + 命令类型
- **[socks5_proto.rs:171-177](src/socks5_proto.rs#L171-L177)** — `ReplyCode`：握手响应码
- **[error.rs:3-11](src/error.rs#L3-L11)** — `ProxyError` 枚举：IO、协议错误、DNS 失败

### 依赖项

| Crate | 用途 |
|-------|------|
| `tokio` (full) | 异步运行时：TCP/UDP 网络 IO、DNS 解析、信号处理 |
| `socket2` | 原始 socket 创建 + `IP_TRANSPARENT` 前置配置 |
| `libc` | `setsockopt(IP_TRANSPARENT)` 系统调用 |
| `httparse` | 声明但未使用（预留给后续 HTTP 解析扩展） |
