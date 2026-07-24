# Mini Caddy — REPORT.md

## 架构

```
main.rs  (18 行)
  ├── config.rs            —— Caddyfile 解析器 (132 行)
  │     │                     支持 root, file_server, reverse_proxy,
  │     │                     gzip, log, basic_auth, rate_limit 指令
  │     │                     虚拟主机按 Host 头路由
  │     └── SiteConfig      —— 每站点配置结构体
  ├── error.rs             —— ProxyError (Io + HttpInvalidRequest)
  ├── http_proto.rs        —— HTTP/1.1 协议层 (324 行)
  │     │                     请求解析、Content-Length / chunked 帧、
  │     │                     gzip 压缩、MIME 类型、ETag / HTTP-Date、
  │     │                     Basic Auth 常量时间比对、Range 解析、
  │     │                     hop-by-hop 头过滤、路径穿越保护
  │     └── 工具函数        —— read_body, write_chunk, copy_headers, safe_path...
  ├── rate_limiter.rs      —— Token Bucket 限流器 (35 行)
  └── inbounds/
        ├── http.rs         —— 调度 + keep-alive + 入口 (183 行)
        ├── http_files.rs   —— 静态文件服务器 (130 行)
        └── http_proxy.rs   —— 反向代理 (63 行)
```

```
run_http (入口)
  └── accept loop → per-connection tokio::spawn
       └── serve_connection
            └── loop { parse → handle_request → keep-alive? }
                 ├── rate_limit 检查 → 429 (if exceeded)
                 ├── Host 匹配 → SiteConfig 路由
                 ├── basic_auth 检查 → 401
                 ├── reverse_proxy → 透明转发到 upstream
                 └── file_server → 静态文件 / 目录索引
```

## 帧设计

### Content-Length（文件和目录索引默认）

文件大小由 `metadata.len()` 获取，直接写入 `Content-Length`。目录索引 HTML 为动态生成，大小已知，同样使用 Content-Length。

### Chunked Transfer-Encoding（gzip 压缩输出 + chunked 请求体）

gzip 压缩后大小不可预知，采用 chunked 编码逐块输出。`write_chunk()` 负责 `hex-size\r\ndata\r\n` 格式，`write_last_chunk()` 写入终止块 `0\r\n\r\n`。

请求端 `read_chunked_body()` 逐块解析：
- 支持 chunk extension（`;key=val`，被忽略）
- 支持 trailer headers（终止块后的 `\r\n\r\n` 结束）
- Pipelined 安全：chunked 体后的剩余字节通过 leftover buffer 返回，供下一个请求解析使用

### 连接复用与 Keep-Alive

`serve_connection` 维护一个 `buffer: Vec<u8>`，循环解析请求。每个请求处理完后返回 leftover 字节，不清空 buffer。判断 `Connection: close` 决定是否退出循环。30 秒 idle timeout 后关闭空闲连接。

## 功能清单

### 已实现（23/23 一致性测试通过）

| 功能 | 说明 |
|------|------|
| Caddyfile 配置解析 | `root`, `file_server`, `reverse_proxy`, `gzip`, `log`, `basic_auth`, `rate_limit` 指令 |
| HTTP/1.1 请求解析 | 基于 `httparse`，请求行 + 头部 + body |
| Content-Length 响应帧 | 精确 `Content-Length` |
| Chunked 请求体解码 | RFC 7230 §4.1，支持 extension 和 trailer |
| Chunked + gzip 响应 | `Content-Encoding: gzip` + `Vary: Accept-Encoding` |
| Keep-alive 连接复用 | 一连接多请求，30s idle timeout |
| 静态文件服务 | 目录索引、MIME 映射（12 种类型） |
| ETag + Last-Modified | 弱 ETag `W/"mtime-size"`，HTTP-date（libc `gmtime_r`） |
| 条件请求 304 | `If-None-Match` 匹配 |
| Range 请求 206 | `bytes=N-M` 及后缀 `bytes=-N` |
| 416 Range Not Satisfiable | 非法 Range 的正确响应 |
| 路径穿越保护 | `canonicalize()` + `starts_with()` |
| HEAD 方法 | 仅返回响应头，不返回 body |
| HTTP Basic Auth | `Authorization: Basic` + 常量时间比对 + `WWW-Authenticate` |
| 反向代理 | 路径改写（`/api` 前缀剥离）、流式双向转发 |
| X-Forwarded-For / X-Forwarded-Proto | 客户端 IP + 协议 |
| 上游故障 502 | 连接失败 / 响应异常 → 502 |
| Hop-by-hop 头剥离 | 8 个头过滤（connection, keep-alive, transfer-encoding, te, trailer, upgrade, proxy-authenticate, proxy-authorization） |
| Pipelined 请求 | leftover buffer，chunked 体后正确读取下个请求 |
| 虚拟主机 | `Host` 头路由到不同站点配置 |
| Rate Limiting | Token bucket 算法，per-listener 限流，`Retry-After` 头 |
| Gzip 压缩 | 基于 `Accept-Encoding`，支持静态文件和目录索引 |

### 一致性测试结果

```
== static ==                    6/6   ✅
== range / conditional ==       4/4   ✅
== framing / keep-alive ==      4/4   ✅
== virtual host ==              2/2   ✅
== proxy / middleware ==        3/3   ✅
== rate limiting ==             4/4   ✅
─────────────────────────────────────
                              23/23
```

### 未实现

| 功能 | 说明 |
|------|------|
| Access Logging | `log` 指令已解析但未输出日志 |
| ACME HTTP-01 | 自动 HTTPS 证书（需实现 JWS、ACME 客户端、Pebble 测试） |
| HTTP/2 | HPACK 头部压缩、流多路复用、流控、ALPN 协商 |

## 吞吐量对比

### 测试环境

- **硬件**: MacBook (Apple Silicon arm64)
- **OS**: macOS 15
- **工具**: [oha](https://github.com/hatoo/oha)（HTTP/1.1 keep-alive）
- **参数**: 5000 请求 × 50 并发，3 轮取均值
- **minicaddy**: release build (`cargo build --release`)
- **Caddy**: v2.11.4 (Homebrew 预编译二进制)
- **测试文件**: 随机内容，大小 1KB / 16KB / 64KB

### 结果

| 文件大小 | minicaddy (release) | Caddy v2.11.4 | 差距 |
|----------|---------------------|---------------|------|
| 1 KB     | 18,157 req/s        | 35,958 req/s  | Caddy 2.0× |
| 16 KB    | 9,200 req/s         | 38,280 req/s  | Caddy 4.2× |
| 64 KB    | 3,536 req/s         | 35,350 req/s  | Caddy 10.0× |

### 延迟对比（16KB 文件）

| 指标 | minicaddy | Caddy |
|------|-----------|-------|
| p50   | 4.25 ms   | 1.04 ms |
| p90   | 6.35 ms   | 2.06 ms |
| p99   | 8.49 ms   | 4.40 ms |
| avg   | 4.33 ms   | 1.20 ms |

### 差距分析

1. **`sendfile()` 零拷贝**: Caddy 使用 `sendfile()` 系统调用，文件数据从 page cache 直接发送到 socket，不经过用户态。minicaddy 使用 `tokio::io::copy`，数据需在用户态和内核态之间复制两次。这解释了文件越大差异越大的趋势（64KB 时 10×）。

2. **内存分配**: minicaddy 每个连接维护一个动态扩容的 `Vec<u8>` buffer，高并发时分配压力增大。Caddy 的 buffer 复用策略更为成熟。

3. **Release vs Debug**: release 版本比 debug 快约 **16–20 倍**（debug: ~579 req/s → release: ~9,200 req/s），远超最初估计的 3–5 倍。Rust 的 zero-cost abstraction 在 release profile 下充分发挥作用。

4. **小文件场景**: 1KB 文件差距仅 2× —— 此时协议解析和连接管理开销占主导，文件 I/O 差异不明显。minicaddy 的 HTTP/1.1 协议层效率与 Caddy 在解析方面差距不大。

## 依赖

| crate | 用途 |
|-------|------|
| `tokio` (full) | 异步运行时 + 网络 + 文件 I/O |
| `httparse` | HTTP 请求/响应解析 |
| `flate2` | gzip 压缩 |
| `base64` | Basic Auth 凭据解码 |
| `libc` | HTTP-date 格式化 (`gmtime_r`) |
