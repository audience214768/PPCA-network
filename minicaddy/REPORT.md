# Mini Caddy — REPORT.md

## 架构

```
main.rs  (128 行)
  ├── config.rs            —— 环境变量配置 (HTTP_ADDR, UPSTREAM_ADDR, PROXY_AUTH)
  ├── error.rs             —— ProxyError (Io + HttpInvalidRequest)
  ├── http_proto.rs        —— HTTP/1.1 协议层 (302 行)
  │     │                     解析、帧编码、gzip、auth、MIME、chunked
  │     └── SITES 表       —— 虚拟主机路由表
  └── inbounds/
        ├── http.rs         —— 调度 + keep-alive + 入口 (116 行)
        ├── http_files.rs   —— 静态文件服务器 (122 行)
        └── http_proxy.rs   —— 反向代理 (68 行)
```

```
run_http (入口)
  └── accept loop → per-connection spawn
       └── serve_connection
            └── loop { parse → handle_request → keep-alive? }
                 ├── Host lookup → SITES 表
                 ├── /api/* 或 proxy site → reverse_proxy (透明转发)
                 └── 其他 → auth? → file_server
```

## 帧设计

### Content-Length（文件服务默认）

文件大小由 `metadata.len()` 获取，直接写入 `Content-Length`。

### Chunked Transfer-Encoding（gzip 输出 + chunked 请求体）

压缩后大小不可预知，逐块输出。`write_chunk()` 负责 `hex-size\r\ndata\r\n` 格式。请求端 `read_chunked_body()` 逐块解析，支持 chunk extension（`;key=val`）和 trailer headers，pipelined 安全（leftover 字节返回给下一个请求）。

## 功能清单

### 已实现（19/19 一致性测试通过）

| 功能 | 说明 |
|------|------|
| HTTP/1.1 请求解析 | `httparse`，请求行 + 头部 + body |
| Content-Length 响应帧 | 精确 `Content-Length` |
| Chunked 请求体解码 | RFC 7230 §4.1，支持 extension 和 trailer |
| Chunked + gzip 响应 | `Content-Encoding: gzip` + `Vary: Accept-Encoding` |
| Keep-alive 连接复用 | 一连接多请求，30s idle timeout |
| 静态文件服务 | 目录索引、MIME 映射 |
| ETag + Last-Modified | 弱 ETag `W/"mtime-size"`，HTTP-date（libc `gmtime_r`） |
| 条件请求 304 | `If-None-Match` 匹配 |
| Range 请求 206 | `bytes=N-M` 及后缀 `bytes=-N` |
| 416 Range Not Satisfiable | 非法 Range 的正确响应 |
| 路径穿越保护 | `canonicalize()` + `starts_with()` |
| HEAD 方法 | 仅返回响应头 |
| HTTP Basic Auth | `Authorization: Basic` + 常量时间比对 + `WWW-Authenticate` |
| 反向代理 | 路径改写、流式双向转发 |
| X-Forwarded-For / X-Forwarded-Proto | 客户端 IP + 协议 |
| 上游故障 502 | 连接失败 / 响应异常 → 502 |
| Hop-by-hop 头剥离 | 8 个头过滤 |
| 上游响应解析 | `httparse::Response`，记录状态码 |
| Pipelined 请求 | leftover buffer，chunked 体后正确读取下个请求 |
| 虚拟主机 | `Host` 头路由到不同站点 |

### 一致性测试结果

```
== static ==                    6/6   ✅
== range / conditional ==       4/4   ✅
== framing / keep-alive ==      4/4   ✅
== virtual host ==              2/2   ✅
== proxy / middleware ==        3/3   ✅
─────────────────────────────────────
                              19/19
```

### 未实现

| 功能 | 说明 |
|------|------|
| Caddyfile 配置 | TOML 或 Caddyfile 解析替代环境变量/硬编码 |
| Rate Limiting | Token bucket per client IP |
| Access Logging | 请求行、状态码、耗时 |
| ACME HTTP-01 | 自动 HTTPS 证书 |
| HTTP/2 | HPACK、流控、多路复用 |

## 吞吐量

测试环境：OrbStack Ubuntu VM (arm64)，16KB 静态文件，debug build。5 轮 × 200 请求，平均 **~579 req/s**。

Caddy debug build 同等条件约 3000–5000 req/s。差距原因：

1. **Debug vs Release**：Rust debug 比 release 慢 3–5×。`--release` 预期 2000+ req/s
2. **事件模型**：Caddy 已优化 buffer 复用和 goroutine 调度；我们的 per-connection Vec buffer 有分配开销
3. **文件 I/O**：Caddy 的 `sendfile` 零拷贝 vs 我们的 userspace `copy`

## 依赖

| crate | 用途 |
|-------|------|
| `tokio` (full) | 异步运行时 + 网络 + 文件 I/O |
| `httparse` | HTTP 请求/响应解析 |
| `flate2` | gzip 压缩 |
| `base64` | Basic Auth 凭据解码 |
| `libc` | HTTP-date 格式化 (`gmtime_r`) |
