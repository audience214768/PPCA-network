# Mini Caddy — 从 Socket 开始构建 Web 服务器

[English version](minicaddy.md)

> 自选项目 (基础 6' + 最多 12' bonus) — 网络方向

## 动机

到目前为止你一直在客户端/中间层：SOCKS5、MITM、DNS 劫持。这个项目反转角色——**你就是源服务器**。一个请求到达原始 TCP socket，你的代码负责将这些字节变成响应。

你将构建 **minicaddy**，一个 [Caddy](https://caddyserver.com/) 风格的 Web 服务器：静态文件、反向代理、虚拟主机、中间件，以及 Caddy 的标志性功能——通过 ACME 自动获取 HTTPS 证书。

## 红线（先读这个）

重点是 `net/http` 本来会替你做的那些事。因此：

**禁止：**
- `net/http` 服务端：`http.Server`、`http.ListenAndServe`、`http.Handler`、`http.FileServer`、`httputil.ReverseProxy`、`http.ReadRequest`、`http.ReadResponse`
- 任何第三方 HTTP 服务器/路由/ACME 库（`fasthttp`、`gin`、`chi`、`echo`、`golang.org/x/crypto/acme`、`certmagic` 等）

**允许：**
- `net`、`crypto/tls`、`bufio`、`io`、`net/url`、`compress/gzip`、`encoding/*`
- `net/http` **客户端**（`http.Client`、`http.NewRequest`）— **仅限** ACME 对 CA 的外发 REST 请求
- `http.Header` 作为数据结构（但解析必须自己写）

违规 = 受影响组件自动零分。

## 基础 (6')

### 1. HTTP/1.1 引擎
- 基于 `bufio.Reader` 手写请求解析器
- 响应帧：`Content-Length` 或 **chunked** transfer-encoding
- **Keep-alive**：复用连接、drain 未读 body、idle timeout
- 解码 chunked 请求 body

### 2. 静态文件服务器
- 目录索引解析；按扩展名 MIME 类型
- `ETag` + `Last-Modified`，条件请求 `304`
- 单 **Range** 请求 → `206 Partial Content`
- 路径穿越保护

### 3. 反向代理
- 转发到 upstream，流式传输双向 body
- 剥离 hop-by-hop 头；添加 `X-Forwarded-For`/`X-Forwarded-Proto`
- upstream 故障返回 `502`

### 4. 虚拟主机 / 路由
- 按 `Host` 头路由到正确的站点

### 5. 配置
- 解析 Caddyfile 风格配置以驱动所有功能

## Bonus 1: 自动 HTTPS (+4')

实现 **ACME v2 (RFC 8555)** 客户端，使用 **HTTP-01** 挑战：

- JWS 签名的账户注册
- 新订单 → 在 `/.well-known/acme-challenge/<token>` 发布密钥授权（由**你的** HTTP 栈服务）
- 轮询至 `valid`，finalize CSR，将证书安装到 TLS 监听器（按 SNI）
- 用 [Pebble](https://github.com/letsencrypt/pebble) 测试——不需要真实域名

## Bonus 2: 中间件 (+3')

可组合、配置驱动的中间件：

- **basic auth** — `401` + `WWW-Authenticate`，常量时间比较
- **rate limiting** — token bucket，per client IP
- **gzip** — 尊重 `Accept-Encoding`，设置 `Vary`
- **access logging** — 请求行、状态码、耗时

## Bonus 3: HTTP/2 (+5')

TLS 上的完整 HTTP/2：
- HPACK 头部压缩
- 流多路复用与流控
- Server push（可选）
- ALPN 协商（`h2` / `http/1.1`）

## 测试

一致性脚本（`testbed/conformance.sh`）用 `curl`/`nc` 驱动服务器并检查核心行为。用**真实 Caddy 作为参照**：对同一请求运行 Caddy 并 diff 响应。

ACME 测试：本地运行 Pebble：
```bash
ACME_DIRECTORY=https://localhost:14000/dir ACME_INSECURE=1 ./minicaddy -config Caddyfile
```

## 交付物

- 用 `go build ./...` 编译通过的源代码
- 展示你实现的所有功能的 `Caddyfile`
- 通过你核心功能的 `testbed/conformance.sh`
- `REPORT.md`（2-4 页）：架构、帧设计、一个与真实 Caddy 对比的吞吐量数字、已实现和未实现的功能

## 评分

| 组件 | 分值 |
|------|-----:|
| 构建与完整性（无禁用 import） | 1 |
| HTTP/1.1 引擎（解析、帧、keep-alive） | 2 |
| 静态文件服务器（MIME、条件请求、Range） | 1.5 |
| 反向代理（流式、hop-by-hop、502） | 1.5 |
| Bonus: ACME HTTP-01（Pebble 全流程） | +4 |
| Bonus: 中间件（可组合、配置驱动） | +3 |
| Bonus: HTTP/2（HPACK、流、流控） | +5 |

## 参考资料

- [RFC 9112: HTTP/1.1 消息语法](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 8555: ACME](https://www.rfc-editor.org/rfc/rfc8555)
- [Caddy 文档](https://caddyserver.com/docs/)
- [Pebble (ACME 测试 CA)](https://github.com/letsencrypt/pebble)
