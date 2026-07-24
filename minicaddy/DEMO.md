# Minicaddy Demo 流程

## 前置条件

- Rust 工具链 (`rustc` + `cargo`)
- Python 3（用于 upstream 测试服务器）
- `curl`、`nc`（macOS 自带）
- 可选：`oha`（`brew install oha`，性能测试用）
- 可选：`caddy`（`brew install caddy`，性能对比用）

## 第一步：构建

```bash
cd /Users/audience/program/PPCA/network/minicaddy
cargo build --release
```

二进制位置：`../target/release/minicaddy`（1.2MB）

## 第二步：启动 upstream（反向代理测试必需）

minicaddy 的 Caddyfile 配置了反向代理到 `127.0.0.1:9000`，需提前启动：

```bash
cd www && python3 -m http.server 9000 --bind 127.0.0.1 &
```

> `www/index.html` 内容含 `minicaddy is serving this file`，conformance 测试依赖此文本。

## 第三步：启动 minicaddy

```bash
cd /Users/audience/program/PPCA/network/minicaddy
../target/release/minicaddy
```

输出：
```
minicaddy starting with 4 site(s)
listening on 0.0.0.0:8080
listening on 0.0.0.0:8081
```

### Caddyfile 配置说明

| 块 | 功能 |
|----|------|
| `:8080 { root ./www; file_server; gzip; log }` | 静态文件服务 + gzip，catch-all |
| `vh.localhost:8080 { root ./sites/vh; file_server }` | 虚拟主机：按 `Host: vh.localhost` 路由 |
| `api.localhost:8080 { reverse_proxy 127.0.0.1:9000 }` | 反向代理：剥离 `/api` 前缀后转发 |
| `:8081 { reverse_proxy 127.0.0.1:9000; basic_auth ...; rate_limit ... }` | 需认证的代理 + 限流 |

## 第四步：功能演示（逐个 curl 验证）

### 4.1 静态文件服务

```bash
curl -s http://localhost:8080/                    # 200 目录索引
curl -s http://localhost:8080/index.html           # 200 静态文件
curl -s -o /dev/null -w '%{http_code}' \
  http://localhost:8080/nonexistent                # 404
curl -s -o /dev/null -w '%{http_code}' \
  --path-as-is http://localhost:8080/../../etc/passwd  # 非200（路径穿越保护）
```

### 4.2 条件请求 & Range

```bash
# 获取 ETag
ETAG=$(curl -sI http://localhost:8080/index.html | awk '/^etag:/{print $2}' | tr -d '\r')

# 304 Not Modified
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "If-None-Match: $ETAG" http://localhost:8080/index.html

# 206 Partial Content
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Range: bytes=5-9' http://localhost:8080/index.html
curl -s -H 'Range: bytes=5-9' http://localhost:8080/index.html
```

### 4.3 Gzip 压缩

```bash
curl -sD- -o /dev/null --compressed http://localhost:8080/ \
  | grep -iE '(content-encoding|transfer-encoding)'
# Content-Encoding: gzip
# Transfer-Encoding: chunked
```

### 4.4 Keep-alive（连接复用）

```bash
curl -s -o /dev/null -w 'num_connects: %{num_connects}\n' \
  http://localhost:8080/ http://localhost:8080/index.html
# num_connects: 1（两个请求复用同一连接）
```

### 4.5 虚拟主机

```bash
# vh.localhost → ./sites/vh
curl -s -H 'Host: vh.localhost' http://localhost:8080/index.html

# api.localhost → reverse_proxy
curl -s -H 'Host: api.localhost' http://localhost:8080/index.html
```

### 4.6 反向代理 + Basic Auth（端口 8081）

```bash
# 无认证 → 401
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8081/

# 带认证 → 200
curl -s -o /dev/null -w '%{http_code}\n' \
  -u admin:secret http://localhost:8081/index.html

# 401 响应包含 WWW-Authenticate
curl -sI http://localhost:8081/ | grep -i 'www-authenticate'
```

### 4.7 Rate Limiting

```bash
# 快速发送 50 个请求，触发限流
for i in $(seq 1 50); do
  curl -s -o /dev/null -w '%{http_code}\n' -u admin:secret http://localhost:8081/
done | sort | uniq -c
# 预期：部分 429 + Retry-After 头

# 等 1 秒后恢复
sleep 1
curl -s -o /dev/null -w '%{http_code}\n' -u admin:secret http://localhost:8081/
# 200
```

## 第五步：一致性测试

```bash
cd /Users/audience/program/PPCA/network/minicaddy
chmod +x testbed/conformance.sh
./testbed/conformance.sh
```

预期输出：
```
== static ==                    6/6   ✅
== range / conditional ==       4/4   ✅
== framing / keep-alive ==      4/4   ✅
== virtual host ==              2/2   ✅
== proxy / middleware ==        3/3   ✅
== rate limiting ==             4/4   ✅
─────────────────────────────────────
                              23/23
RESULT: 23 passed, 0 failed
```

## 第六步（可选）：与真实 Caddy 性能对比

### 6.1 启动 Caddy

```bash
cat > /tmp/caddy_bench.conf << 'EOF'
:8082 { root * /Users/audience/program/PPCA/network/minicaddy/www; file_server }
EOF
caddy run --config /tmp/caddy_bench.conf &
```

### 6.2 运行对比

```bash
# 生成测试文件
dd if=/dev/urandom of=www/_bench_16k.html bs=1024 count=16 2>/dev/null

# minicaddy
oha --no-tui -n 5000 -c 50 http://127.0.0.1:8080/_bench_16k.html

# Caddy
oha --no-tui -n 5000 -c 50 http://127.0.0.1:8082/_bench_16k.html
```

### 6.3 参考数据（Apple Silicon arm64, macOS 15）

| 文件 | minicaddy release | Caddy v2.11.4 | 差距 |
|------|-------------------|---------------|------|
| 1 KB   | ~18,000 req/s | ~36,000 req/s | 2.0× |
| 16 KB  | ~9,200 req/s  | ~38,000 req/s | 4.2× |
| 64 KB  | ~3,500 req/s  | ~35,000 req/s | 10.0× |

## 清理

```bash
pkill -f "target/release/minicaddy"
pkill -f "python3 -m http.server 9000"
pkill -f "caddy run"
rm -f www/_bench_*.html /tmp/caddy_bench.conf
```

## 代码导读（请求全链路）

1. **`main.rs:12-16`** → 加载 Caddyfile，调用 `run_all()`
2. **`config.rs:24`** → `from_caddyfile()` 解析 7 种指令 → `Vec<SiteConfig>`
3. **`inbounds/http.rs:160`** → `run_all()` 按端口分组，每端口一个 TCP listener
4. **`inbounds/http.rs:73`** → `serve_connection()` accept 循环，per-connection spawn
5. **`inbounds/http.rs:18`** → `handle_request()` 解析请求 → 路由 → 分发
6. **`inbounds/http.rs:39-44`** → Host 头匹配站点（优先精确匹配，fallback catch-all）
7. **`inbounds/http_files.rs:12`** → `file_server()` 静态文件（含 304/206/416/gzip）
8. **`inbounds/http_proxy.rs:11`** → `reverse_proxy()` 转发 upstream
9. **`inbounds/http.rs:86-102`** → keep-alive 循环：复用连接或 close
