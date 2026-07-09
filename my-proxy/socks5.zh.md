# SOCKS5 代理服务器

[English version](socks5.md)

## 任务要求

实现一个简单的 SOCKS5 代理服务器（RFC 1928）。

**必须支持：**
- 方法协商：`NO AUTHENTICATION REQUIRED`（方法 `0x00`）
- `CMD CONNECT`：建立 TCP 连接并在客户端与目标之间转发数据
- 地址类型：IPv4 (`0x01`)、域名 (`0x03`)、IPv6 (`0x04`)

**不要求：**
- `CMD BIND` 或 `CMD UDP ASSOCIATE`（UDP 是单独的自选题）
- 用户名/密码认证（method `0x02`）

## 测试方法

推荐使用 [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif) 将浏览器代理设为你的服务器，然后正常浏览网页。

```bash
./socks5-server -port 1080

curl -x socks5h://127.0.0.1:1080 http://example.com
curl -x socks5h://127.0.0.1:1080 https://www.google.com
curl -x socks5h://127.0.0.1:1080 http://ipv6.google.com
```

运行时打印目标地址有助于调试。

## 截止时间

第一周结束前。

## 评分标准 (5')

| 标准 | 分值 |
|------|------|
| 协议握手正确（方法协商 + 连接请求/响应） | 1.5 |
| TCP CONNECT 正常工作（能代理 HTTP 和 HTTPS） | 2.0 |
| 支持所有地址类型（IPv4 / 域名 / IPv6） | 0.5 |
| 并发处理多连接（goroutine per connection） | 0.5 |
| 错误处理与代码质量 | 0.5 |

## 参考资料

- [RFC 1928: SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
