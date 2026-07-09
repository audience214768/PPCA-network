# 网络工具箱

[English version](network-toolkit.md)

> 自选项目 — 网络方向

## 概述

实现一套渐进式网络诊断工具，每个工具基于前一个的技能：

| 工具 | 分值 | 学习内容 |
|------|------|---------|
| **ping** | 2' | Raw socket, ICMP 包构造, checksum, RTT |
| **traceroute** | 3' | TTL 操控, ICMP 错误解析, 路径发现 |
| **recursive DNS resolver** | 5' | 二进制协议 (RFC 1035), 递归委派, 缓存 |

各子项目独立给分，可以只做其中一部分。

---

## 库限制

### 禁止使用

- 任何 DNS 库（`miekg/dns`、`golang.org/x/net/dns/dnsmessage` 等）
- `net.Resolver`、`net.LookupHost`、`net.LookupIP` 及所有 `net.Lookup*`
- `golang.org/x/net/icmp`（ICMP 包构造辅助）
- 第三方 ping/traceroute/DNS 库

### 允许使用

- `net.ListenPacket`、`net.DialUDP`、`net.UDPConn`、`net.IPConn` — 原始 socket 操作
- `golang.org/x/net/ipv4` — **仅限** `SetTTL()` / `SetControlMessage()`
- `encoding/binary`、`bytes`、`strings`、`fmt`、`os`、`time`、`sync`、`context`
- CLI 库（`flag`、`cobra` 等）
- 显示库（`tablewriter`、`bubbletea` 等）用于 bonus TUI

**重点是手动构造和解析数据包。如果一个库替你做了有趣的工作，你什么也没学到。**

---

## 第一层：Ping (2')

### 要实现的效果

```
$ sudo ./ping -c 4 google.com
PING google.com (142.250.80.46): 56 data bytes
64 bytes from 142.250.80.46: icmp_seq=0 ttl=116 time=3.42 ms
64 bytes from 142.250.80.46: icmp_seq=1 ttl=116 time=3.51 ms
64 bytes from 142.250.80.46: icmp_seq=2 ttl=116 time=3.38 ms
64 bytes from 142.250.80.46: icmp_seq=3 ttl=116 time=4.12 ms

--- google.com ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 3.38/3.61/4.12/0.30 ms
```

### 必须手写

- ICMP Echo Request 构造（Type=8, Code=0, Checksum, ID, Seq, Payload）
- ICMP Echo Reply 解析
- Checksum 计算（RFC 1071 — 反码求和）
- RTT 测量与统计（min/avg/max/stddev, 丢包率）

### 命令行接口

```
ping [options] <host>
  -c <count>      发送包数（默认：无限）
  -i <interval>   间隔秒数（默认：1.0）
  -s <size>       Payload 字节数（默认：56）
  -t <timeout>    每包超时秒数（默认：2.0）
```

### 注意事项

- 需要 root/sudo（或 Linux 上 `setcap cap_net_raw+ep`）
- 必须处理：超时、SIGINT（退出前打印统计）、ICMP 错误
- 使用唯一的 ICMP Identifier（如 PID）区分其他 ping 进程

---

## 第二层：Traceroute (3')

### 要实现的效果

```
$ sudo ./traceroute google.com
traceroute to google.com (142.250.80.46), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.345 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms  5.891 ms
 3  * * *
 ...
14  142.250.80.46 (142.250.80.46)  12.345 ms  12.123 ms  12.456 ms
```

### 必须手写

- **UDP 模式**：向高端口（33434+）发送递增 TTL 的 UDP 包；接收 ICMP Time Exceeded 或 Destination Unreachable
- **ICMP 模式**：发送递增 TTL 的 ICMP Echo；接收 Time Exceeded 或 Echo Reply
- 解析 ICMP 错误消息并提取**原始包头**（内层 IP + 8 字节传输层头）以匹配响应与探测
- 并发发送探测（不要逐个阻塞等待）

### 命令行接口

```
traceroute [options] <host>
  -m <max_hops>    最大 TTL（默认：30）
  -q <nqueries>    每跳探测数（默认：3）
  -w <timeout>     超时秒数（默认：3.0）
  -I               使用 ICMP Echo 模式（默认：UDP）
  -f <first_ttl>   起始 TTL（默认：1）
```

### 难点

将 ICMP 错误响应匹配回发出的探测。UDP 模式中每个探测使用不同目标端口。ICMP 错误的 payload 包含原始 UDP 头的前 8 字节（含 src/dst port）——用这些来关联。

---

## 第三层：递归 DNS 解析器 (5')

### 要实现的效果

一个 DNS 服务器，**从根域名服务器开始递归解析**（不转发到 8.8.8.8）。

```bash
# 终端 1
$ ./dnsresolver -port 5353

# 终端 2
$ dig @127.0.0.1 -p 5353 example.com A
;; ANSWER SECTION:
example.com.        86400   IN  A   93.184.216.34

$ dig @127.0.0.1 -p 5353 gmail.com MX
;; ANSWER SECTION:
gmail.com.          3600    IN  MX  5 gmail-smtp-in.l.google.com.
```

### 必须手写

**1. DNS Wire Format (RFC 1035)**

- Header 编解码（12 字节，所有 flag）
- Question 段（QNAME 为长度前缀标签，QTYPE，QCLASS）
- Resource Record 解析：NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA
- **名称压缩** — `0xC0` 开头的标签是指针；必须跟随指针（并检测循环）
- 按类型解析 RDATA：A (4B IPv4), AAAA (16B IPv6), CNAME/NS (域名), MX (preference + 域名), SOA (所有字段)

**2. 递归解析逻辑**

```
resolve(name, qtype):
    nameservers = root_servers
    loop:
        查询一个 nameserver
        如果有答案 → 返回
        如果 NXDOMAIN → 返回错误
        如果 NS referral:
            从 Authority 段获取新 NS 名称
            从 Additional 段获取 glue IP
            如果没有 glue → 递归解析 NS 名称
            nameservers = 新集合
            continue
        如果 CNAME → 跟随链
```

必须处理：
- 有 glue records 的 referral（Additional 段有 IP）
- 没有 glue 的 referral（必须递归解析 NS 名称）
- CNAME 链（跟随 → 解析目标，最大深度保护）
- 循环检测、超时、重试其他 nameserver

**3. 缓存**

- 按 (name, type, class) 缓存 RR，遵守 TTL
- 负缓存（NXDOMAIN）按 RFC 2308
- 并发安全（`sync.RWMutex` 或 `sync.Map`）

**4. 服务端**

- 监听可配置 UDP 端口（默认 5353）
- 并发处理查询（每个查询一个 goroutine）
- 正确格式响应（QR=1, 复制 ID, 包含 question 段）

### 命令行接口

```
dnsresolver [options]
  -port <port>     监听端口（默认：5353）
  -root <file>     Root hints 文件（默认：root.hints）
  -verbose         打印解析过程
```

### 提供给学生

- `network-toolkit/` 目录中的 `root.hints` 文件，用于启动递归 DNS 解析。

你需要自行创建 Go module、CLI 结构、packet parser 测试，以及你选择实现的工具所需的集成测试。

---

## Bonus（最多 +2'）

| Bonus | 分值 | 描述 |
|-------|------|------|
| MTR 模式 | +0.5 | 持续 traceroute，实时更新显示（丢包率、RTT 统计） |
| AS/GeoIP 标注 | +0.5 | 通过 DNS TXT 查询 `origin.asn.cymru.com`，显示每跳 ASN |
| TCP fallback (DNS) | +0.5 | 响应 TC=1 时通过 TCP 重试 |
| 查询合并 | +0.5 | 去重并发相同查询 |
| EDNS0 | +0.5 | 支持 OPT pseudo-RR 以增大 UDP payload |
| Paris-traceroute | +0.5 | 固定 flow ID 避免 ECMP 路径变化 |

最多 bonus：**+2'**（任选组合）。

---

## 环境

- **Linux**：`sudo` 或 `setcap cap_net_raw+ep ./binary`（ping/traceroute）
- **macOS**：需要 `sudo`
- **DNS resolver**：不需要特权（只是高端口 UDP）

建议在 Linux 上开发（VM、带 `--cap-add=NET_RAW` 的容器、或 WSL2）。
