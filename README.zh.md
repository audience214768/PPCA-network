# PPCA 2025 — 网络方向

[English version](README.md)

## 项目介绍

理解计算机网络的核心组件，学习使互联网运作的协议，亲手实现你日常会用到的网络工具。

## 重要说明

* PPCA 不是以内卷为目的的项目。遵守规则、完成必做任务，你不需要担心分数。
* 请选择你真正感兴趣的题目，而不是单纯为了绩点。
* 希望大家玩得开心。

## 语言

**Go**。环境配置见 [environment-setup.md](environment-setup.md)。

## 项目结构

今年采用**分层给分**制：一个必做任务 + 若干自选题目，各题目分值独立。所以你可以自由选择你感兴趣的项目。

---

## 必做 (5')

### SOCKS5 代理服务器

实现简单的 SOCKS5 代理服务器，支持 `CMD CONNECT`（TCP）。认证只需支持 `NO AUTH` (method `0x00`)。

详见 [socks5.zh.md](socks5.zh.md)。

**截止时间**：第一周结束前。

---

## 自选题目

从以下题目中选择，各题目分值独立累加。

---

### 1. 代理工具配置文件 (1')

使用**配置文件**（非 GUI）配置你喜欢的代理工具（sing-box / xray 等）。

要求：
- 提交配置文件及注释说明各字段含义
- 能在实际环境中正常使用

---

### 2. SOCKS5 UDP 支持 (4')

在你的 SOCKS5 服务器基础上实现 `CMD UDP ASSOCIATE`（RFC 1928）。

要求：
- 实现完整的 UDP 中继流程
- NAT 行为为 Full Cone 或 Symmetric
- 能通过标准 SOCKS5 客户端测试

---

### 3. TLS 劫持 (6')

实现类似 `mitmproxy` 的 HTTPS 流量劫持与检查。

要求：
- 动态生成受信任证书（自建 CA）
- 能解密并展示 HTTPS 请求/响应内容
- 作为代理透明处理客户端 HTTPS 请求

**BONUS (+2')**：用 TLS 劫持做一些有趣/有用的事——广告过滤、请求改写、安全审计等。发挥想象力。

---

### 4. 简单 frp (6')

实现简单的 [frp](https://github.com/fatedier/frp)（Fast Reverse Proxy），将内网机器端口映射到公网机器端口。

要求：
- 支持 TCP 和 UDP 转发
- mTLS 认证
- 带宽延迟合理

**BONUS 1 (+2')**：根据代理内容设计压缩协议。

**BONUS 2 (+2')**：frp 的 QUIC 传输层支持。

---

### 5. 网络工具箱

实现一套渐进式网络诊断工具：

| 子项目 | 分值 | 核心学习点 |
|--------|------|-----------|
| **ping** | 2' | Raw socket, ICMP 包构造与解析, RTT 测量 |
| **traceroute** | 3' | TTL 操控, ICMP 错误消息, 路径发现 |
| **recursive DNS resolver** | 5' | 二进制协议编解码, 递归解析, 缓存 |

各子项目独立给分，可只做其中一部分。

**关键约束**：必须手写 ICMP 包构造和 DNS wire format 编解码。详见 [network-toolkit.zh.md](network-toolkit.zh.md)。DNS resolver 需要的 root hints 文件在 [`network-toolkit/`](network-toolkit/) 目录。

---

### 6. QUIC 拥塞控制 (5')

在 `apernet/quic-go` 框架上实现自己的 QUIC 拥塞控制算法（CUBIC / BBR / 延迟驱动 / 自定义）。

要求：
- 只修改 `internal/cc/student.go`
- 在模拟网络环境下取得良好吞吐量和公平性
- 提交报告分析算法表现

详见 [quic-cc.zh.md](quic-cc.zh.md)。初始代码在 [`quic-cc-lab/`](quic-cc-lab/) 目录。

---

### 7. Mini Caddy

从 TCP socket 开始实现 [Caddy](https://caddyserver.com/) 风格的 Web 服务器。

| 组件 | 分值 | 内容 |
|------|------|------|
| **基础** | 6' | 手写 HTTP/1.1 解析与连接管理、静态文件服务、反向代理、虚拟主机、Caddyfile 配置 |
| **Bonus 1: 自动 HTTPS** | +4' | ACME HTTP-01 客户端，通过 Pebble 测试 |
| **Bonus 2: 中间件** | +3' | basicauth, rate limit, gzip, access log |
| **Bonus 3: HTTP/2** | +5' | HPACK, 流控, 多路复用 |

**关键约束**：禁止使用 `net/http` 服务端和第三方 HTTP 框架。详见 [minicaddy.zh.md](minicaddy.zh.md)。测试脚本和示例配置在 [`minicaddy/`](minicaddy/) 目录。

---

### 8. 修改现有代理软件

为现有开源代理工具（如 [sing-box](https://github.com/SagerNet/sing-box)、[Xray-core](https://github.com/XTLS/Xray-core) 等）贡献一个有意义的功能。

可选方向（选一个或自己提出）：
- 设计并实现**自定义代理协议**
- 编写新的**分流规则**（基于地理位置、域名列表、进程名等）
- 实现高级 **DNS 解析策略**（split DNS、条件转发等）
- 添加新的**传输层**
- 性能优化、可观测性或安全加固

**开始前**：你**必须**先和助教讨论你的方案。我们会一起确定范围，并根据复杂度分配分值（通常 4'–10'）。未经助教批准就开始的不计分。

提交要求：
- 有清晰 commit 的 fork
- 简短的说明文档：改了什么、为什么、怎么测试
- 展示功能端到端工作的 demo

---

### 9. 自选题目

有其他想实现的网络项目？向助教提出，评估工作量后给分。

---

## 分数计算

- **必做 (SOCKS5)**：5 分
- **自选题目**：各题目分值独立累加
- 代码质量、commit 规范、可用性会在 code review 中考量

## 致谢

感谢 2021 级 ACM 班 Alan Liang 为本项目奠定基础。
