# VeloxVPN

> A lightweight, high-performance VPN / proxy client written in Rust — only VLESS, AnyTLS and TUIC, plus a simple local web UI.
>
> 用 Rust 编写的高性能、轻量级 VPN / 代理客户端 —— 只支持 VLESS、AnyTLS、TUIC 三种协议，并自带一个简洁的本地 Web 管理界面。

---

## Features / 特性

- **Only 3 protocols** — VLESS, AnyTLS, TUIC. No extra bloat. / 只支持 VLESS、AnyTLS、TUIC 三种协议，没有多余功能。
- **Simple local Web UI** — a browser-based panel (similar to a Cloud9-style web terminal) with two modules: **Subscription URL** and **Admin**, protected by a login (default `admin` / `admin1234`, changeable). / 简洁的本地 Web 管理界面，类似 Cloud9 风格的 Web 面板，包含**订阅地址**与**管理后台**两个模块，带登录保护（默认 `admin` / `admin1234`，可修改）。
- **Subscription in two formats** — raw `vless://`/`anytls://`/`tuic://` URIs and a ready-to-use **Clash / Mihomo** YAML (proxies + rules). / 订阅支持两种格式：原始链接和可直接导入的 **Clash / Mihomo** YAML（含节点与规则）。
- **Rust & async** — high performance, low memory footprint, memory-safe. / 基于 Rust 异步运行时，性能高、内存占用低、内存安全。
- **Random ports** — every inbound gets a randomly generated port **once at first startup, then fixed** (persisted in config). / 全部入站使用**随机端口**，**首次启动时生成一次，此后保持不变**（持久化到配置）。
- **Anti-blocking** — VLESS over **WS + Host header**, configurable **SNI / ALPN** for TLS/QUIC camouflage. / **抗封锁**：VLESS 走 **WS + Host 头**，可配置 **SNI / ALPN** 伪装。
- **Cross-platform** — Windows / macOS / Linux. / 跨平台：Windows / macOS / Linux。

## Protocol Support / 协议支持

| Protocol / 协议 | Inbound / 入站 | Outbound / 出站 |
| ---------------- | -------------- | ---------------- |
| VLESS           | ✅ via Cloudflare Quick Tunnel / 经 Cloudflare 快速隧道 | ✅ |
| AnyTLS          | ✅ own IP:port / 自有 IP 与端口 | ✅ |
| TUIC            | ✅ own IP:port / 自有 IP 与端口 | ✅ |

> **Only VLESS goes through the Cloudflare Quick Tunnel; AnyTLS and TUIC listen directly on the server's own IP and port.** / **只有 VLESS 走 Cloudflare 快速隧道，AnyTLS 和 TUIC 直接使用服务器自有 IP 与端口。**

## Exposure Model / 暴露模型

```
                          ┌────────────────────────────────┐
   VLESS  (127.0.0.1:local) ── cloudflared quick tunnel ──▶ xxx.trycloudflare.com
                          │                                │
   AnyTLS  (own IP:443/TCP)        ◀──── public ────        │
   TUIC    (own IP:443/UDP)        ◀──── public ────        │
                          └────────────────────────────────┘
```

- **VLESS** — listens on a local random port, transports over **WebSocket with a custom Host header**, and is published through a random `cloudflared` quick tunnel (trycloudflare.com, no login). / 监听本地随机端口，通过 **WebSocket + 自定义 Host 头**传输，并经随机 `cloudflared` 快速隧道发布（无需登录）。
- **AnyTLS & TUIC** — bind directly to the server's public IP on a **randomly assigned port (fixed after first startup)**, with custom **SNI / ALPN** for camouflage. / 直接绑定服务器公网 IP，使用**随机分配的端口（首次启动后固定）**，并设置 **SNI / ALPN** 伪装。
- Cloudflare Quick Tunnels proxy HTTP/WS/TCP only, which is why only TCP-based VLESS uses it; TUIC (QUIC/UDP) and AnyTLS cannot be exposed that way. / 快速隧道只转发 HTTP/WS/TCP，因此只有基于 TCP 的 VLESS 使用它；TUIC（QUIC/UDP）无法用此方式暴露。

### SNI & ALPN for anti-blocking / SNI 与 ALPN 抗封锁

Every inbound (AnyTLS / TUIC) supports custom **SNI** and **ALPN** so the TLS handshake mimics a normal website and resists active probing. / 每个入站（AnyTLS / TUIC）都支持自定义 **SNI** 和 **ALPN**，让 TLS 握手伪装成正常网站流量，抵抗主动探测。

| Field / 字段 | Example / 示例 | Purpose / 作用 |
| ------------- | -------------- | -------------- |
| `sni`       | `www.cloudflare.com` | The server name presented in TLS handshake / TLS 握手呈现的服务器名 |
| `alpn`      | `["h2", "http/1.1"]` | Application-layer protocols, mimicking a normal web server / 应用层协议，伪装普通网站 |

## Anti-blocking / 防封策略

### Applied by default / 默认启用

- **TLS 1.3 + standard cipher suites** for all protocols — the TLS config is uniform and conservative, avoiding unusual extensions that are easy to fingerprint. / 所有协议统一使用 **TLS 1.3 + 标准密码套件**，TLS 配置保持一致、保守，避免被指纹识别的特殊扩展。
- **SNI + ALPN camouflage** — every AnyTLS / TUIC inbound presents a decoy SNI and normal web ALPN during the handshake. / 每个 AnyTLS / TUIC 入站在握手时呈现伪装的 SNI 和正常的 Web ALPN。
- **VLESS over WebSocket + Host header** — wrapped inside Cloudflare Quick Tunnel, so the flow looks like ordinary WS/HTTP traffic through a CDN. / VLESS 使用 **WebSocket + Host 头**，经 Cloudflare 快速隧道封装，流量表现为经过 CDN 的普通 WS/HTTP。
- **TUIC over QUIC** — TLS 1.3 with `h3` ALPN and **BBR** congestion control, TCP + UDP relay (native datagram mode with 0-RTT full-cone UDP). / TUIC 基于 QUIC + TLS 1.3，`h3` ALPN，**BBR** 拥塞控制，支持 TCP 与 UDP 中继（native datagram 模式，0-RTT full-cone）。
- **Random fixed ports** — all inbounds use randomly assigned ports (fixed after first startup), avoiding the commonly monitored 443/80. / 所有入站使用随机分配端口（首次启动后固定），避开常见的 443/80 监测端口。

### Future / optional ideas (not implemented yet) / 后续可选（暂未实现）

| Idea / 思路 | Description / 说明 |
| ----------- | ------------------- |
| uTLS fingerprint mimicry | Mimic Chrome/Edge JA3/JA4 on outbound handshakes / 出站握手模仿 Chrome/Edge 的 TLS 指纹 |
| Clean IP / ASN | Prefer IPs not flagged by active probing (avoid hotspot datacenter segments) / 优先使用未被主动探测标记的干净 IP |
| Bandwidth limiting | Cap per-connection bandwidth to avoid QoS-based blocking / 限制每连接带宽，避免触发 QoS 封禁 |
| Per-IP connection limits | Limit connections per client IP to prevent abuse and probing / 限制单 IP 连接数，防滥用与探测 |
| AnyTLS via named Cloudflare tunnel | Tunnel AnyTLS (TCP/TLS) through Cloudflare with a custom domain too / 用自定义域名让 AnyTLS 也走 Cloudflare 隧道 |
| VLESS + Reality | Replace CF tunnel with VLESS Reality (hardest to detect) if a domain is available / 有域名时可换用 VLESS Reality，最难被识别 |

## Quick Start / 快速开始

```bash
cargo build --release
./target/release/veloxvpn --config config.json
```

Then open the web UI in your browser and log in: / 然后在浏览器打开 Web 界面并登录：

```
http://127.0.0.1:8080        # default login: admin / admin1234
```

- Default login is **`admin` / `admin1234`**; you can change the username & password after logging in (Admin → Account). / 默认账号 **`admin` / `admin1234`**，登录后可在「管理后台 → 账号」修改用户名和密码。
- If `cloudflared` is installed, a VLESS inbound with `via: "cf-quick-tunnel"` automatically opens a quick tunnel and its public `*.trycloudflare.com` hostname is written into the subscription. / 若本机装有 `cloudflared`，`via: "cf-quick-tunnel"` 的 VLESS 入站会自动开启快速隧道，并把 `*.trycloudflare.com` 公网域名写入订阅。

## Configuration / 配置

Create a `config.json` like this: / 配置示例 `config.json`：

```json
{
  "web": {
    "listen": "127.0.0.1:8080",
    "admin_token": "your-admin-token",
    "user": "admin",
    "password": "admin1234"
  },
  "subscription": {
    "enabled": true,
    "path": "/random-generated-path",
    "token": "random-generated-token"
  },
  "inbounds": [
    {
      "name": "vless-tunnel",
      "type": "vless",
      "listen": "127.0.0.1",
      "port": 0,
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "network": "ws",
      "host": "www.cloudflare.com",
      "path": "/random-ws-path",
      "via": "cf-quick-tunnel"
    },
    {
      "name": "anytls-main",
      "type": "anytls",
      "listen": "0.0.0.0",
      "port": 0,
      "password": "your-password",
      "sni": "www.cloudflare.com",
      "alpn": ["h2", "http/1.1"]
    },
    {
      "name": "tuic-main",
      "type": "tuic",
      "listen": "0.0.0.0",
      "port": 0,
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "password": "your-password",
      "sni": "www.cloudflare.com",
      "alpn": ["h3"]
    }
  ],
  "outbounds": [
    {
      "name": "my-vless",
      "type": "vless",
      "server": "example.com",
      "port": 443,
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    },
    {
      "name": "my-anytls",
      "type": "anytls",
      "server": "example.com",
      "port": 443,
      "password": "your-password"
    },
    {
      "name": "my-tuic",
      "type": "tuic",
      "server": "example.com",
      "port": 443,
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "password": "your-password",
      "sni": "www.cloudflare.com",
      "alpn": ["h3"]
    }
  ]
}
```

> `port: 0` means **auto-assign a random port at first startup and keep it fixed afterwards** (stored in config). / `port: 0` 表示首次启动时**自动分配一个随机端口，之后保持不变**（写入配置）。

## Web UI / Web 界面

VeloxVPN serves a minimal web panel on the address you configure (default `127.0.0.1:8080`). It has two modules: / VeloxVPN 在配置的地址（默认 `127.0.0.1:8080`）提供简洁的 Web 面板，包含两个模块：

### 1. Subscription URL / 订阅地址

- Provides a single subscription URL for clients to import all inbound nodes at once. / 提供给客户端一个统一的订阅地址，一键导入全部入站节点。
- Two formats, switchable in the UI / 两种格式，可在界面切换：
  - **Raw URIs** — plain `vless://` / `anytls://` / `tuic://` links (sing-box, v2rayN). / 原始链接，适合 sing-box / v2rayN。
  - **Clash / Mihomo** — a ready-to-use YAML with `proxies`, a `PROXY` select group and default rules (`GEOIP,CN,DIRECT` + `MATCH,PROXY`). Clash needs rules to route traffic through the proxy, so they are included. / 可直接导入 Clash/Mihomo 的 YAML，含 `proxies`、`PROXY` 选择组和默认规则（`GEOIP,CN,DIRECT` + `MATCH,PROXY`）。Clash 依赖规则路由流量到代理，因此内置规则。
- The subscription path/token is **randomly generated** when first started. / 订阅地址在首次启动时**随机生成**。
- The admin can **regenerate** the subscription URL at any time (old one becomes invalid). / 管理后台可随时**重新生成**订阅地址（旧地址随即失效）。
- URL param `?format=clash` returns the Clash YAML; default (no param) returns raw URIs. / 加 `?format=clash` 返回 Clash YAML，默认返回原始链接。

### 2. Admin / 管理后台

The admin module uses a **Cloud9-style IDE layout** (dark theme, reference: AWS Cloud9). / 管理后台采用 **Cloud9 风格布局**（深色主题，参考 AWS Cloud9）：

```
┌────────────────────────────────────────────────────────────┐
│  Toolbar: VeloxVPN   Nodes   Subscription   Status          │  ← top menu bar / 顶部菜单栏
├───────────┬────────────────────────────────────────────────┤
│  Sidebar  │  Inbound Nodes / 入站节点                       │
│  · VLESS  │  ┌──────────────────────────────────────────┐  │
│  · AnyTLS │  │  node card / 节点卡片 (type · addr · port) │  │  ← editor area / 编辑区
│  · TUIC   │  └──────────────────────────────────────────┘  │
│  · Add+   │  ┌──────────────────────────────────────────┐  │
│  · Sub URL│  │  node card / 节点卡片                     │  │
│           │  └──────────────────────────────────────────┘  │
├───────────┴────────────────────────────────────────────────┤
│  Terminal / logs · 实时连接日志                              │  ← bottom panel / 底部面板
└────────────────────────────────────────────────────────────┘
```

- **Top toolbar** — module switches: Nodes / Subscription / Status. / 顶部工具栏：节点 / 订阅 / 状态 模块切换。
- **Left sidebar** — inbound node list (VLESS / AnyTLS / TUIC) with an "Add" button. / 左侧边栏：入站节点列表，含「添加」按钮。
- **Center editor area** — node cards / detail editing forms, one tab per node. / 中间编辑区：节点卡片 / 详情编辑表单，每个节点一个标签页。
- **Bottom panel** — real-time connection logs like a terminal. / 底部面板：类似终端的实时连接日志。
- **Admin actions** — regenerate subscription URL, set SNI / ALPN, add / edit / delete nodes, view status. Ports are fixed after first startup and are **not** regenerated. / 管理操作：重新生成订阅地址、设置 SNI / ALPN、增删改节点、查看状态。端口在首次启动后固定，**不会重新生成**。

## Project Structure / 项目结构

```
veloxvpn/
├── src/
│   ├── main.rs          # Entry point / 程序入口
│   ├── lib.rs           # Library root / 库根
│   ├── config.rs        # Config parsing, random ports, subscription / 配置解析、随机端口、订阅
│   ├── tls.rs           # TLS identity + rustls/quinn configs / TLS 证书与配置
│   ├── util.rs          # Random helpers, self-signed cert, URI builders / 工具函数
│   ├── proxy/
│   │   ├── mod.rs       # Inbound lifecycle / 入站生命周期
│   │   ├── address.rs   # SOCKS-style target address / 目标地址解析
│   │   ├── vless.rs     # VLESS inbound + outbound (TCP / WS) / VLESS 出入站
│   │   ├── anytls.rs    # AnyTLS inbound + outbound / AnyTLS 出入站
│   │   └── tuic.rs      # TUIC inbound + outbound (QUIC) / TUIC 出入站
│   └── web/
│       ├── mod.rs       # Web server: subscription + admin API / Web 服务
│       └── ui.html      # Cloud9-style admin panel / Cloud9 风格管理界面
└── tests/
    └── end_to_end.rs    # Protocol + Web UI integration tests / 集成测试
```

## Development / 开发

```bash
cargo run -- --config config.json
```

Requirements: Rust stable (1.75+) / 环境要求：Rust stable（1.75+）

## License / 许可证

MIT
