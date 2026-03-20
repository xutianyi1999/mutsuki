# mutsuki

**语言 / Language:** [English](README.md) · 简体中文

基于 Rust 的代理服务器，支持 SOCKS5、HTTP 及 TLS。可配合规则文件实现分流：直连或经上游代理。

## 功能

- **协议**
  - `socks5` — SOCKS5 代理
  - `socks5_over_tls` — SOCKS5 over TLS
  - `http` — HTTP 代理（CONNECT）
  - `https` — HTTPS 代理（TLS）

- **认证** — 可选用户名/密码（SOCKS5 与 HTTP）

- **TLS** — `socks5_over_tls` 与 `https` 需自行提供服务端证书与私钥（本仓库不包含证书）。

- **分流**
  - `rules_file` — gfwlist / AutoProxy 风格规则文件路径
  - `upstream` — 上游代理 URL（`socks5://` 或 `http://`）。命中规则的请求走 upstream，其余直连。

- **多实例** — 配置为 JSON 数组，可同时运行多个不同协议/端口的代理。

## 使用

```bash
./mutsuki config.json
```

或通过 Cargo：

```bash
cargo run --release -- config.json
```

## 配置说明

配置文件为 JSON 数组，每个元素对应一个代理实例。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `protocol` | string | 是 | `socks5` / `socks5_over_tls` / `http` / `https` |
| `bind_addr` | string | 是 | 监听地址，如 `127.0.0.1:1080` |
| `auth` | object | 否 | `{"username": "user", "password": "pass"}` |
| `rules_file` | string | 否 | gfwlist 风格规则路径，与 `upstream` 配合做分流 |
| `upstream` | string | 否 | 上游代理：`socks5://[user:pass@]host:port` 或 `http://[user:pass@]host:port` |

使用 `socks5_over_tls` 或 `https` 时需额外配置 `server_cert_key`（证书与私钥路径）；可选 `client_cert_path` 做客户端证书校验。

### 规则文件

- 兼容 gfwlist / AutoProxy：空行、`!` 注释、`[` 开头的元数据行会被忽略。
- 支持域名与 IP 规则（如 `||example.com`、`||1.2.3.4`）。
- 仅当同时配置 `rules_file` 与 `upstream` 时生效：**命中规则**的请求走 upstream，其余直连。

### 示例配置

```json
[
  {
    "protocol": "socks5",
    "bind_addr": "127.0.0.1:1080",
    "rules_file": "/path/to/gfwlist.dat",
    "upstream": "socks5://127.0.0.1:10800"
  },
  {
    "protocol": "http",
    "bind_addr": "127.0.0.1:8080"
  }
]
```

更多示例见 `cfg-example/config.json`。

## 环境变量

- **`MUTSUKI_LOG`** — 日志级别，默认 `INFO`。例如：`MUTSUKI_LOG=debug ./mutsuki config.json`

## 构建

```bash
cargo build --release
```

产物：`target/release/mutsuki`（Windows 下为 `mutsuki.exe`）。

## 依赖与运行环境

- Rust 2021
- 主要依赖：tokio、hyper、rustls、adblock、fast-socks5；release 使用 LTO 与单 codegen-unit。
