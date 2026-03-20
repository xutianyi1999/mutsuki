# mutsuki

**Language / 语言:** English · [简体中文](README.zh-CN.md)

A Rust proxy server supporting SOCKS5, HTTP, and TLS. Use a rules file to split traffic: direct or via an upstream proxy.

## Features

- **Protocols**
  - `socks5` — SOCKS5 proxy
  - `socks5_over_tls` — SOCKS5 over TLS
  - `http` — HTTP proxy (CONNECT)
  - `https` — HTTPS proxy (TLS)

- **Auth** — Optional username/password (SOCKS5 and HTTP)

- **TLS** — For `socks5_over_tls` and `https` you provide your own server certificate and key (no certs shipped).

- **Traffic split**
  - `rules_file` — gfwlist / AutoProxy-style rules path
  - `upstream` — Upstream proxy URL (`socks5://` or `http://`). Requests matching rules use upstream; others go direct.

- **Multi-instance** — Config is a JSON array; run multiple proxies (different protocols/ports) at once.

## Usage

```bash
./mutsuki config.json
```

Or with Cargo:

```bash
cargo run --release -- config.json
```

## Configuration

Config file is a JSON array; each element is one proxy instance.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol` | string | yes | `socks5` / `socks5_over_tls` / `http` / `https` |
| `bind_addr` | string | yes | Listen address, e.g. `127.0.0.1:1080` |
| `auth` | object | no | `{"username": "user", "password": "pass"}` |
| `rules_file` | string | no | Path to gfwlist-style rules; used with `upstream` for split |
| `upstream` | string | no | Upstream proxy: `socks5://[user:pass@]host:port` or `http://[user:pass@]host:port` |

For `socks5_over_tls` and `https` you must add `server_cert_key` with your cert and private key paths; optional `client_cert_path` for client certificate verification.

### Rules file

- gfwlist / AutoProxy compatible: empty lines, `!` comments, and `[` metadata lines are ignored.
- Supports domain and IP rules (e.g. `||example.com`, `||1.2.3.4`).
- Only used when both `rules_file` and `upstream` are set: **matched** requests go via upstream, others direct.

### Example config

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

See `cfg-example/config.json` for more.

## Environment

- **`MUTSUKI_LOG`** — Log level, default `INFO`. Example: `MUTSUKI_LOG=debug ./mutsuki config.json`

## Build

```bash
cargo build --release
```

Binary: `target/release/mutsuki` (or `mutsuki.exe` on Windows).

## Requirements

- Rust 2021
- Main deps: tokio, hyper, rustls, adblock, fast-socks5; release uses LTO and single codegen-unit.
