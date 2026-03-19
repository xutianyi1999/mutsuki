//! Outbound connection: direct, via SOCKS5 upstream, or via HTTP CONNECT upstream.

use std::io;

use base64::Engine;
use fast_socks5::client::{Config as Socks5Config, Socks5Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parsed upstream proxy URL (socks5:// or http://).
#[derive(Clone)]
pub struct UpstreamConfig {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parse upstream URL: socks5://[user:pass@]host:port, http://[user:pass@]host:port.
pub fn parse_upstream(url: &str) -> io::Result<UpstreamConfig> {
    let parsed = url::Url::parse(url).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "socks5" && scheme != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream must be socks5:// or http://",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream missing host"))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or_else(|| if scheme == "socks5" { 1080 } else { 8080 });
    let (username, password) = match (parsed.username(), parsed.password()) {
        ("", None) => (None, None),
        (u, p) => {
            let user = if u.is_empty() { None } else { Some(u.to_string()) };
            (user, p.map(String::from))
        }
    };
    Ok(UpstreamConfig {
        scheme,
        host,
        port,
        username,
        password,
    })
}

/// Stream that can be either a direct TcpStream or a SOCKS5-wrapped stream.
/// Used for copy_bidirectional with the client stream.
pub enum OutboundStream {
    Direct(TcpStream),
    Socks5(Socks5Stream<TcpStream>),
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Direct(s) => TcpStream::poll_read(std::pin::Pin::new(s), cx, buf),
            OutboundStream::Socks5(s) => Socks5Stream::poll_read(std::pin::Pin::new(s), cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            OutboundStream::Direct(s) => TcpStream::poll_write(std::pin::Pin::new(s), cx, buf),
            OutboundStream::Socks5(s) => Socks5Stream::poll_write(std::pin::Pin::new(s), cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            OutboundStream::Direct(s) => TcpStream::poll_flush(std::pin::Pin::new(s), cx),
            OutboundStream::Socks5(s) => Socks5Stream::poll_flush(std::pin::Pin::new(s), cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            OutboundStream::Direct(s) => TcpStream::poll_shutdown(std::pin::Pin::new(s), cx),
            OutboundStream::Socks5(s) => Socks5Stream::poll_shutdown(std::pin::Pin::new(s), cx),
        }
    }
}

/// Connect to (host, port). If upstream is Some, connect via that proxy; otherwise direct.
pub async fn connect_target(
    upstream: Option<&UpstreamConfig>,
    host: &str,
    port: u16,
) -> io::Result<OutboundStream> {
    let Some(up) = upstream else {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(addr).await?;
        return Ok(OutboundStream::Direct(stream));
    };

    let proxy_addr = format!("{}:{}", up.host, up.port);

    if up.scheme == "socks5" {
        let config = Socks5Config::default();
        let socks_stream = match (&up.username, &up.password) {
            (Some(u), Some(p)) => {
                Socks5Stream::connect_with_password(
                    proxy_addr.clone(),
                    host.to_string(),
                    port,
                    u.clone(),
                    p.clone(),
                    config,
                )
                .await
            }
            _ => Socks5Stream::connect(proxy_addr, host.to_string(), port, config).await,
        }
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(OutboundStream::Socks5(socks_stream))
    } else {
        // HTTP CONNECT
        let mut stream = TcpStream::connect(&proxy_addr).await?;
        let auth_header = match (&up.username, &up.password) {
            (Some(u), Some(p)) => {
                let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, p));
                format!("\r\nProxy-Authorization: Basic {}", cred)
            }
            _ => String::new(),
        };
        let request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}{}\r\n\r\n",
            host,
            port,
            host,
            port,
            auth_header
        );
        stream.write_all(request.as_bytes()).await?;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let response = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let status = response
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP CONNECT failed: {}", status),
            ));
        }
        Ok(OutboundStream::Direct(stream))
    }
}
