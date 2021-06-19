use std::error::Error;
use std::io;

use socket2::{Socket, TcpKeepalive};
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_rustls::rustls::{AllowAnyAuthenticatedClient, Certificate, NoClientAuth, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::internal::pemfile;

use crate::ServerCertKey;

pub trait TcpSocketExt {
    fn set_keepalive(&self) -> tokio::io::Result<()>;
}

impl TcpSocketExt for TcpStream {
    fn set_keepalive(&self) -> tokio::io::Result<()> {
        set_keepalive(self)
    }
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(target_os = "windows")]
fn set_keepalive<S: std::os::windows::io::AsRawSocket>(socket: &S) -> tokio::io::Result<()> {
    use std::os::windows::io::FromRawSocket;

    unsafe {
        let socket = Socket::from_raw_socket(socket.as_raw_socket());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_keepalive<S: std::os::unix::io::AsRawFd>(socket: &S) -> tokio::io::Result<()> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let socket = Socket::from_raw_fd(socket.as_raw_fd());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

pub async fn load_tls_config(server_cert_key: ServerCertKey, client_cert_path: Option<String>) -> Result<ServerConfig, Box<dyn Error>> {
    let cert_future = load_certs(&server_cert_key.cert_path);
    let key_future = load_keys(&server_cert_key.priv_key_path);
    let (certs, mut keys) = tokio::try_join!(cert_future, key_future)?;

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config.set_single_cert(certs, keys.pop().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?)?;

    if let Some(cert_path) = client_cert_path {
        let mut client_cert = load_certs(&cert_path).await?;

        let mut root = RootCertStore::empty();
        root.add(&client_cert.pop().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?)?;

        tls_config.set_client_certificate_verifier(AllowAnyAuthenticatedClient::new(root));
    };
    Ok(tls_config)
}

async fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    let certs_buff = fs::read(path).await?;
    let mut buff: &[u8] = &certs_buff;

    pemfile::certs(&mut buff)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

async fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    let keys_buff = fs::read(path).await?;
    let mut buff: &[u8] = &keys_buff;

    pemfile::pkcs8_private_keys(&mut buff)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
