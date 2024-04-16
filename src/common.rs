use std::io;
use std::sync::Arc;

use socket2::TcpKeepalive;
use tokio::fs;
use tokio::time::Duration;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;

use crate::ServerCertKey;

pub trait SocketExt {
    fn set_keepalive(&self) -> io::Result<()>;
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

macro_rules! build_socket_ext {
    ($type:path) => {
        impl<T: $type> SocketExt for T {
            fn set_keepalive(&self) -> io::Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_tcp_keepalive(&TCP_KEEPALIVE)
            }
        }
    };
}

#[cfg(windows)]
build_socket_ext!(std::os::windows::io::AsSocket);

#[cfg(unix)]
build_socket_ext!(std::os::unix::io::AsFd);

pub async fn load_tls_config(
    server_cert_key: ServerCertKey,
    client_cert_path: Option<String>,
) -> io::Result<ServerConfig> {
    let cert_future = load_certs(&server_cert_key.cert_path);
    let key_future = load_keys(&server_cert_key.priv_key_path);
    let (certs, key) = tokio::try_join!(cert_future, key_future)?;

    let builder = ServerConfig::builder();
    let builder = if let Some(cert_path) = client_cert_path {
        let client_certs = load_certs(&cert_path).await?;
        let mut root = RootCertStore::empty();

        for client_cert in client_certs {
            root.add(client_cert)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        builder.with_client_cert_verifier(client_verifier)
    } else {
        builder.with_no_client_auth()
    };

    let key = key
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
    let server_config = builder
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(server_config)
}

async fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs_buff = fs::read(path).await?;
    let mut buff: &[u8] = &certs_buff;

    rustls_pemfile::certs(&mut buff).collect()
}

async fn load_keys(path: &str) -> io::Result<Option<PrivateKeyDer<'static>>> {
    let keys_buff = fs::read(path).await?;
    let mut buff: &[u8] = &keys_buff;

    rustls_pemfile::private_key(&mut buff)
}
