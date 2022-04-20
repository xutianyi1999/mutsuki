use std::io;
use std::ops::{Deref, DerefMut};

use socket2::TcpKeepalive;
use tokio::fs;
use tokio::time::Duration;
use tokio_rustls::rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;

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
build_socket_ext!(std::os::windows::io::AsRawSocket);

#[cfg(unix)]
build_socket_ext!(std::os::unix::io::AsRawFd);

pub async fn load_tls_config(
    server_cert_key: ServerCertKey,
    client_cert_path: Option<String>,
) -> io::Result<ServerConfig> {
    let cert_future = load_certs(&server_cert_key.cert_path);
    let key_future = load_keys(&server_cert_key.priv_key_path);
    let (certs, mut keys) = tokio::try_join!(cert_future, key_future)?;

    let builder = ServerConfig::builder().with_safe_defaults();

    let builder = if let Some(cert_path) = client_cert_path {
        let mut client_cert = load_certs(&cert_path).await?;

        let mut root = RootCertStore::empty();
        root.add(
            &client_cert
                .pop()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?,
        )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        builder.with_client_cert_verifier(AllowAnyAuthenticatedClient::new(root))
    } else {
        builder.with_no_client_auth()
    };

    let key = keys
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
    let builder = builder
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(builder)
}

async fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    let certs_buff = fs::read(path).await?;
    let mut buff: &[u8] = &certs_buff;

    rustls_pemfile::certs(&mut buff).map(|certs| certs.into_iter().map(Certificate).collect())
}

async fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    let keys_buff = fs::read(path).await?;
    let mut buff: &[u8] = &keys_buff;

    rustls_pemfile::pkcs8_private_keys(&mut buff)
        .map(|keys| keys.into_iter().map(PrivateKey).collect())
}

#[derive(Copy)]
pub(crate) struct PointerWrap<T: ?Sized> {
    ptr: *mut T,
}

impl<T: ?Sized> PointerWrap<T> {
    pub fn new(ptr: &mut T) -> Self {
        PointerWrap { ptr }
    }
}

impl<T: ?Sized> Deref for PointerWrap<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T: ?Sized> DerefMut for PointerWrap<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T: ?Sized> Clone for PointerWrap<T> {
    fn clone(&self) -> Self {
        PointerWrap { ptr: self.ptr }
    }
}

unsafe impl<T: ?Sized> Send for PointerWrap<T> {}

unsafe impl<T: ?Sized> Sync for PointerWrap<T> {}
