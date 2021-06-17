#[macro_use]
extern crate log;

use std::{env, io};
use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;

use async_trait::async_trait;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio::fs;
use tokio_rustls::rustls::{AllowAnyAuthenticatedClient, Certificate, NoClientAuth, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::internal::pemfile;

mod socks5;
mod common;
mod http;

#[derive(Deserialize, Clone)]
pub struct ProxyConfig {
    protocol: String,
    bind_addr: SocketAddr,
    auth: Option<Auth>,
    server_cert_key: Option<ServerCertKey>,
    client_cert_path: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct ServerCertKey {
    cert_path: String,
    priv_key_path: String,
}

#[derive(Deserialize, Clone)]
pub struct Auth {
    username: String,
    password: String,
}

#[async_trait]
pub trait ProxyServer {
    async fn start(self: Box<Self>) -> Result<(), Box<dyn Error>>;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    logger_init()?;

    if let Err(e) = process().await {
        error!("{}", e)
    }
    Ok(())
}

async fn process() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();
    args.next();

    let config_path = args.next().ok_or(io::Error::new(ErrorKind::InvalidInput, "command invalid"))?;
    let json = fs::read(config_path).await?;
    let config_list: Vec<ProxyConfig> = serde_json::from_slice(&json)?;

    let mut join_list = Vec::with_capacity(config_list.len());

    for config in config_list {
        let f = async move {
            let bind_addr = config.bind_addr;

            if let Err(e) = async move { match_server(config).await?.start().await }.await {
                error!("{} -> {}", bind_addr, e)
            }

            error!("{} crashed", bind_addr);
        };
        join_list.push(f);
    }

    futures_util::future::join_all(join_list).await;
    Ok(())
}

async fn match_server(config: ProxyConfig) -> Result<Box<dyn ProxyServer>, Box<dyn Error>> {
    let p: Box<dyn ProxyServer> = match config.protocol.as_str() {
        "socks5" => Box::new(socks5::Socks5ProxyServer::new(config)),
        "socks5_over_tls" => Box::new(socks5::Socks5OverTlsProxyServer::new(config).await?),
        "http" => Box::new(http::HttpProxyServer::new(config)),
        "https" => Box::new(http::HttpsProxyServer::new(config).await?),
        _ => return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "invalid proxy protocol")))
    };
    Ok(p)
}

fn logger_init() -> Result<(), Box<dyn Error>> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}

pub async fn load_tls_config(server_cert_key: ServerCertKey, client_cert_path: Option<String>) -> Result<ServerConfig, Box<dyn Error>> {
    let cert_future = load_certs(&server_cert_key.cert_path);
    let key_future = load_keys(&server_cert_key.priv_key_path);
    let (certs, mut keys) = tokio::try_join!(cert_future, key_future)?;

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config.set_single_cert(certs, keys.pop().ok_or(io::Error::new(ErrorKind::InvalidInput, "invalid key"))?)?;

    if let Some(cert_path) = client_cert_path {
        let mut client_cert = load_certs(&cert_path).await?;

        let mut root = RootCertStore::empty();
        root.add(&client_cert.pop().ok_or(io::Error::new(ErrorKind::InvalidInput, "invalid cert"))?)?;

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
