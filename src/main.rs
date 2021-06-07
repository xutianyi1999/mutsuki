#[macro_use]
extern crate log;

use std::{env, io};
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::net::SocketAddr;

use async_trait::async_trait;
use hyper::body::Buf;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio_rustls::rustls::{AllowAnyAuthenticatedClient, Certificate, NoClientAuth, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::rustls::internal::pemfile;

use crate::common::{OptionConvert, StdResAutoConvert};

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
    async fn start() -> Result<(), Box<dyn Error>>;
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

    let config_path = args.next().ok_or(io::Error::new(ErrorKind::Other, "Command invalid"))?;
    let json_str = tokio::fs::read_to_string(config_path).await?;
    let config_list: Vec<ProxyConfig> = serde_json::from_str(&json_str)?;

    for config in config_list {}
    Ok(())
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

fn load_tls_config(server_cert_key: ServerCertKey, client_cert_path: Option<String>) -> Result<ServerConfig, Box<dyn Error>> {
    let certs = load_certs(&server_cert_key.cert_path)?;
    let mut keys = load_keys(&server_cert_key.priv_key_path)?;

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config.set_single_cert(certs, keys.pop().ok_or(io::Error::new(ErrorKind::Other, "invalid key"))?)?;

    if let Some(cert_path) = client_cert_path {
        let mut client_cert = load_certs(&cert_path)?;

        let mut root = RootCertStore::empty();
        root.add(&client_cert.pop().ok_or(io::Error::new(ErrorKind::Other, "invalid cert"))?)?;

        tls_config.set_client_certificate_verifier(AllowAnyAuthenticatedClient::new(root));
    };
    Ok(tls_config)
}

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    pemfile::certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
