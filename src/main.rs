#[macro_use]
extern crate log;

use std::error::Error;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::{env, io};

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use serde::Deserialize;
use tokio::fs;

mod common;
mod http;
mod socks5;

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

type BoxFuture<V> = Pin<Box<dyn Future<Output = V> + Send>>;

pub trait ProxyServer {
    fn start(self: Box<Self>) -> BoxFuture<io::Result<()>>;
}

#[tokio::main]
async fn main() {
    logger_init().unwrap();

    if let Err(e) = process().await {
        error!("{}", e)
    }
}

async fn process() -> io::Result<()> {
    let mut args = env::args();
    args.next();

    let config_path = args
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Command invalid"))?;
    let json = fs::read(config_path).await?;
    let config_list: Vec<ProxyConfig> = serde_json::from_slice(&json)?;

    let mut join_list = Vec::with_capacity(config_list.len());

    for config in config_list {
        let handle = tokio::spawn(async move {
            let bind_addr = config.bind_addr;

            if let Err(e) = async move {
                let proxy_server = match_server(config).await?;
                proxy_server.start().await
            }
            .await
            {
                error!("{} -> {}", bind_addr, e)
            }

            error!("{} crashed", bind_addr);
        });

        join_list.push(handle)
    }

    for h in join_list {
        if let Err(e) = h.await {
            error!("{}", e)
        }
    }
    Ok(())
}

async fn match_server(config: ProxyConfig) -> io::Result<Box<dyn ProxyServer + Send>> {
    let p: Box<dyn ProxyServer + Send> = match config.protocol.as_str() {
        "socks5" => Box::new(socks5::Socks5ProxyServer::new(config)),
        "socks5_over_tls" => Box::new(socks5::Socks5OverTlsProxyServer::new(config).await?),
        "http" => Box::new(http::HttpProxyServer::new(config)),
        "https" => Box::new(http::HttpsProxyServer::new(config).await?),
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Invalid proxy protocol",
            ))
        }
    };
    Ok(p)
}

fn logger_init() -> Result<(), Box<dyn Error>> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}",
        )))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}
