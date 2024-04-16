#[macro_use]
extern crate log;

use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::{env, io};

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use mimalloc::MiMalloc;
use serde::Deserialize;
use tokio::fs;

mod common;
mod http;
mod socks5;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "invalid command"))?;
    let json = fs::read(config_path).await?;
    let config_list: Vec<ProxyConfig> = serde_json::from_slice(&json)?;

    let mut join_list = Vec::with_capacity(config_list.len());

    for config in config_list {
        let handle = tokio::spawn(async move {
            let bind_addr = config.bind_addr;

            if let Err(e) = match_server(config).await {
                error!("server {} error: {}", bind_addr, e);
            }
        });

        join_list.push(handle)
    }

    for h in join_list {
        if let Err(e) = h.await {
            error!("server error: {}", e)
        }
    }
    Ok(())
}

async fn match_server(config: ProxyConfig) -> io::Result<()> {
    match config.protocol.as_str() {
        "socks5" => socks5::Socks5ProxyServer::new(config).start().await,
        "socks5_over_tls" => {
            socks5::Socks5OverTlsProxyServer::new(config)
                .await?
                .start()
                .await
        }
        "http" => http::HttpProxyServer::new(config).start().await,
        "https" => http::HttpsProxyServer::new(config).await?.start().await,
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid proxy protocol",
        )),
    }
}

fn logger_init() -> Result<(), Box<dyn Error>> {
    let pattern = if cfg!(debug_assertions) {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {f}:{L} - {m}{n}"
    } else {
        "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}"
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(
            Root::builder()
                .appender("stdout")
                .build(LevelFilter::from_str(
                    std::env::var("MUTSUKI_LOG").as_deref().unwrap_or("INFO"),
                )?),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}
