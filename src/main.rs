#[macro_use]
extern crate log;

use std::env;
use std::net::SocketAddr;

use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use serde::Deserialize;
use tokio::io::Result;

use crate::common::{OptionConvert, StdResAutoConvert};

mod socks5;
mod common;
mod http;

#[tokio::main]
async fn main() -> Result<()> {
    logger_init()?;

    if let Err(e) = process().await {
        error!("{}", e)
    }
    Ok(())
}

async fn process() -> Result<()> {
    let mut args = env::args();
    args.next();

    let config_path = args.next().option_to_res("Command invalid")?;

    let json_str = tokio::fs::read_to_string(config_path).await?;
    let config: ProxyConfig = serde_json::from_str(&json_str)?;

    let socks5 = config.socks5;
    let http = config.http;

    let f1 = async move {
        match socks5 {
            Some(config) => socks5::socks5_server_start(config).await,
            None => Ok(())
        }
    };

    let f2 = async move {
        match http {
            Some(config) => http::http_server_start(config).await,
            None => Ok(())
        }
    };

    tokio::try_join!(f1, f2)?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ProxyConfig {
    socks5: Option<Socks5Config>,
    http: Option<HttpConfig>,
}

#[derive(Deserialize, Clone)]
pub struct Socks5Config {
    bind_addr: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct HttpConfig {
    bind_addr: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}")))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .res_auto_convert()?;

    log4rs::init_config(config).res_auto_convert()?;
    Ok(())
}