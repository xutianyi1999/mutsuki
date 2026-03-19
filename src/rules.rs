//! Rule loading and matching for traffic split (gfwlist / AutoProxy style).
//! Compatible with gfwlist.dat: skip empty lines, `!` comments, `[` metadata.
//! Rules can match both domain names and IP addresses (e.g. `||example.com`, `||1.2.3.4`).
//! RuleMatcher runs the adblock Engine in a dedicated thread (Engine is !Send).

use std::io;
use std::sync::mpsc;
use std::thread;

use adblock::Engine;
use adblock::lists::ParseOptions;
use adblock::request::Request;
use tokio::sync::oneshot;

/// Load rules from a gfwlist-style file (blocking, for use in matcher thread).
fn load_engine_blocking(path: &str) -> io::Result<Engine> {
    let content = std::fs::read_to_string(path)?;
    let rules: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with('!') && !line.starts_with('[')
        })
        .map(String::from)
        .collect();

    if rules.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no rules after filter"));
    }

    Ok(Engine::from_rules(rules, ParseOptions::default()))
}

/// Returns true if the host should be proxied (matched by rules).
pub fn matches_proxy_sync(engine: &Engine, host: &str) -> bool {
    let url = format!("https://{}/", host);
    let req = match Request::new(&url, "", "") {
        Ok(r) => r,
        Err(_) => return false,
    };
    engine.check_network_request(&req).matched
}

/// Send-safe rule matcher: runs the engine in a dedicated thread, answers via channel.
#[derive(Clone)]
pub struct RuleMatcher {
    tx: mpsc::Sender<(String, oneshot::Sender<bool>)>,
}

impl RuleMatcher {
    /// Start the matcher thread with the given rules file path. Returns None if load fails.
    pub fn start(path: String) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<(String, oneshot::Sender<bool>)>();
        let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
        thread::spawn(move || {
            match load_engine_blocking(&path) {
                Ok(engine) => {
                    let _ = ready_tx.send(Ok(()));
                    for (host, reply_tx) in rx.iter() {
                        let _ = reply_tx.send(matches_proxy_sync(&engine, &host));
                    }
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        });
        ready_rx.recv().map_err(|_| io::Error::new(io::ErrorKind::Other, "matcher thread died"))??;
        Ok(RuleMatcher { tx })
    }

    /// Returns true if the host should be proxied. Safe to call from any async context.
    pub async fn matches_proxy(&self, host: &str) -> bool {
        let tx = self.tx.clone();
        let host = host.to_string();
        tokio::task::spawn_blocking(move || {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send((host, reply_tx)).is_err() {
                return false;
            }
            reply_rx.blocking_recv().unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
}
