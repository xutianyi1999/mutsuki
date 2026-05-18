//! Rule loading and matching for traffic split (gfwlist / AutoProxy style).
//! Compatible with gfwlist.dat: skip empty lines, `!` comments, `[` metadata.
//! Rules can match both domain names and IP addresses (e.g. `||example.com`, `||1.2.3.4`).
//! RuleMatcher runs the adblock Engine in a dedicated thread (Engine is !Send).
//! The rules file is automatically watched for changes and hot-reloaded.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use adblock::Engine;
use adblock::lists::ParseOptions;
use adblock::request::Request;
use log::{error, info, warn};
use notify::{Event, EventKind, RecursiveMode, Watcher};
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
/// Automatically watches the rules file for changes and hot-reloads the engine.
#[derive(Clone)]
pub struct RuleMatcher {
    tx: mpsc::Sender<(String, oneshot::Sender<bool>)>,
}

impl RuleMatcher {
    /// Start the matcher thread with the given rules file path.
    /// The file is watched for changes and automatically reloaded on modification.
    pub fn start(path: String) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<(String, oneshot::Sender<bool>)>();
        let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
        let watch_path = PathBuf::from(&path);
        let file_name = watch_path.file_name().map(|n| n.to_os_string());

        const DEBOUNCE_MS: u64 = 500;

        thread::spawn(move || {
            let mut engine = match load_engine_blocking(&path) {
                Ok(engine) => {
                    let _ = ready_tx.send(Ok(()));
                    engine
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };

            // Set up file watcher for automatic hot-reload
            let (event_tx, event_rx) = mpsc::channel::<notify::Result<Event>>();
            let _watcher: Option<notify::RecommendedWatcher> =
                match notify::recommended_watcher(move |res| {
                    let _ = event_tx.send(res);
                }) {
                    Ok(mut w) => {
                        if let Some(parent) = watch_path.parent() {
                            let watch_dir = if parent.as_os_str().is_empty() {
                                PathBuf::from(".")
                            } else {
                                parent.to_path_buf()
                            };
                            if let Err(e) =
                                w.watch(&watch_dir, RecursiveMode::NonRecursive)
                            {
                                warn!("failed to watch directory {}: {}", watch_dir.display(), e);
                            } else {
                                info!("watching {} for rules file changes", watch_dir.display());
                            }
                        }
                        Some(w)
                    }
                    Err(e) => {
                        warn!("failed to create file watcher: {}; rules auto-reload disabled", e);
                        None
                    }
                };

            let mut last_reload = Instant::now();

            loop {
                // Process file change events (non-blocking)
                while let Ok(Ok(event)) = event_rx.try_recv() {
                    let is_target = |p: &PathBuf| -> bool {
                        p.file_name() == file_name.as_deref()
                    };
                    let changed = match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            event.paths.iter().any(is_target)
                        }
                        _ => false,
                    };
                    if changed {
                        let now = Instant::now();
                        if now < last_reload + Duration::from_millis(DEBOUNCE_MS) {
                            continue;
                        }
                        last_reload = now;
                        match load_engine_blocking(&path) {
                            Ok(new_engine) => {
                                engine = new_engine;
                                info!("rules file reloaded: {}", path);
                            }
                            Err(e) => {
                                error!("failed to reload rules file {}: {}", path, e);
                            }
                        }
                    }
                }

                // Process match queries with timeout to allow file event processing
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok((host, reply_tx)) => {
                        let _ = reply_tx.send(matches_proxy_sync(&engine, &host));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
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
