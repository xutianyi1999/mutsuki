use std::io;
use std::net::SocketAddr;
use std::option::Option::Some;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::{Either, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{http, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::common::{load_tls_config, SocketExt};
use crate::{Auth, ProxyConfig};

fn auth<T>(auth_opt: Option<&Auth>, req: &Request<T>) -> Result<(), StatusCode> {
    if let Some(auth) = auth_opt {
        let username = auth.username.as_str();
        let password = auth.password.as_str();

        match req.headers().get(http::header::PROXY_AUTHORIZATION) {
            Some(head_value) => {
                let head_str = head_value.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
                let Ok((_, credentials)) = sscanf::scanf!(head_str, "{} {}", str, str) else {
                    return Err(StatusCode::BAD_REQUEST);
                };
                let credentials = String::from_utf8(
                    STANDARD
                        .decode(credentials)
                        .map_err(|_| StatusCode::BAD_REQUEST)?,
                )
                .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut list = credentials.split(':');

                let req_username_op = list.next();
                let req_password_op = list.next();

                match (req_username_op, req_password_op) {
                    (Some(req_username), Some(req_password)) => {
                        if req_username != username || req_password != password {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                    _ => return Err(StatusCode::BAD_REQUEST),
                }
            }
            None => return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED),
        }
    };
    Ok(())
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    auth_opt: Option<&Auth>,
) -> hyper::Result<Response<Either<Full<Bytes>, hyper::body::Incoming>>> {
    if let Err(resp_code) = auth(auth_opt.as_deref(), &req) {
        let mut resp = Response::new(Either::Left(Full::new(Bytes::new())));
        *resp.status_mut() = resp_code;
        return Ok(resp);
    }

    let Some(dst_addr) = req.uri().authority().map(|v| v.to_string()) else {
        let mut resp = Response::new(Either::Left(Full::new(Bytes::new())));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    };

    if Method::CONNECT == req.method() {
        tokio::spawn(async move {
            let res= async {
                let upgraded = hyper::upgrade::on(req).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let mut source_stream = TokioIo::new(upgraded);

                let mut dst_stream = TcpStream::connect(&dst_addr).await?;
                dst_stream.set_keepalive()?;

                tokio::io::copy_bidirectional(&mut source_stream, &mut dst_stream).await?;
                Ok::<_, io::Error>(())
            }
            .await;

            if let Err(e) = res {
                error!("proxy error: {}; peer: {}", e, dst_addr);
            }
        });
        Ok(Response::new(Either::Left(Full::new(Bytes::new()))))
    } else {
        let fut = async {
            let stream = TcpStream::connect(dst_addr).await?;
            stream.set_keepalive()?;
            let io = TokioIo::new(stream);

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            tokio::spawn(conn);

            sender
                .send_request(req)
                .await
                .map(|v| v.map(|v| Either::Right(v)))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        };

        match fut.await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let mut resp = Response::new(Either::Left(Full::new(Bytes::from(e.to_string()))));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                Ok(resp)
            }
        }
    }
}

pub struct HttpProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
}

async fn child<RW: 'static + AsyncRead + AsyncWrite + Unpin + Send>(
    auth_opt: Option<Arc<Auth>>,
    source: RW,
) -> io::Result<()> {
    let io = TokioIo::new(source);
    let auth_opt = auth_opt.as_deref();

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service_fn(move |req| proxy(req, auth_opt)))
        .with_upgrades()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(())
}

async fn server_start(
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
    tls_acceptor: Option<TlsAcceptor>,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let fut = async {
                stream.set_keepalive()?;

                match tls_acceptor {
                    None => child(auth, stream).await,
                    Some(acceptor) => {
                        let stream = acceptor.accept(stream).await?;
                        child(auth, stream).await
                    }
                }
            };

            if let Err(e) = fut.await {
                error!("http server error: {}; bind: {}; peer: {}", e, bind_addr, peer);
            }
        });
    }
}

impl HttpProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        HttpProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth.map(Arc::new),
        }
    }

    pub async fn start(self) -> io::Result<()> {
        info!("listening on http://{}", self.bind_addr);
        server_start(self.bind_addr, self.auth, None).await
    }
}

pub struct HttpsProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
    tls_config: Arc<ServerConfig>,
}

impl HttpsProxyServer {
    pub async fn new(config: ProxyConfig) -> io::Result<Self> {
        let server_cert_key = config
            .server_cert_key
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Server certificate is missing"))?;
        let tls_config = load_tls_config(server_cert_key, config.client_cert_path).await?;

        let https_proxy_server = HttpsProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth.map(Arc::new),
            tls_config: Arc::new(tls_config),
        };
        Ok(https_proxy_server)
    }

    pub async fn start(self) -> io::Result<()> {
        info!("listening on https://{}", self.bind_addr);
        let tls_acceptor = TlsAcceptor::from(self.tls_config);
        server_start(self.bind_addr, self.auth, Some(tls_acceptor)).await
    }
}
