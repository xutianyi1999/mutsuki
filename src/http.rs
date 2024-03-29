use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::option::Option::Some;
use std::sync::Arc;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use futures_util::TryFutureExt;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{http, Body, Client, Method, Request, Response, Server};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerConfig;

use crate::common::{load_tls_config, SocketExt};
use crate::http::tls::TlsAcceptor;
use crate::{Auth, BoxFuture, ProxyConfig, ProxyServer};

type HttpClient = Client<hyper::client::HttpConnector>;

pub struct HttpProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
}

impl ProxyServer for HttpProxyServer {
    fn start(self: Box<Self>) -> BoxFuture<io::Result<()>> {
        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build_http();

        let client = Arc::new(client);
        let bind_addr = self.bind_addr;
        let auth = self.auth;

        let make_service = make_service_fn(move |_| {
            let client = client.clone();
            let auth_op = auth.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    proxy(client.clone(), req, auth_op.clone())
                }))
            }
        });

        let server = Server::bind(&bind_addr)
            .tcp_keepalive(Some(Duration::from_secs(120)))
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(make_service);

        info!("Listening on http://{}", server.local_addr());

        Box::pin(server.map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
    }
}

impl HttpProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        HttpProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth.map(Arc::new),
        }
    }
}

pub struct HttpsProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
    tls_config: Arc<ServerConfig>,
}

impl ProxyServer for HttpsProxyServer {
    fn start(self: Box<Self>) -> BoxFuture<io::Result<()>> {
        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build_http();

        let client = Arc::new(client);
        let bind_addr = self.bind_addr;
        let auth = self.auth;
        let tls_config = self.tls_config;

        let fut = async move {
            let mut addr_incoming = AddrIncoming::bind(&bind_addr)?;
            addr_incoming.set_keepalive(Some(Duration::from_secs(120)));

            let acceptor = TlsAcceptor::new(tls_config, addr_incoming);

            let service = make_service_fn(move |_| {
                let client = client.clone();
                let auth = auth.clone();

                async move {
                    Ok::<_, io::Error>(service_fn(move |req| {
                        proxy(client.clone(), req, auth.clone())
                    }))
                }
            });

            let server = Server::builder(acceptor)
                .http1_preserve_header_case(true)
                .http1_title_case_headers(true)
                .serve(service);

            info!("Listening on https://{}", bind_addr);
            server.await
        };

        Box::pin(fut.map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
    }
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
}

async fn proxy(
    client: Arc<HttpClient>,
    req: Request<Body>,
    auth_opt: Option<Arc<Auth>>,
) -> io::Result<Response<Body>> {
    let res = async move {
        if !auth(auth_opt.as_deref(), &req)? {
            let mut resp = Response::new(Body::from("Authentication failed"));
            *resp.status_mut() = http::StatusCode::FORBIDDEN;
            return Ok::<Response<Body>, Box<dyn Error>>(resp);
        }

        if Method::CONNECT == req.method() {
            if let Some(addr) = host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    let res: Result<(), Box<dyn Error>> = async move {
                        let upgraded = hyper::upgrade::on(req).await?;
                        tunnel(upgraded, addr).await?;
                        Ok(())
                    }
                    .await;

                    if let Err(e) = res {
                        error!("{}", e)
                    }
                });
                Ok(Response::new(Body::empty()))
            } else {
                let mut resp = Response::new(Body::from("Connect must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
        } else {
            let res = client.request(req).await?;
            Ok(res)
        }
    };
    res.await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

async fn tunnel(mut upgraded: Upgraded, addr: String) -> io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    server.set_keepalive()?;
    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

fn auth(auth_opt: Option<&Auth>, req: &Request<Body>) -> Result<bool, Box<dyn Error>> {
    if let Some(auth) = auth_opt {
        let username = auth.username.as_str();
        let password = auth.password.as_str();

        match req.headers().get("Proxy-Authorization") {
            Some(head_value) => {
                let head_str = head_value.to_str()?;
                let (_, value) = sscanf::scanf!(head_str, "{} {}", str, str).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Parse Proxy-Authorization failed",
                    )
                })?;
                let username_and_password = String::from_utf8( STANDARD.decode(value)?)?;

                let mut res = username_and_password.split(':');

                let username_temp_op = res.next();
                let password_temp_op = res.next();

                match (username_temp_op, password_temp_op) {
                    (Some(username_temp), Some(password_temp)) => {
                        Ok(username_temp == username && password_temp == password)
                    }
                    _ => Ok(false),
                }
            }
            None => Ok(false),
        }
    } else {
        Ok(true)
    }
}

mod tls {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use futures_util::ready;
    use futures_util::Future;
    use hyper::server::accept::Accept;
    use hyper::server::conn::{AddrIncoming, AddrStream};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_rustls::rustls::ServerConfig;

    enum State {
        Handshaking(tokio_rustls::Accept<AddrStream>),
        Streaming(tokio_rustls::server::TlsStream<AddrStream>),
    }

    pub struct TlsStream {
        state: State,
    }

    impl TlsStream {
        fn new(accept: tokio_rustls::Accept<AddrStream>) -> TlsStream {
            TlsStream {
                state: State::Handshaking(accept),
            }
        }
    }

    impl AsyncRead for TlsStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<io::Result<()>> {
            let pin = self.get_mut();
            match pin.state {
                State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        pin.state = State::Streaming(stream);
                        result
                    }
                    Err(err) => Poll::Ready(Err(err)),
                },
                State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for TlsStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let pin = self.get_mut();
            match pin.state {
                State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_write(cx, buf);
                        pin.state = State::Streaming(stream);
                        result
                    }
                    Err(err) => Poll::Ready(Err(err)),
                },
                State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.state {
                State::Handshaking(_) => Poll::Ready(Ok(())),
                State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.state {
                State::Handshaking(_) => Poll::Ready(Ok(())),
                State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            }
        }
    }

    pub struct TlsAcceptor {
        acceptor: tokio_rustls::TlsAcceptor,
        incoming: AddrIncoming,
    }

    impl TlsAcceptor {
        pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
            TlsAcceptor {
                acceptor: tokio_rustls::TlsAcceptor::from(config),
                incoming,
            }
        }
    }

    impl Accept for TlsAcceptor {
        type Conn = TlsStream;
        type Error = io::Error;

        fn poll_accept(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
            let pin = self.get_mut();
            match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
                Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(pin.acceptor.accept(sock))))),
                Some(Err(e)) => Poll::Ready(Some(Err(e))),
                None => Poll::Ready(None),
            }
        }
    }
}
