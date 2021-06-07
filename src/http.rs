use std::convert::Infallible;
use std::io;
use std::option::Option::Some;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{FutureExt, Stream, TryFutureExt};
use hyper::{Body, Client, http, Method, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use tokio::io::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;

use async_stream::stream;

use crate::{Auth, Http};
use crate::common::{StdResAutoConvert, TcpSocketExt};

type HttpClient = Client<hyper::client::HttpConnector>;

struct HttpProxyServer {}

pub async fn http_server_start(
    config: Http,
    tls_config: Option<ServerConfig>,
) -> Result<()> {
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let auth_opt = config.auth;

    let make_service = make_service_fn(move |_| {
        let client = client.clone();

        async move {
            Ok::<_, Infallible>(
                service_fn(move |req| proxy(
                    client.clone(),
                    req,
                    None,
                ))
            )
        }
    });

    match tls_config {
        Some(tls_config) => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            let tcp = TcpListener::bind(config.bind_addr).await?;

            let incoming_tls_stream = stream! {
                loop {
                    let (socket, _) = tcp.accept().await?;
                      let stream = acceptor.accept(socket).map_err(|e| {
                        println!("[!] Voluntary server halt due to client-connection error...");
                        // Errors could be handled here, instead of server aborting.
                        // Ok(None)
                        error(format!("TLS Error: {:?}", e))
                    });
                    yield stream.await;
                }
            };
            // Server::builder(HyperAcceptor {
            //     acceptor: Box::pin(incoming_tls_stream),
            // })
            //     .http1_preserve_header_case(true)
            //     .http1_title_case_headers(true)
            //     .serve(make_service).await;
        }
        None => {
            Server::bind(&config.bind_addr)
                .http1_preserve_header_case(true)
                .http1_title_case_headers(true)
                .serve(make_service).await;
        }
    };
    Ok(())
    // info!("Listening on http://{}", server.local_addr());
    // server.await.res_auto_convert()
}

async fn proxy(
    client: HttpClient,
    req: Request<Body>,
    auth_opt: Option<Auth>,
) -> Result<Response<Body>> {
    if !auth(auth_opt, &req)? {
        let mut resp = Response::new(Body::from("Authentication failed"));
        *resp.status_mut() = http::StatusCode::FORBIDDEN;
        return Ok(resp);
    }

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                let res = async move {
                    let upgraded = hyper::upgrade::on(req).await.res_auto_convert()?;
                    tunnel(upgraded, addr).await
                };

                if let Err(e) = res.await {
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
        client.request(req).await.res_auto_convert()
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

async fn tunnel(mut upgraded: Upgraded, addr: String) -> Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    server.set_keepalive()?;
    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

fn auth(
    auth_opt: Option<Auth>,
    req: &Request<Body>,
) -> Result<bool> {
    if let Some(auth) = auth_opt {
        let username = auth.username;
        let password = auth.password;

        match req.headers().get("Proxy-Authorization") {
            Some(head_value) => {
                let head_str = head_value.to_str().res_auto_convert()?;
                let slice = &head_str[6..];
                let username_and_password = String::from_utf8(
                    base64::decode(slice).res_auto_convert()?
                ).res_auto_convert()?;

                let mut res = username_and_password.split(':');

                let username_temp_op = res.next();
                let password_temp_op = res.next();

                if username_temp_op.is_some() && password_temp_op.is_some() {
                    let username_temp = username_temp_op.unwrap();
                    let password_temp = password_temp_op.unwrap();

                    if username_temp == username && password_temp == password {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            None => Ok(false)
        }
    } else {
        Ok(true)
    }
}

struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item=std::result::Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}

impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<std::result::Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

