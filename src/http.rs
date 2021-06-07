use std::convert::Infallible;
use std::time::Duration;

use hyper::{Body, Client, http, Method, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use tokio::io::Result;
use tokio::net::TcpStream;

use crate::common::{StdResAutoConvert, TcpSocketExt};
use crate::HttpConfig;

type HttpClient = Client<hyper::client::HttpConnector>;

pub async fn http_server_start(config: HttpConfig) -> Result<()> {
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let username_op = config.username;
    let password_op = config.password;

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let username_op = username_op.clone();
        let password_op = password_op.clone();

        async move {
            Ok::<_, Infallible>(
                service_fn(move |req| proxy(
                    client.clone(),
                    req,
                    username_op.clone(),
                    password_op.clone(),
                ))
            )
        }
    });

    let server = Server::bind(&config.bind_addr)
        .tcp_keepalive(Some(Duration::from_secs(120)))
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    info!("Listening on http://{}", server.local_addr());
    server.await.res_auto_convert()
}

async fn proxy(
    client: HttpClient,
    req: Request<Body>,
    username_op: Option<String>,
    password_op: Option<String>,
) -> Result<Response<Body>> {
    if !auth(username_op, password_op, &req)? {
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
    username_op: Option<String>,
    password_op: Option<String>,
    req: &Request<Body>,
) -> Result<bool> {
    if username_op.is_some() && password_op.is_some() {
        let username = username_op.unwrap();
        let password = password_op.unwrap();

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
