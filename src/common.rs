use socket2::{Socket, TcpKeepalive};
use tokio::io::{Error, ErrorKind, Result};
use tokio::net::TcpStream;
use tokio::time::Duration;

pub trait OptionConvert<T> {
    fn option_to_res(self, msg: &str) -> Result<T>;
}

impl<T> OptionConvert<T> for Option<T> {
    fn option_to_res(self, msg: &str) -> Result<T> {
        option_convert(self, msg)
    }
}

pub trait StdResConvert<T, E> {
    fn res_convert(self, f: fn(E) -> String) -> Result<T>;
}

impl<T, E> StdResConvert<T, E> for std::result::Result<T, E> {
    fn res_convert(self, f: fn(E) -> String) -> Result<T> {
        std_res_convert(self, f)
    }
}

pub trait StdResAutoConvert<T, E: ToString> {
    fn res_auto_convert(self) -> Result<T>;
}

impl<T, E: ToString> StdResAutoConvert<T, E> for std::result::Result<T, E> {
    fn res_auto_convert(self) -> Result<T> {
        std_res_convert(self, |e| e.to_string())
    }
}

fn option_convert<T>(o: Option<T>, msg: &str) -> Result<T> {
    match o {
        Some(v) => Ok(v),
        None => Err(Error::new(ErrorKind::Other, msg))
    }
}

fn std_res_convert<T, E>(res: std::result::Result<T, E>, f: fn(E) -> String) -> Result<T> {
    match res {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = f(e);
            Err(Error::new(ErrorKind::Other, msg))
        }
    }
}

pub trait TcpSocketExt {
    fn set_keepalive(&self) -> tokio::io::Result<()>;
}

impl TcpSocketExt for TcpStream {
    fn set_keepalive(&self) -> tokio::io::Result<()> {
        set_keepalive(self)
    }
}


const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(target_os = "windows")]
fn set_keepalive<S: std::os::windows::io::AsRawSocket>(socket: &S) -> tokio::io::Result<()> {
    use std::os::windows::io::FromRawSocket;

    unsafe {
        let socket = Socket::from_raw_socket(socket.as_raw_socket());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_keepalive<S: std::os::unix::io::AsRawFd>(socket: &S) -> tokio::io::Result<()> {
    use std::os::unix::io::FromRawFd;

    unsafe {
        let socket = Socket::from_raw_fd(socket.as_raw_fd());
        socket.set_tcp_keepalive(&TCP_KEEPALIVE)?;
        std::mem::forget(socket);
    };
    Ok(())
}