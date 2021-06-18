use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::result::Result::Err;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ErrorKind};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::{Auth, ProxyConfig, ProxyServer};
use crate::common::{load_tls_config, TcpSocketExt};

pub const SOCKS5_VERSION: u8 = 0x05;

const IPV4: u8 = 0x01;
const DOMAIN_NAME: u8 = 0x03;
const IPV6: u8 = 0x04;

pub struct Socks5ProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Auth>,
}

#[async_trait]
impl ProxyServer for Socks5ProxyServer {
    async fn start(self: Box<Self>) -> Result<(), Box<dyn Error>> {
        info!("Listening on socks5://{}", self.bind_addr);
        server_start(self.bind_addr, self.auth, None).await
    }
}

impl Socks5ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Socks5ProxyServer { bind_addr: config.bind_addr, auth: config.auth }
    }
}

pub struct Socks5OverTlsProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Auth>,
    tls_acceptor: TlsAcceptor,
}

#[async_trait]
impl ProxyServer for Socks5OverTlsProxyServer {
    async fn start(self: Box<Self>) -> Result<(), Box<dyn Error>> {
        info!("Listening on socks5 over tls://{}", self.bind_addr);
        server_start(self.bind_addr, self.auth, Some(self.tls_acceptor)).await
    }
}

impl Socks5OverTlsProxyServer {
    pub async fn new(config: ProxyConfig) -> Result<Self, Box<dyn Error>> {
        let server_cert_key = config.server_cert_key.ok_or(io::Error::new(ErrorKind::Other, "socks5 tls server_certificate certificate is missing"))?;
        let tls_config = load_tls_config(server_cert_key, config.client_cert_path).await?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let server = Socks5OverTlsProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth,
            tls_acceptor,
        };
        Ok(server)
    }
}

enum Socks5Addr {
    Ip(IpAddr),
    DomainName(String),
}

#[async_trait]
trait MsgWrite: AsyncWrite + Unpin {
    async fn write_msg<MSG: Encode + Send>(&mut self, msg: MSG) -> Result<(), Box<dyn Error>> {
        let mut buff = [0u8; 1024];
        let out = msg.encode(&mut buff)?;
        self.write_all(out).await?;
        Ok(())
    }
}

impl MsgWrite for TcpStream {}

impl MsgWrite for TlsStream<TcpStream> {}

#[async_trait]
trait Decode {
    type Output;
    async fn decode<R: AsyncRead + Unpin + Send>(rx: &mut R) -> Result<Self::Output, Box<dyn Error>>;
}

trait Encode {
    fn encode(self, buff: &mut [u8]) -> Result<&[u8], Box<dyn Error>>;
}

#[allow(dead_code)]
struct NegotiateRequest {
    version: u8,
    nmethods: u8,
    methods: Vec<u8>,
}

struct NegotiateResponse {
    version: u8,
    methods: u8,
}

#[async_trait]
impl Decode for NegotiateRequest {
    type Output = NegotiateRequest;

    async fn decode<R: AsyncRead + Unpin + Send>(rx: &mut R) -> Result<NegotiateRequest, Box<dyn Error>> {
        let mut buff = [0u8; 2];
        rx.read_exact(&mut buff).await?;

        let version = buff[0];
        let nmethods = buff[1];

        let mut methods = vec![0u8; nmethods as usize];
        rx.read_exact(&mut methods).await?;

        Ok(NegotiateRequest {
            version,
            nmethods,
            methods,
        })
    }
}

impl Encode for NegotiateResponse {
    fn encode(self, buff: &mut [u8]) -> Result<&[u8], Box<dyn Error>> {
        buff[0] = self.version;
        buff[1] = self.methods;
        Ok(&buff[..2])
    }
}

async fn negotiate<RW: AsyncRead + MsgWrite + Send>(stream: &mut RW, is_auth: bool) -> Result<(), Box<dyn Error>> {
    let no_auth = 0x00;
    let auth = 0x02;
    let no_acceptable_methods = 0xff;

    let negotiate_req = NegotiateRequest::decode(stream).await?;

    if negotiate_req.version != SOCKS5_VERSION {
        return Err(Box::new(io::Error::new(ErrorKind::Other, "Invalid protocol version")));
    };

    let op = if is_auth {
        if negotiate_req.methods.contains(&auth) {
            Some(auth)
        } else {
            None
        }
    } else {
        if negotiate_req.methods.contains(&no_auth) {
            Some(no_auth)
        } else {
            None
        }
    };

    match op {
        Some(code) => {
            let msg = NegotiateResponse {
                version: SOCKS5_VERSION,
                methods: code,
            };
            stream.write_msg(msg).await
        }
        None => {
            let msg = NegotiateResponse {
                version: SOCKS5_VERSION,
                methods: no_acceptable_methods,
            };

            stream.write_msg(msg).await?;
            Err(Box::new(io::Error::new(ErrorKind::Other, "No acceptable methods")))
        }
    }
}

#[allow(dead_code)]
struct AuthRequest {
    version: u8,
    username_len: u8,
    username: String,
    password_len: u8,
    password: String,
}

struct AuthResponse {
    version: u8,
    status: u8,
}

#[async_trait]
impl Decode for AuthRequest {
    type Output = AuthRequest;

    async fn decode<R: AsyncRead + Unpin + Send>(rx: &mut R) -> Result<AuthRequest, Box<dyn Error>> {
        let mut buff = [0u8; 2];
        rx.read_exact(&mut buff).await?;

        let version = buff[0];
        let username_len = buff[1];

        let mut username_buff = vec![0u8; username_len as usize];
        rx.read_exact(&mut username_buff).await?;
        let username = String::from_utf8(username_buff)?;

        let password_len = rx.read_u8().await?;
        let mut password_buff = vec![0u8; password_len as usize];
        rx.read_exact(&mut password_buff).await?;
        let password = String::from_utf8(password_buff)?;

        Ok(AuthRequest {
            version,
            username_len,
            username,
            password_len,
            password,
        })
    }
}

impl Encode for AuthResponse {
    fn encode(self, buff: &mut [u8]) -> Result<&[u8], Box<dyn Error>> {
        buff[0] = self.version;
        buff[1] = self.status;
        Ok(&buff[..2])
    }
}

async fn auth<RW: AsyncRead + MsgWrite + Send>(
    stream: &mut RW,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let version = 0x01;
    let success = 0x00;
    let failed = 0x01;

    let auth_request = AuthRequest::decode(stream).await?;

    if auth_request.version == version {
        if auth_request.username == username && auth_request.password == password {
            let msg = AuthResponse {
                version,
                status: success,
            };
            stream.write_msg(msg).await
        } else {
            let msg = AuthResponse {
                version,
                status: failed,
            };

            stream.write_msg(msg).await?;
            Err(Box::new(io::Error::new(ErrorKind::Other, "Authentication failed")))
        }
    } else {
        let msg = AuthResponse {
            version,
            status: failed,
        };

        stream.write_msg(msg).await?;
        Err(Box::new(io::Error::new(ErrorKind::Other, "Authentication version invalid")))
    }
}

#[allow(dead_code)]
struct AcceptRequest {
    version: u8,
    cmd: u8,
    rsv: u8,
    addr_type: u8,
    dest_addr: Socks5Addr,
    port: u16,
}

struct AcceptResponse {
    version: u8,
    rep: u8,
    rsv: u8,
    bind_addr_type: u8,
    bind_addr: Socks5Addr,
    bind_port: u16,
}

#[async_trait]
impl Decode for AcceptRequest {
    type Output = Option<AcceptRequest>;

    async fn decode<R: AsyncRead + Unpin + Send>(rx: &mut R) -> Result<Option<AcceptRequest>, Box<dyn Error>> {
        let mut request = [0u8; 4];
        rx.read_exact(&mut request).await?;

        let version = request[0];
        let cmd = request[1];
        let addr_type = request[3];

        let (dest_addr, port) = match addr_type {
            IPV4 => {
                let mut buff = [0u8; 4 + 2];
                rx.read_exact(&mut buff).await?;

                let mut addr_buff = [0u8; 4];
                let mut port_buff = [0u8; 2];

                addr_buff.copy_from_slice(&buff[..4]);
                port_buff.copy_from_slice(&buff[4..]);

                let dest_addr = IpAddr::from(addr_buff);
                let port = u16::from_be_bytes(port_buff);

                (Socks5Addr::Ip(dest_addr), port)
            }
            IPV6 => {
                let mut buff = [0u8; 16 + 2];
                rx.read_exact(&mut buff).await?;

                let mut addr_buff = [0u8; 16];
                let mut port_buff = [0u8; 2];

                addr_buff.copy_from_slice(&buff[..16]);
                port_buff.copy_from_slice(&buff[16..]);

                let dest_addr = IpAddr::from(addr_buff);
                let port = u16::from_be_bytes(port_buff);

                (Socks5Addr::Ip(dest_addr), port)
            }
            DOMAIN_NAME => {
                let len = rx.read_u8().await? as usize;
                let mut buff = vec![0u8; len + 2];

                rx.read_exact(&mut buff).await?;

                let domain_name = String::from_utf8(buff[..len].to_vec())?;

                let mut port_buff = [0u8; 2];
                port_buff.copy_from_slice(&buff[len..]);
                let port = u16::from_be_bytes(port_buff);

                (Socks5Addr::DomainName(domain_name), port)
            }
            _ => return Ok(None)
        };

        let req = AcceptRequest {
            version,
            cmd,
            rsv: 0x00,
            addr_type,
            dest_addr,
            port,
        };
        Ok(Some(req))
    }
}

impl Encode for AcceptResponse {
    fn encode(self, buff: &mut [u8]) -> Result<&[u8], Box<dyn Error>> {
        buff[0] = self.version;
        buff[1] = self.rep;
        buff[2] = self.rsv;
        buff[3] = self.bind_addr_type;

        let start = match self.bind_addr {
            Socks5Addr::Ip(ip) => {
                match ip {
                    IpAddr::V4(v4) => {
                        buff[4..8].copy_from_slice(&v4.octets());
                        8
                    }
                    IpAddr::V6(v6) => {
                        buff[4..20].copy_from_slice(&v6.octets());
                        20
                    }
                }
            }
            Socks5Addr::DomainName(domain_name) => {
                let domain_name_bytes = domain_name.as_bytes();
                let domain_name_len = domain_name_bytes.len();
                buff[4] = domain_name_len as u8;

                let end = 5 + domain_name_len;
                buff[5..end].copy_from_slice(domain_name_bytes);

                end
            }
        };

        buff[start..(start + 2)].copy_from_slice(&self.bind_port.to_be_bytes());
        Ok(&buff[..(start + 2)])
    }
}

async fn accept<RW: AsyncRead + MsgWrite + Send>(stream: &mut RW, peer_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let op = AcceptRequest::decode(stream).await?;

    let request = match op {
        Some(accept_request) => accept_request,
        None => {
            let address_type_not_supported = 0x08;
            let resp = build_err_resp(address_type_not_supported);
            stream.write_msg(resp).await?;
            return Err(Box::new(io::Error::new(ErrorKind::AddrNotAvailable, "Address type not supported")));
        }
    };

    if request.version != SOCKS5_VERSION {
        return Err(Box::new(io::Error::new(ErrorKind::Other, "Invalid protocol version")));
    }

    match request.cmd {
        // TCP
        0x01 => tcp_handle(stream, request).await?,
        // UDP
        0x03 => udp_handle(stream, peer_addr).await?,
        _ => {
            let cmd_not_supported = 0x07;
            let resp = build_err_resp(cmd_not_supported);
            stream.write_msg(resp).await?;
            return Err(Box::new(io::Error::new(ErrorKind::Other, "Cmd not supported")));
        }
    };
    Ok(())
}

async fn tcp_handle<RW: AsyncRead + MsgWrite + Send>(stream: &mut RW, request: AcceptRequest) -> Result<(), Box<dyn Error>> {
    let res = match request.dest_addr {
        Socks5Addr::Ip(ip) => TcpStream::connect((ip, request.port)).await,
        Socks5Addr::DomainName(domain_name) => TcpStream::connect((domain_name, request.port)).await
    };

    let mut dest_stream = match res {
        Ok(dest_stream) => dest_stream,
        Err(err) => {
            let err_code = match err.kind() {
                ErrorKind::NotFound | ErrorKind::NotConnected => 0x03,
                ErrorKind::PermissionDenied => 0x02,
                ErrorKind::ConnectionRefused => 0x05,
                ErrorKind::ConnectionAborted |
                ErrorKind::ConnectionReset |
                ErrorKind::TimedOut => 0x04,
                ErrorKind::AddrNotAvailable => 0x08,
                _ => 0x01,
            };

            let resp = build_err_resp(err_code);
            stream.write_msg(resp).await?;
            return Err(Box::new(err));
        }
    };

    dest_stream.set_keepalive()?;

    let success = 0x00;
    let local_addr = dest_stream.local_addr()?;

    let addr_type = match local_addr {
        SocketAddr::V4(_) => IPV4,
        SocketAddr::V6(_) => IPV6
    };

    let resp_msg = AcceptResponse {
        version: SOCKS5_VERSION,
        rep: success,
        rsv: 0x00,
        bind_addr_type: addr_type,
        bind_addr: Socks5Addr::Ip(local_addr.ip()),
        bind_port: local_addr.port(),
    };

    stream.write_msg(resp_msg).await?;
    tokio::io::copy_bidirectional(stream, &mut dest_stream).await?;
    Ok(())
}

struct UdpProxyPacket<'a> {
    rsv: u16,
    frag: u8,
    addr_type: u8,
    dest_addr: Socks5Addr,
    dest_port: u16,
    data: &'a [u8],
}

impl UdpProxyPacket<'_> {
    fn decode(packet: &[u8]) -> Result<UdpProxyPacket, Box<dyn Error>> {
        let frag = packet[2];
        let addr_type = packet[3];

        let (dest_addr, start) = match addr_type {
            IPV4 => {
                let mut ipv4_addr_buff = [0u8; 4];
                ipv4_addr_buff.copy_from_slice(&packet[4..8]);

                (Socks5Addr::Ip(IpAddr::from(ipv4_addr_buff)), 8)
            }
            IPV6 => {
                let mut ipv6_addr_buff = [0u8; 16];
                ipv6_addr_buff.copy_from_slice(&packet[4..20]);

                (Socks5Addr::Ip(IpAddr::from(ipv6_addr_buff)), 20)
            }
            DOMAIN_NAME => {
                let domain_name_len = packet[4] as usize;
                let mut domain_name_buff = vec![0u8; domain_name_len];
                let domain_end = 5 + domain_name_len;
                domain_name_buff.copy_from_slice(&packet[5..domain_end]);
                let domain_name = String::from_utf8(domain_name_buff)?;

                (Socks5Addr::DomainName(domain_name), domain_end)
            }
            _ => return Err(Box::new(io::Error::new(ErrorKind::AddrNotAvailable, "Address type not supported")))
        };

        let mut port_buff = [0u8; 2];
        port_buff.copy_from_slice(&packet[start..(start + 2)]);
        let dest_port = u16::from_be_bytes(port_buff);

        let data = &packet[(start + 2)..];

        Ok(UdpProxyPacket {
            rsv: 0x0000,
            frag,
            addr_type,
            dest_addr,
            dest_port,
            data,
        })
    }

    fn encode(self, buff: &mut [u8]) -> &[u8] {
        buff[0..2].copy_from_slice(&self.rsv.to_be_bytes());
        buff[2] = self.frag;
        buff[3] = self.addr_type;

        let start = match self.dest_addr {
            Socks5Addr::Ip(ip) => {
                match ip {
                    IpAddr::V4(v4) => {
                        buff[4..8].copy_from_slice(&v4.octets());
                        8
                    }
                    IpAddr::V6(v6) => {
                        buff[4..20].copy_from_slice(&v6.octets());
                        20
                    }
                }
            }
            Socks5Addr::DomainName(domain_name) => {
                let domain_name_bytes = domain_name.as_bytes();
                let domain_name_len = domain_name_bytes.len();
                buff[4] = domain_name_len as u8;

                let end = 5 + domain_name_len;
                buff[5..end].copy_from_slice(domain_name_bytes);

                end
            }
        };

        buff[start..(start + 2)].copy_from_slice(&self.dest_port.to_be_bytes());
        let end = start + 2 + self.data.len();
        buff[(start + 2)..end].copy_from_slice(self.data);

        &buff[..end]
    }
}

async fn udp_handle<RW: AsyncRead + MsgWrite + Send>(stream: &mut RW, peer_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let udp_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;

    let local_addr = udp_socket.local_addr()?;
    let local_to_peer_ip = get_interface_addr(peer_addr).await?;
    let success = 0x00;

    let addr_type = match local_to_peer_ip {
        IpAddr::V4(_) => IPV4,
        IpAddr::V6(_) => IPV6
    };

    let resp = AcceptResponse {
        version: SOCKS5_VERSION,
        rep: success,
        rsv: 0x00,
        bind_addr_type: addr_type,
        bind_addr: Socks5Addr::Ip(local_to_peer_ip),
        bind_port: local_addr.port(),
    };

    stream.write_msg(resp).await?;

    let f1 = async move {
        let _ = stream.read(&mut [0u8; 1]).await;
        Ok(())
    };

    let f2 = async move {
        let mut buff = vec![0u8; 65536];
        let mut out = vec![0u8; 65536];

        let (len, source_addr) = udp_socket.recv_from(&mut buff).await?;
        proxy_server_to_dest(&buff[..len], &udp_socket).await?;

        while let Ok((len, peer_addr)) = udp_socket.recv_from(&mut buff).await {
            if peer_addr == source_addr {
                proxy_server_to_dest(&buff[..len], &udp_socket).await?;
            } else {
                let addr_type = match peer_addr.ip() {
                    IpAddr::V4(_) => IPV4,
                    IpAddr::V6(_) => IPV6
                };

                let msg = UdpProxyPacket {
                    rsv: 0x0000,
                    frag: 0x00,
                    addr_type,
                    dest_addr: Socks5Addr::Ip(peer_addr.ip()),
                    dest_port: peer_addr.port(),
                    data: &buff[..len],
                }.encode(&mut out);

                udp_socket.send_to(msg, source_addr).await?;
            }
        }
        Ok(())
    };

    tokio::select! {
        res = f1 => res,
        res = f2 => res
    }
}

async fn proxy_server_to_dest(packet: &[u8], udp_socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let packet = UdpProxyPacket::decode(packet)?;

    match packet.dest_addr {
        Socks5Addr::Ip(ip) => udp_socket.send_to(packet.data, (ip, packet.dest_port)).await,
        Socks5Addr::DomainName(domain_name) => udp_socket.send_to(packet.data, (domain_name, packet.dest_port)).await
    }?;
    Ok(())
}

fn build_err_resp(rep: u8) -> AcceptResponse {
    AcceptResponse {
        version: SOCKS5_VERSION,
        rep,
        rsv: 0x00,
        bind_addr_type: IPV4,
        bind_addr: Socks5Addr::Ip(IpAddr::from([0, 0, 0, 0])),
        bind_port: 0,
    }
}

async fn get_interface_addr(dest_addr: SocketAddr) -> io::Result<IpAddr> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(dest_addr).await?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

async fn socks5_codec<RW: AsyncRead + MsgWrite + Send>(
    stream: &mut RW,
    peer_addr: SocketAddr,
    auth_op: Option<Auth>,
) -> Result<(), Box<dyn Error>> {
    negotiate(stream, auth_op.is_some()).await?;

    if let Some(auth_param) = auth_op {
        auth(stream, &auth_param.username, &auth_param.password).await?;
    };
    accept(stream, peer_addr).await
}

async fn server_start(
    bind_addr: SocketAddr,
    auth: Option<Auth>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(bind_addr).await?;

    while let Ok((mut stream, peer_addr)) = listener.accept().await {
        let auth = auth.clone();
        let tls_acceptor_op = tls_acceptor.clone();

        tokio::spawn(async move {
            let res = async move {
                match tls_acceptor_op {
                    Some(acceptor) => {
                        let mut tls_stream = acceptor.accept(stream).await?;
                        socks5_codec(&mut tls_stream, peer_addr, auth).await
                    }
                    None => socks5_codec(&mut stream, peer_addr, auth).await
                }
            }.await;

            if let Err(e) = res {
                error!("{} -> {}", peer_addr, e)
            }
        });
    }
    Ok(())
}
