use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::result::Result::Err;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ErrorKind};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

use crate::common::{load_tls_config, SocketExt};
use crate::{Auth,  ProxyConfig};

const SOCKS5_VERSION: u8 = 0x05;
const IPV4: u8 = 0x01;
const DOMAIN_NAME: u8 = 0x03;
const IPV6: u8 = 0x04;

macro_rules! get_mut {
    ($slice: expr, $index: expr, $error_msg: expr) => {
        $slice
            .get_mut($index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, $error_msg))?
    };
    ($slice: expr, $index: expr) => {
        get_mut!($slice, $index, "Decode failed")
    };
}

pub struct Socks5ProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
}

impl Socks5ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Socks5ProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth.map(Arc::new),
        }
    }

    pub async fn start(self) -> io::Result<()> {
        info!("listening on socks5://{}", self.bind_addr);
        server_start(self.bind_addr, self.auth, None).await
    }
}

pub struct Socks5OverTlsProxyServer {
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
    tls_acceptor: TlsAcceptor,
}

impl Socks5OverTlsProxyServer {
    pub async fn new(config: ProxyConfig) -> io::Result<Self> {
        let server_cert_key = config.server_cert_key.ok_or_else(|| {
            io::Error::new(ErrorKind::Other, "socks5 tls server certificate is missing")
        })?;
        let tls_config = load_tls_config(server_cert_key, config.client_cert_path).await?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let server = Socks5OverTlsProxyServer {
            bind_addr: config.bind_addr,
            auth: config.auth.map(Arc::new),
            tls_acceptor,
        };
        Ok(server)
    }

    pub async fn start(self) -> io::Result<()> {
        info!("listening on socks5_over_tls://{}", self.bind_addr);
        server_start(
            self.bind_addr,
            self.auth,
            Some(self.tls_acceptor),
        ).await
    }
}

enum Socks5Addr<'a> {
    Ip(IpAddr),
    DomainName(Cow<'a, str>),
}

trait Encode {
    fn encode(self, buff: &mut [u8]) -> &[u8];
}

#[allow(dead_code)]
struct NegotiateRequest<'a> {
    version: u8,
    nmethods: u8,
    methods: &'a [u8],
}

struct NegotiateResponse {
    version: u8,
    methods: u8,
}

impl<'a> NegotiateRequest<'a> {
    async fn decode<R: AsyncRead + Unpin>(
        rx: &mut R,
        buff: &'a mut [u8],
    ) -> io::Result<NegotiateRequest<'a>> {
        let mut temp_buff = [0u8; 2];
        rx.read_exact(&mut temp_buff).await?;

        let version = temp_buff[0];
        let nmethods = temp_buff[1];

        let methods = get_mut!(buff, ..nmethods as usize);
        rx.read_exact(methods).await?;

        Ok(NegotiateRequest {
            version,
            nmethods,
            methods,
        })
    }
}

impl Encode for NegotiateResponse {
    fn encode(self, buff: &mut [u8]) -> &[u8] {
        buff[0] = self.version;
        buff[1] = self.methods;
        &buff[..2]
    }
}

#[allow(dead_code)]
struct AuthRequest<'a> {
    version: u8,
    username_len: u8,
    username: Cow<'a, str>,
    password_len: u8,
    password: Cow<'a, str>,
}

struct AuthResponse {
    version: u8,
    status: u8,
}

impl<'a> AuthRequest<'a> {
    async fn decode<R: AsyncRead + Unpin>(
        rx: &mut R,
        buff: &'a mut [u8],
    ) -> io::Result<AuthRequest<'a>> {
        let mut temp_buff = [0u8; 2];
        rx.read_exact(&mut temp_buff).await?;

        let version = temp_buff[0];
        let username_len = temp_buff[1];

        let username_range = ..username_len as usize;
        let username_buff = get_mut!(buff, username_range, "Username too long");
        rx.read_exact(username_buff).await?;

        let password_len = rx.read_u8().await?;
        let password_range = username_len as usize..(username_len + password_len) as usize;
        let password_buff = get_mut!(&mut *buff, password_range.clone(), "Password too long");
        rx.read_exact(password_buff).await?;

        let username = String::from_utf8_lossy(&buff[username_range]);
        let password = String::from_utf8_lossy(&buff[password_range]);

        let auth_request = AuthRequest {
            version,
            username_len,
            username,
            password_len,
            password,
        };
        Ok(auth_request)
    }
}

impl Encode for AuthResponse {
    fn encode(self, buff: &mut [u8]) -> &[u8] {
        buff[0] = self.version;
        buff[1] = self.status;
        &buff[..2]
    }
}

#[allow(dead_code)]
struct AcceptRequest<'a> {
    version: u8,
    cmd: u8,
    rsv: u8,
    addr_type: u8,
    dest_addr: Socks5Addr<'a>,
    port: u16,
}

struct AcceptResponse<'a> {
    version: u8,
    rep: u8,
    rsv: u8,
    bind_addr_type: u8,
    bind_addr: Socks5Addr<'a>,
    bind_port: u16,
}

impl<'a> AcceptRequest<'a> {
    async fn decode<R: AsyncRead + Unpin>(
        rx: &mut R,
        buff: &'a mut [u8],
    ) -> io::Result<AcceptRequest<'a>> {
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
                let buff = get_mut!(buff, ..len + 2);

                rx.read_exact(buff).await?;

                let domain_name = String::from_utf8_lossy(&buff[..len]);

                let mut port_buff = [0u8; 2];
                port_buff.copy_from_slice(&buff[len..]);
                let port = u16::from_be_bytes(port_buff);

                (Socks5Addr::DomainName(domain_name), port)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Address type unsupported",
                ));
            }
        };

        let req = AcceptRequest {
            version,
            cmd,
            rsv: 0x00,
            addr_type,
            dest_addr,
            port,
        };
        Ok(req)
    }
}

impl Encode for AcceptResponse<'_> {
    fn encode(self, buff: &mut [u8]) -> &[u8] {
        buff[0] = self.version;
        buff[1] = self.rep;
        buff[2] = self.rsv;
        buff[3] = self.bind_addr_type;

        let start = match self.bind_addr {
            Socks5Addr::Ip(ip) => match ip {
                IpAddr::V4(v4) => {
                    buff[4..8].copy_from_slice(&v4.octets());
                    8
                }
                IpAddr::V6(v6) => {
                    buff[4..20].copy_from_slice(&v6.octets());
                    20
                }
            },
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
        &buff[..(start + 2)]
    }
}

enum Cmd {
    TCP(TcpStream),
    UDP(UdpSocket),
}

struct UdpProxyPacket<'a> {
    rsv: u16,
    frag: u8,
    addr_type: u8,
    dest_addr: Socks5Addr<'a>,
    dest_port: u16,
    data: &'a [u8],
}

impl UdpProxyPacket<'_> {
    fn decode(packet: &[u8]) -> io::Result<UdpProxyPacket<'_>> {
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
                let domain_end = 5 + domain_name_len;
                let domain_name = String::from_utf8_lossy(&packet[5..domain_end]);

                (Socks5Addr::DomainName(domain_name), domain_end)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Address type unsupported",
                ));
            }
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

    fn encode(self, buff: &mut [u8]) -> usize {
        buff[0..2].copy_from_slice(&self.rsv.to_be_bytes());
        buff[2] = self.frag;
        buff[3] = self.addr_type;

        let start = match self.dest_addr {
            Socks5Addr::Ip(ip) => match ip {
                IpAddr::V4(v4) => {
                    buff[4..8].copy_from_slice(&v4.octets());
                    8
                }
                IpAddr::V6(v6) => {
                    buff[4..20].copy_from_slice(&v6.octets());
                    20
                }
            },
            Socks5Addr::DomainName(domain_name) => {
                let domain_name_bytes = domain_name.as_bytes();
                let domain_name_len = domain_name_bytes.len();
                buff[4] = domain_name_len as u8;

                let end = 5 + domain_name_len;
                buff[5..end].copy_from_slice(domain_name_bytes);

                end
            }
        };

        buff[start..start + 2].copy_from_slice(&self.dest_port.to_be_bytes());
        start + 2 + self.data.len()
    }
}

async fn proxy_server_to_dest(packet: &[u8], udp_socket: &UdpSocket) -> io::Result<()> {
    let packet = UdpProxyPacket::decode(packet)?;

    match packet.dest_addr {
        Socks5Addr::Ip(ip) => {
            udp_socket
                .send_to(packet.data, (ip, packet.dest_port))
                .await
        }
        Socks5Addr::DomainName(domain_name) => {
            udp_socket
                .send_to(packet.data, (&*domain_name, packet.dest_port))
                .await
        }
    }?;
    Ok(())
}

fn build_err_resp(rep: u8) -> AcceptResponse<'static> {
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
    let bind_addr = match dest_addr {
        SocketAddr::V4(_) => IpAddr::from(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::from(Ipv6Addr::UNSPECIFIED),
    };

    let socket = UdpSocket::bind((bind_addr, 0)).await?;
    socket.connect(dest_addr).await?;
    Ok(socket.local_addr()?.ip())
}

struct Socks5Handler<'a, RW> {
    buff: Box<[u8]>,
    stream: &'a mut RW,
    peer_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
}

impl<'a, RW: AsyncRead + AsyncWrite + Unpin + 'static> Socks5Handler<'a, RW> {
    fn new(stream: &'a mut RW, peer_addr: SocketAddr, auth: Option<Arc<Auth>>) -> Self {
        Socks5Handler {
            buff: vec![0u8; 1024].into_boxed_slice(),
            stream,
            peer_addr,
            auth,
        }
    }

    async fn write_msg<MSG: Encode>(&mut self, msg: MSG) -> io::Result<()> {
        let writer = &mut *self.stream;
        let buff = &mut *self.buff;

        let out = msg.encode(buff);
        writer.write_all(out).await
    }

    async fn negotiate(&mut self, is_auth: bool) -> io::Result<()> {
        const NO_AUTH: u8 = 0x00;
        const AUTH: u8 = 0x02;
        const NO_ACCEPTABLE_METHODS: u8 = 0xff;

        let stream = &mut *self.stream;
        let buff = &mut *self.buff;

        let negotiate_req = NegotiateRequest::decode(stream, buff).await?;

        if negotiate_req.version != SOCKS5_VERSION {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Invalid protocol version",
            ));
        };

        let op = if is_auth {
            match negotiate_req.methods.contains(&AUTH) {
                true => Some(AUTH),
                false => None,
            }
        } else {
            Some(NO_AUTH)
        };

        let msg = match op {
            Some(code) => NegotiateResponse {
                version: SOCKS5_VERSION,
                methods: code,
            },
            None => NegotiateResponse {
                version: SOCKS5_VERSION,
                methods: NO_ACCEPTABLE_METHODS,
            },
        };
        self.write_msg(msg).await
    }

    async fn auth(&mut self) -> io::Result<()> {
        const VERSION: u8 = 0x01;
        const SUCCESS: u8 = 0x00;
        const FAILED: u8 = 0x01;

        let (username, password) = match self.auth {
            Some(ref auth) => (auth.username.as_str(), auth.password.as_str()),
            None => return Ok(()),
        };

        let stream = &mut *self.stream;
        let buff = &mut *self.buff;

        let auth_request = AuthRequest::decode(stream, buff).await?;

        let resp = if auth_request.version == VERSION {
            if auth_request.username == username && auth_request.password == password {
                AuthResponse {
                    version: VERSION,
                    status: SUCCESS,
                }
            } else {
                AuthResponse {
                    version: VERSION,
                    status: FAILED,
                }
            }
        } else {
            AuthResponse {
                version: VERSION,
                status: FAILED,
            }
        };

        self.write_msg(resp).await
    }

    async fn accept(&mut self) -> io::Result<Cmd> {
        let stream = &mut *self.stream;

        let request = match AcceptRequest::decode(stream, &mut *self.buff).await {
            Ok(req) => req,
            Err(e) => {
                if e.kind() == io::ErrorKind::Unsupported {
                    const ADDRESS_TYPE_UNSUPPORTED: u8 = 0x08;
                    let resp = build_err_resp(ADDRESS_TYPE_UNSUPPORTED);
                    self.write_msg(resp).await?;
                }
                return Err(e);
            }
        };

        if request.version != SOCKS5_VERSION {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Invalid protocol version",
            ));
        }

        const TCP: u8 = 0x01;
        const UDP: u8 = 0x03;
        const SUCCESS: u8 = 0x00;

        match request.cmd {
            TCP => {
                let dst_addr = match request.dest_addr {
                    Socks5Addr::Ip(ip) => SocketAddr::from((ip, request.port)),
                    Socks5Addr::DomainName(domain) => lookup_host((&*domain, request.port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "Resolve dst domain name error")
                        })?,
                };

                let res = TcpStream::connect(dst_addr).await;

                let dest_stream = match res {
                    Ok(dest_stream) => dest_stream,
                    Err(err) => {
                        let err_code = match err.kind() {
                            ErrorKind::NotFound | ErrorKind::NotConnected => 0x03,
                            ErrorKind::PermissionDenied => 0x02,
                            ErrorKind::ConnectionRefused => 0x05,
                            ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::TimedOut => 0x04,
                            ErrorKind::AddrNotAvailable => 0x08,
                            _ => 0x01,
                        };

                        let resp = build_err_resp(err_code);
                        self.write_msg(resp).await?;
                        return Err(err);
                    }
                };

                dest_stream.set_keepalive()?;
                let local_addr = dest_stream.local_addr()?;

                let addr_type = match local_addr {
                    SocketAddr::V4(_) => IPV4,
                    SocketAddr::V6(_) => IPV6,
                };

                let resp_msg = AcceptResponse {
                    version: SOCKS5_VERSION,
                    rep: SUCCESS,
                    rsv: 0x00,
                    bind_addr_type: addr_type,
                    bind_addr: Socks5Addr::Ip(local_addr.ip()),
                    bind_port: local_addr.port(),
                };

                self.write_msg(resp_msg).await?;
                Ok(Cmd::TCP(dest_stream))
            }
            UDP => {
                let bind_addr = match request.dest_addr {
                    Socks5Addr::Ip(ip) => SocketAddr::from((ip, request.port)),
                    Socks5Addr::DomainName(domain) => lookup_host((&*domain, request.port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "Resolve dst domain name error")
                        })?,
                };

                let udp_socket = UdpSocket::bind(bind_addr).await?;
                let local_addr = udp_socket.local_addr()?;

                let local_addr = if local_addr.ip().is_unspecified() {
                    // TODO maybe bind ipv4 ipv6 address type not match
                    let local_to_peer_ip = get_interface_addr(self.peer_addr).await?;
                    SocketAddr::new(local_to_peer_ip, local_addr.port())
                } else {
                    local_addr
                };

                let addr_type = match local_addr {
                    SocketAddr::V4(_) => IPV4,
                    SocketAddr::V6(_) => IPV6,
                };

                let resp = AcceptResponse {
                    version: SOCKS5_VERSION,
                    rep: SUCCESS,
                    rsv: 0x00,
                    bind_addr_type: addr_type,
                    bind_addr: Socks5Addr::Ip(local_addr.ip()),
                    bind_port: local_addr.port(),
                };

                self.write_msg(resp).await?;
                Ok(Cmd::UDP(udp_socket))
            }
            _ => {
                const CMD_UNSUPPORTED: u8 = 0x07;
                let resp = build_err_resp(CMD_UNSUPPORTED);
                self.write_msg(resp).await?;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "CMD unsupported",
                ))
            }
        }
    }

    async fn udp_tunnel(&mut self, udp_socket: UdpSocket) -> io::Result<()> {
        let stream = &mut *self.stream;
        let buff = &mut *self.buff;

        let f1 = async move {
            let _ = stream.read_u8().await;
            Ok(())
        };

        let f2 = async move {
            let (len, source_addr) = udp_socket.recv_from(&mut *buff).await?;
            proxy_server_to_dest(&buff[..len], &udp_socket).await?;

            let data_range_start = match udp_socket.local_addr()?.ip() {
                IpAddr::V4(_) => 10,
                IpAddr::V6(_) => 22,
            };

            while let Ok((len, peer_addr)) =
                udp_socket.recv_from(&mut buff[data_range_start..]).await
            {
                let (left, right) = buff.split_at_mut(data_range_start);

                if peer_addr == source_addr {
                    proxy_server_to_dest(&right[..len], &udp_socket).await?;
                } else {
                    let addr_type = match peer_addr.ip() {
                        IpAddr::V4(_) => IPV4,
                        IpAddr::V6(_) => IPV6,
                    };

                    let end = UdpProxyPacket {
                        rsv: 0x0000,
                        frag: 0x00,
                        addr_type,
                        dest_addr: Socks5Addr::Ip(peer_addr.ip()),
                        dest_port: peer_addr.port(),
                        data: &right[..len],
                    }
                    .encode(left);

                    udp_socket.send_to(&buff[..end], source_addr).await?;
                }
            }
            Ok(())
        };

        tokio::select! {
            res = f1 => res,
            res = f2 => res
        }
    }

    async fn exec(mut self) -> io::Result<()> {
        self.negotiate(self.auth.is_some()).await?;
        self.auth().await?;

        match self.accept().await? {
            Cmd::TCP(mut dst_stream) => {
                #[cfg(target_os = "linux")]
                {
                    let source: &mut dyn std::any::Any = self.stream;
                    if let Some(source) = source.downcast_mut::<TcpStream>() {
                        tokio_splice::zero_copy_bidirectional(source, &mut dst_stream).await?;
                        return Ok(());
                    }
                }

                tokio::io::copy_bidirectional(self.stream, &mut dst_stream).await?;
                Ok(())
            }
            Cmd::UDP(socket) => self.udp_tunnel(socket).await,
        }
    }
}

async fn server_start(
    bind_addr: SocketAddr,
    auth: Option<Arc<Auth>>,
    tls_acceptor: Option<TlsAcceptor>,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let auth = auth.clone();
        let tls_acceptor_op = tls_acceptor.clone();

        tokio::spawn(async move {
            let res = async {
                stream.set_keepalive()?;

                match tls_acceptor_op {
                    Some(acceptor) => {
                        let mut tls_stream = acceptor.accept(stream).await?;
                        Socks5Handler::new(&mut tls_stream, peer_addr, auth)
                            .exec()
                            .await
                    }
                    None => {
                        Socks5Handler::new(&mut stream, peer_addr, auth)
                            .exec()
                            .await
                    }
                }
            }
            .await;

            if let Err(e) = res {
                error!("socks5 server error: {}; bind: {}; peer: {}", e, bind_addr, peer_addr);
            }
        });
    }
}
