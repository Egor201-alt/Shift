use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

use shift_proto::tunnel::{relay, Established};
use shift_proto::{CipherSuite, OpenRequest, OpenStatus, Psk, Target, UdpPacket};

use crate::pool::ConnectionPool;
use crate::socks5::{
    encode_udp_header, parse_udp_datagram, read_request, reply_bound, reply_failure,
    reply_success, Socks5Listener, SocksRequest,
};

/// Headroom for a SOCKS5 UDP datagram: RFC 1928 header (≤ 3 + 2 + 255 + 2)
/// plus a full IPv6 UDP payload.
const MAX_SOCKS_DATAGRAM: usize = 66_000;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_public_key: [u8; 32],
    pub psk: PskSource,
    pub cipher: CipherSuite,
    pub connect_timeout: Duration,
    /// When set, precede the handshake with a real ClientHello for this
    /// hostname and wrap every frame in a fake TLS record. See
    /// `shift_proto::masquerade` for the framing rationale.
    pub camouflage_sni: Option<String>,
    /// Advertise and serve SOCKS5 UDP ASSOCIATE (DNS, QUIC, games) through
    /// an in-tunnel UDP relay. Disable to accept CONNECT only.
    pub udp_enabled: bool,
}

#[derive(Clone, Debug)]
pub enum PskSource {
    Passphrase(String),
    Hex(String),
}

impl PskSource {
    pub fn resolve(&self) -> shift_proto::Result<Psk> {
        match self {
            PskSource::Passphrase(text) => Ok(Psk::from_passphrase(text)),
            PskSource::Hex(hex) => Psk::from_hex(hex),
        }
    }
}

pub struct RunningClient {
    stop: Arc<AtomicBool>,
}

impl RunningClient {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub async fn run_socks5(config: ClientConfig, bind: SocketAddr) -> std::io::Result<RunningClient> {
    let listener = Socks5Listener::bind(bind).await?;
    tracing::info!(bind = %listener.local_addr()?, server = %config.server_addr, udp = config.udp_enabled, "shift-client SOCKS5 listening");
    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let config = Arc::new(config);
    let pool = ConnectionPool::spawn(Arc::clone(&config), 4, Arc::clone(&stop));

    tokio::spawn(async move {
        loop {
            if loop_stop.load(Ordering::SeqCst) {
                return;
            }
            let (client, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "socks5 accept failed");
                    continue;
                }
            };
            let config = Arc::clone(&config);
            let pool = pool.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_socks_client(client, config, pool).await {
                    tracing::debug!(%peer, error = %err, "socks5 connection ended");
                }
            });
        }
    });

    Ok(RunningClient { stop })
}

async fn handle_socks_client(
    mut client: TcpStream,
    config: Arc<ClientConfig>,
    pool: ConnectionPool,
) -> std::io::Result<()> {
    match read_request(&mut client).await? {
        SocksRequest::Connect(target) => run_connect(client, pool, target).await,
        SocksRequest::UdpAssociate if config.udp_enabled => {
            run_udp_associate(client, pool).await
        }
        SocksRequest::UdpAssociate => {
            reply_failure(&mut client).await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "udp associate is disabled",
            ))
        }
    }
}

async fn run_connect(mut client: TcpStream, pool: ConnectionPool, target: Target) -> io::Result<()> {
    let (mut server_stream, mut session) = pool.acquire().await?;

    let request = OpenRequest::Connect(target.clone())
        .encode()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    session.send(&mut server_stream, &request).await?;

    let status_frame = session
        .recv_frame(&mut server_stream)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "early eof waiting for status",
            )
        })?;

    let status = match status_frame.as_ref() {
        [byte] => OpenStatus::from_byte(*byte)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed open status",
            ))
        }
    };

    if status != OpenStatus::Ok {
        reply_failure(&mut client).await?;
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("server refused to open {target}"),
        ));
    }

    reply_success(&mut client).await?;
    relay(client, server_stream, session).await
}

async fn run_udp_associate(mut client: TcpStream, pool: ConnectionPool) -> io::Result<()> {
    let relay = match bind_udp_relay(&client).await {
        Ok(relay) => relay,
        Err(err) => {
            let _ = reply_failure(&mut client).await;
            return Err(err);
        }
    };
    let relay_addr = relay.local_addr()?;

    let (mut server_stream, mut session) = match pool.acquire().await {
        Ok(pair) => pair,
        Err(err) => {
            let _ = reply_failure(&mut client).await;
            return Err(err);
        }
    };

    reply_bound(&mut client, &relay_addr).await?;

    let request = OpenRequest::Udp
        .encode()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    session.send(&mut server_stream, &request).await?;
    let status_frame = session
        .recv_frame(&mut server_stream)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "early eof waiting for status",
            )
        })?;
    let status = match status_frame.as_ref() {
        [byte] => OpenStatus::from_byte(*byte)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed open status",
            ))
        }
    };
    if status != OpenStatus::Ok {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "server refused a udp association",
        ));
    }

    tracing::debug!(relay = %relay_addr, "udp association established");
    serve_udp_pipe(client, server_stream, session, relay).await
}

async fn bind_udp_relay(client: &TcpStream) -> io::Result<UdpSocket> {
    // Bind on the loopback of the control connection so the relay is never
    // exposed off-host.
    let bind = if client.local_addr()?.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    UdpSocket::bind(bind).await
}

/// One in-tunnel UDP association: datagrams from the SOCKS5 client are
/// forwarded as [`UdpPacket`] frames, replies come back framed and are
/// re-wrapped in a SOCKS5 UDP header toward the last observed sender.
async fn serve_udp_pipe(
    mut control: TcpStream,
    mut server: TcpStream,
    mut session: Established,
    relay: UdpSocket,
) -> io::Result<()> {
    let mut datagram = vec![0u8; MAX_SOCKS_DATAGRAM];
    let mut probe = [0u8; 1];
    let mut last_sender: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            received = relay.recv_from(&mut datagram) => {
                let (len, from) = received?;
                let Some((target, data)) = parse_udp_datagram(&datagram[..len]) else {
                    continue;
                };
                last_sender = Some(from);
                let bytes = UdpPacket { target, data: data.to_vec() }
                    .encode()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                session.send(&mut server, &bytes).await?;
            }
            frame = session.recv_frame(&mut server) => {
                let payload = match frame? {
                    Some(payload) => payload,
                    None => return Ok(()),
                };
                let packet = UdpPacket::decode(&payload)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                let mut reply = Vec::with_capacity(packet.data.len() + 32);
                encode_udp_header(&packet.target, &mut reply);
                reply.extend_from_slice(&packet.data);
                if let Some(to) = last_sender {
                    relay.send_to(&reply, to).await?;
                }
            }
            read = control.read(&mut probe) => {
                if read? == 0 {
                    // The SOCKS5 client closed the control connection: the
                    // association is over.
                    return Ok(());
                }
            }
        }
    }
}
