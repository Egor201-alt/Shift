//! In-tunnel UDP relay. One association per tunnel connection opened with
//! [`shift_proto::OpenRequest::Udp`]: datagrams arrive as [`UdpPacket`]
//! frames, are emitted from a single shared per-association socket, and
//! replies are framed back toward the client with the responder's address
//! as the target. DNS (plain UDP :53) works through this path with no
//! special handling; domain targets are resolved server-side.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

use shift_proto::tunnel::Established;
use shift_proto::{Host, Target, UdpPacket};

const MAX_DATAGRAM: usize = 65_536;

/// Serves one UDP association until the tunnel ends, the client goes
/// away, or `idle` passes with no traffic in either direction.
pub async fn serve(
    mut stream: TcpStream,
    mut session: Established,
    peer: SocketAddr,
    idle: Duration,
) -> anyhow::Result<()> {
    // Match the socket family to the client's so replies to IPv6 targets
    // are possible; all outbound targets share this one socket (NAT-style).
    let bind_addr = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    tracing::info!(%peer, "udp tunnel established");

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut deadline = tokio::time::Instant::now() + idle;
    loop {
        tokio::select! {
            frame = session.recv_frame(&mut stream) => {
                let payload = match frame? {
                    Some(payload) => payload,
                    None => return Ok(()),
                };
                let packet = match UdpPacket::decode(&payload) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::debug!(%peer, error = %err, "malformed udp packet");
                        continue;
                    }
                };
                match resolve(&packet.target).await {
                    Ok(addr) => {
                        if let Err(err) = socket.send_to(&packet.data, addr).await {
                            tracing::debug!(%peer, error = %err, "udp send failed");
                        }
                    }
                    Err(err) => {
                        tracing::debug!(%peer, error = %err, "udp target unresolved");
                    }
                }
                deadline = tokio::time::Instant::now() + idle;
            }
            received = socket.recv_from(&mut buf) => {
                let (len, from) = match received {
                    Ok(pair) => pair,
                    Err(err) => {
                        // e.g. ICMP-driven WSAECONNRESET on Windows: one
                        // unreachable target must not kill the association.
                        tracing::debug!(%peer, error = %err, "udp recv failed");
                        continue;
                    }
                };
                let packet = UdpPacket {
                    target: Target::from_socket_addr(from),
                    data: buf[..len].to_vec(),
                };
                let bytes = packet.encode()?;
                if session.send(&mut stream, &bytes).await.is_err() {
                    return Ok(());
                }
                deadline = tokio::time::Instant::now() + idle;
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::debug!(%peer, "udp association idle, closing");
                return Ok(());
            }
        }
    }
}

async fn resolve(target: &Target) -> anyhow::Result<SocketAddr> {
    match target.to_socket_addr() {
        Some(addr) => Ok(addr),
        None => {
            let Host::Domain(name) = &target.host else {
                unreachable!("to_socket_addr only returns None for domains");
            };
            let candidate = format!("{name}:{}", target.port);
            tokio::net::lookup_host(candidate)
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "udp target unresolved")
                })
                .map_err(anyhow::Error::from)
        }
    }
}
