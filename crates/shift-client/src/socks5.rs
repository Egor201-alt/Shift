use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use shift_proto::{Host, Target};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;
const REPLY_OK: u8 = 0;
const REPLY_GENERAL_FAILURE: u8 = 1;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;

pub struct Socks5Listener {
    listener: TcpListener,
}

impl Socks5Listener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Socks5Listener {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }
}

/// A parsed SOCKS5 request: CONNECT with its target, or UDP ASSOCIATE
/// (whose request address is consumed but ignored — the app learns the
/// relay endpoint from the reply).
#[derive(Debug, PartialEq, Eq)]
pub enum SocksRequest {
    Connect(Target),
    UdpAssociate,
}

/// Reads and negotiates one SOCKS5 request: method negotiation followed
/// by the command header and its target address.
pub async fn read_request(stream: &mut TcpStream) -> io::Result<SocksRequest> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 client",
        ));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no acceptable auth method",
        ));
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad request version",
        ));
    }
    match header[1] {
        CMD_CONNECT => Ok(SocksRequest::Connect(read_target(stream, header[3]).await?)),
        CMD_UDP_ASSOCIATE => {
            // The requested address only tells us where the app plans to
            // send from; read and discard it to keep the stream in sync.
            let _ = read_target(stream, header[3]).await?;
            Ok(SocksRequest::UdpAssociate)
        }
        _ => {
            reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only CONNECT and UDP ASSOCIATE are supported",
            ))
        }
    }
}

async fn read_target(stream: &mut TcpStream, atyp: u8) -> io::Result<Target> {
    let host = match atyp {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::V4(Ipv4Addr::from(octets))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::V6(Ipv6Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain is not utf-8"))?;
            Host::Domain(name)
        }
        _ => {
            reply(stream, REPLY_GENERAL_FAILURE).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;

    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

pub async fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    let zero = SocketAddr::from(([0, 0, 0, 0], 0));
    reply_addr(stream, code, &zero).await
}

pub async fn reply_success(stream: &mut TcpStream) -> io::Result<()> {
    reply(stream, REPLY_OK).await
}

pub async fn reply_failure(stream: &mut TcpStream) -> io::Result<()> {
    reply(stream, REPLY_GENERAL_FAILURE).await
}

/// Success reply carrying `bound` as BND.ADDR/BND.PORT. Used for UDP
/// ASSOCIATE, where the app needs the relay endpoint to send datagrams to.
pub async fn reply_bound(stream: &mut TcpStream, bound: &SocketAddr) -> io::Result<()> {
    reply_addr(stream, REPLY_OK, bound).await
}

async fn reply_addr(stream: &mut TcpStream, code: u8, bound: &SocketAddr) -> io::Result<()> {
    let mut payload = [0u8; 22];
    payload[0] = VERSION;
    payload[1] = code;
    payload[2] = 0;
    let len = match bound {
        SocketAddr::V4(v4) => {
            payload[3] = ATYP_V4;
            payload[4..8].copy_from_slice(&v4.ip().octets());
            payload[8..10].copy_from_slice(&v4.port().to_be_bytes());
            10
        }
        SocketAddr::V6(v6) => {
            payload[3] = ATYP_V6;
            payload[4..20].copy_from_slice(&v6.ip().octets());
            payload[20..22].copy_from_slice(&v6.port().to_be_bytes());
            22
        }
    };
    stream.write_all(&payload[..len]).await
}

/// Parses a SOCKS5 UDP datagram header (RFC 1928 §7). Returns the target
/// and the payload, or `None` for fragmented (FRAG != 0) or malformed
/// datagrams, which are dropped per common practice.
pub fn parse_udp_datagram(datagram: &[u8]) -> Option<(Target, &[u8])> {
    if datagram.len() < 4 || datagram[2] != 0 {
        return None;
    }
    let (target, used) = Target::decode(&datagram[3..]).ok()?;
    let data = datagram.get(3 + used..)?;
    Some((target, data))
}

/// Prepends a SOCKS5 UDP reply header (RSV/FRAG zeros plus the encoded
/// address) for `target` to `out`.
pub fn encode_udp_header(target: &Target, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0, 0, 0]);
    // Targets on this path were decoded from the wire or built from socket
    // addresses, so encoding cannot fail (domain length is at most 255).
    let _ = target.encode(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_header(atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut out = vec![0, 0, 0, atyp];
        out.extend_from_slice(addr);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    #[test]
    fn parses_v4_v6_and_domain_datagrams() {
        let header = udp_header(ATYP_V4, &[93, 184, 216, 34], 443);
        let mut datagram = header.clone();
        datagram.extend_from_slice(b"payload");
        let (target, data) = parse_udp_datagram(&datagram).unwrap();
        assert_eq!(
            target,
            Target {
                host: Host::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 443
            }
        );
        assert_eq!(data, b"payload");

        let datagram = udp_header(ATYP_V6, &[0u8; 16], 53);
        let (target, data) = parse_udp_datagram(&datagram).unwrap();
        assert!(matches!(target.host, Host::V6(_)));
        assert_eq!(data, b"");

        let mut datagram = udp_header(
            ATYP_DOMAIN,
            &[
                11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g',
            ],
            53,
        );
        datagram.push(0xaa);
        let (target, data) = parse_udp_datagram(&datagram).unwrap();
        assert_eq!(target.host, Host::Domain("example.org".into()));
        assert_eq!(data, &[0xaa]);
    }

    #[test]
    fn rejects_fragmented_and_malformed_datagrams() {
        let mut fragmented = udp_header(ATYP_V4, &[1, 1, 1, 1], 53);
        fragmented[2] = 2;
        assert!(parse_udp_datagram(&fragmented).is_none());
        assert!(parse_udp_datagram(&[0, 0]).is_none());
        assert!(parse_udp_datagram(&[0, 0, 0, 9, 1]).is_none());
        // Unknown address type.
        assert!(parse_udp_datagram(&udp_header(7, &[1, 2], 53)).is_none());
    }

    #[test]
    fn encodes_reply_header_roundtrip() {
        let target = Target {
            host: Host::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 5353,
        };
        let mut out = Vec::new();
        encode_udp_header(&target, &mut out);
        out.extend_from_slice(b"reply");
        let (parsed, data) = parse_udp_datagram(&out).unwrap();
        assert_eq!(parsed, target);
        assert_eq!(data, b"reply");
    }
}
