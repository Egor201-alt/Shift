use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{Result, ShiftError};

const KIND_RAW: u8 = 0;
const KIND_CONNECT: u8 = 1;
const KIND_UDP: u8 = 2;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::V4(ip) => write!(f, "{ip}"),
            Host::V6(ip) => write!(f, "[{ip}]"),
            Host::Domain(name) => f.write_str(name),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

fn take<const N: usize>(src: &[u8], start: usize) -> Result<[u8; N]> {
    let slice = src
        .get(start..start + N)
        .ok_or(ShiftError::InvalidRequest("truncated target"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

impl Target {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match &self.host {
            Host::V4(ip) => {
                out.push(ATYP_V4);
                out.extend_from_slice(&ip.octets());
            }
            Host::V6(ip) => {
                out.push(ATYP_V6);
                out.extend_from_slice(&ip.octets());
            }
            Host::Domain(name) => {
                let bytes = name.as_bytes();
                if bytes.is_empty() || bytes.len() > 255 {
                    return Err(ShiftError::InvalidRequest("domain length must be 1..=255"));
                }
                out.push(ATYP_DOMAIN);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    pub fn decode(src: &[u8]) -> Result<(Target, usize)> {
        let atyp = *src
            .first()
            .ok_or(ShiftError::InvalidRequest("empty target"))?;
        let (host, used) = match atyp {
            ATYP_V4 => (Host::V4(Ipv4Addr::from(take::<4>(src, 1)?)), 5),
            ATYP_V6 => (Host::V6(Ipv6Addr::from(take::<16>(src, 1)?)), 17),
            ATYP_DOMAIN => {
                let len = *src
                    .get(1)
                    .ok_or(ShiftError::InvalidRequest("truncated target"))?
                    as usize;
                if len == 0 {
                    return Err(ShiftError::InvalidRequest("empty domain"));
                }
                let raw = src
                    .get(2..2 + len)
                    .ok_or(ShiftError::InvalidRequest("truncated target"))?;
                let name = std::str::from_utf8(raw)
                    .map_err(|_| ShiftError::InvalidRequest("domain is not utf-8"))?;
                (Host::Domain(name.to_owned()), 2 + len)
            }
            _ => return Err(ShiftError::InvalidRequest("unknown address type")),
        };
        let port = u16::from_be_bytes(take::<2>(src, used)?);
        Ok((Target { host, port }, used + 2))
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Target {
                host: Host::V4(*v4.ip()),
                port: v4.port(),
            },
            SocketAddr::V6(v6) => Target {
                host: Host::V6(*v6.ip()),
                port: v6.port(),
            },
        }
    }

    /// Returns the target as a socket address, or `None` when it carries a
    /// domain name that still needs resolution.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        let ip = match &self.host {
            Host::V4(ip) => IpAddr::V4(*ip),
            Host::V6(ip) => IpAddr::V6(*ip),
            Host::Domain(_) => return None,
        };
        Some(SocketAddr::new(ip, self.port))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenRequest {
    Raw,
    Connect(Target),
    /// Open a UDP association: every subsequent frame on this tunnel
    /// connection carries one [`UdpPacket`].
    Udp,
}

impl OpenRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            OpenRequest::Raw => Ok(vec![KIND_RAW]),
            OpenRequest::Connect(target) => {
                let mut out = vec![KIND_CONNECT];
                target.encode(&mut out)?;
                Ok(out)
            }
            OpenRequest::Udp => Ok(vec![KIND_UDP]),
        }
    }

    pub fn decode(src: &[u8]) -> Result<Self> {
        match src.first() {
            Some(&KIND_RAW) if src.len() == 1 => Ok(OpenRequest::Raw),
            Some(&KIND_CONNECT) => {
                let (target, used) = Target::decode(&src[1..])?;
                if 1 + used != src.len() {
                    return Err(ShiftError::InvalidRequest("trailing bytes"));
                }
                Ok(OpenRequest::Connect(target))
            }
            Some(&KIND_UDP) if src.len() == 1 => Ok(OpenRequest::Udp),
            _ => Err(ShiftError::InvalidRequest("unknown request kind")),
        }
    }
}

/// One UDP datagram inside the tunnel: the destination (or, on the return
/// path, the responder) followed by a length-prefixed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpPacket {
    pub target: Target,
    pub data: Vec<u8>,
}

impl UdpPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data.len() > u16::MAX as usize {
            return Err(ShiftError::InvalidRequest("udp payload too large"));
        }
        let mut out = Vec::with_capacity(4 + 16 + self.data.len());
        self.target.encode(&mut out)?;
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(src: &[u8]) -> Result<Self> {
        let (target, used) = Target::decode(src)?;
        let data_len = u16::from_be_bytes(take::<2>(src, used)?) as usize;
        let data_start = used + 2;
        if src.len() != data_start + data_len {
            return Err(ShiftError::InvalidRequest("udp length mismatch"));
        }
        Ok(UdpPacket {
            target,
            data: src[data_start..].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenStatus {
    Ok,
    Failed,
    NotAllowed,
    Timeout,
}

impl OpenStatus {
    pub fn byte(self) -> u8 {
        match self {
            OpenStatus::Ok => 0,
            OpenStatus::Failed => 1,
            OpenStatus::NotAllowed => 2,
            OpenStatus::Timeout => 3,
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(OpenStatus::Ok),
            1 => Ok(OpenStatus::Failed),
            2 => Ok(OpenStatus::NotAllowed),
            3 => Ok(OpenStatus::Timeout),
            _ => Err(ShiftError::InvalidRequest("unknown status")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(request: OpenRequest) {
        let bytes = request.encode().unwrap();
        assert_eq!(OpenRequest::decode(&bytes).unwrap(), request);
    }

    #[test]
    fn all_address_kinds_roundtrip() {
        roundtrip(OpenRequest::Raw);
        roundtrip(OpenRequest::Udp);
        roundtrip(OpenRequest::Connect(Target {
            host: Host::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port: 443,
        }));
        roundtrip(OpenRequest::Connect(Target {
            host: Host::V6("2606:2800:220:1::1".parse().unwrap()),
            port: 80,
        }));
        roundtrip(OpenRequest::Connect(Target {
            host: Host::Domain("example.com".into()),
            port: 8443,
        }));
    }

    #[test]
    fn udp_packets_roundtrip_all_address_kinds() {
        let packets = [
            UdpPacket {
                target: Target {
                    host: Host::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    port: 53,
                },
                data: b"dns query".to_vec(),
            },
            UdpPacket {
                target: Target {
                    host: Host::V6("2606:4700::1111".parse().unwrap()),
                    port: 53,
                },
                data: vec![],
            },
            UdpPacket {
                target: Target {
                    host: Host::Domain("dns.example".into()),
                    port: 5353,
                },
                data: vec![0xab; 1200],
            },
        ];
        for packet in packets {
            let bytes = packet.encode().unwrap();
            assert_eq!(UdpPacket::decode(&bytes).unwrap(), packet);
        }
    }

    #[test]
    fn malformed_udp_packets_are_rejected() {
        assert!(UdpPacket::decode(&[]).is_err());
        assert!(UdpPacket::decode(&[1, 1, 2, 3]).is_err());
        let packet = UdpPacket {
            target: Target {
                host: Host::V4(Ipv4Addr::LOCALHOST),
                port: 53,
            },
            data: b"xyz".to_vec(),
        };
        let mut bytes = packet.encode().unwrap();
        // Truncated tail.
        bytes.pop();
        assert!(UdpPacket::decode(&bytes).is_err());
        // Trailing garbage.
        bytes.push(0);
        assert!(UdpPacket::decode(&bytes).is_err());
        let mut huge = packet;
        huge.data = vec![0u8; u16::MAX as usize + 1];
        assert!(huge.encode().is_err());
    }

    #[test]
    fn socket_addr_conversions() {
        let v4: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let target = Target::from_socket_addr(v4);
        assert_eq!(target.host, Host::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(target.to_socket_addr(), Some(v4));

        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let target = Target::from_socket_addr(v6);
        assert_eq!(target.to_socket_addr(), Some(v6));

        let domain = Target {
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert_eq!(domain.to_socket_addr(), None);
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(OpenRequest::decode(&[]).is_err());
        assert!(OpenRequest::decode(&[0, 0]).is_err());
        assert!(OpenRequest::decode(&[9]).is_err());
        assert!(OpenRequest::decode(&[1, 1, 1, 2, 3]).is_err());
        assert!(OpenRequest::decode(&[1, 3, 0, 0, 80]).is_err());
        assert!(OpenRequest::decode(&[1, 3, 5, b'a', 0, 80]).is_err());
        assert!(OpenRequest::decode(&[1, 3, 1, 0xff, 0, 80]).is_err());
        let mut long = vec![1, 1, 2, 3, 4, 0, 80, 0];
        long.push(0xff);
        assert!(OpenRequest::decode(&long).is_err());
    }

    #[test]
    fn oversized_domain_is_refused() {
        let target = Target {
            host: Host::Domain("a".repeat(256)),
            port: 1,
        };
        assert!(OpenRequest::Connect(target).encode().is_err());
    }

    #[test]
    fn status_bytes_roundtrip() {
        for status in [
            OpenStatus::Ok,
            OpenStatus::Failed,
            OpenStatus::NotAllowed,
            OpenStatus::Timeout,
        ] {
            assert_eq!(OpenStatus::from_byte(status.byte()).unwrap(), status);
        }
        assert!(OpenStatus::from_byte(77).is_err());
    }
}
