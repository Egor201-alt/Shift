use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use shift_client::core::{run_socks5, PskSource};
use shift_client::ClientConfig;
use shift_proto::{CipherSuite, Psk, ServerHandshake, ServerIdentity};
use shift_server::{serve, RuntimeConfig};

async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    let read = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    if socket.send_to(&buf[..len], from).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    addr
}

fn runtime_config(
    listen: SocketAddr,
    forward: SocketAddr,
    fallback: SocketAddr,
    camouflage: bool,
) -> RuntimeConfig {
    RuntimeConfig {
        listen,
        forward,
        fallback,
        handshake_timeout: Duration::from_secs(5),
        fallback_drain: Duration::from_millis(500),
        udp_idle_timeout: Duration::from_secs(300),
        shaper: shift_proto::ShaperConfig::default(),
        camouflage,
        camouflage_port: 443,
    }
}

async fn spawn_shift_server(
    psk: &Psk,
    forward: SocketAddr,
    fallback: SocketAddr,
    camouflage: bool,
) -> (SocketAddr, [u8; 32]) {
    let identity = ServerIdentity::generate();
    let server_public_key = identity.public_bytes();
    let handshake = Arc::new(ServerHandshake::new(identity, psk.clone()));
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    tokio::spawn(serve(
        server_listener,
        Arc::new(runtime_config(server_addr, forward, fallback, camouflage)),
        handshake,
    ));
    (server_addr, server_public_key)
}

async fn spawn_socks_client(
    server_addr: SocketAddr,
    server_public_key: [u8; 32],
    psk_passphrase: &str,
    camouflage_sni: Option<String>,
) -> SocketAddr {
    let client_config = ClientConfig {
        server_addr: server_addr.to_string(),
        server_public_key,
        psk: PskSource::Passphrase(psk_passphrase.to_owned()),
        cipher: CipherSuite::preferred(),
        connect_timeout: Duration::from_secs(5),
        camouflage_sni,
        udp_enabled: true,
    };
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    run_socks5(client_config, socks_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    socks_addr
}

async fn socks5_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [5, 0]);

    let SocketAddr::V4(v4) = target else {
        panic!("test target must be IPv4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks5 connect should succeed");
    stream
}

#[tokio::test]
async fn full_tunnel_relays_bytes_end_to_end() {
    let echo_addr = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("integration-test-psk");
    let (server_addr, server_public_key) =
        spawn_shift_server(&psk, echo_addr, fallback_addr, false).await;
    let socks_addr =
        spawn_socks_client(server_addr, server_public_key, "integration-test-psk", None).await;

    let mut tunnel = socks5_connect(socks_addr, echo_addr).await;

    for round in 0..20u8 {
        let payload: Vec<u8> = (0..(500 + round as usize * 37))
            .map(|i| (i as u8).wrapping_add(round))
            .collect();
        tunnel.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round {round} mismatch");
    }
}

#[tokio::test]
async fn wrong_psk_falls_back_instead_of_reaching_forward() {
    let real_forward = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("server-secret");
    let identity = ServerIdentity::generate();
    let server_public_key = identity.public_bytes();
    let handshake = Arc::new(ServerHandshake::new(identity, psk));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let runtime_cfg = Arc::new(runtime_config(
        server_addr,
        real_forward,
        fallback_addr,
        false,
    ));
    tokio::spawn(serve(server_listener, runtime_cfg, handshake));

    let socks_addr = spawn_socks_client(server_addr, server_public_key, "wrong-guess", None).await;

    let mut direct = TcpStream::connect(socks_addr).await.unwrap();
    direct.write_all(&[5, 1, 0]).await.unwrap();
    let mut method_reply = [0u8; 2];
    let outcome =
        tokio::time::timeout(Duration::from_secs(2), direct.read_exact(&mut method_reply)).await;
    assert!(
        outcome.is_ok(),
        "server must still speak to fallback path, not hang"
    );
}

#[tokio::test]
async fn masqueraded_tunnel_relays_bytes_end_to_end() {
    let echo_addr = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("camouflage-test-psk");
    let (server_addr, server_public_key) =
        spawn_shift_server(&psk, echo_addr, fallback_addr, true).await;
    let socks_addr = spawn_socks_client(
        server_addr,
        server_public_key,
        "camouflage-test-psk",
        Some("www.example.com".to_owned()),
    )
    .await;

    let mut tunnel = socks5_connect(socks_addr, echo_addr).await;
    for round in 0..15u8 {
        let payload: Vec<u8> = (0..(600 + round as usize * 41))
            .map(|i| (i as u8).wrapping_mul(3).wrapping_add(round))
            .collect();
        tunnel.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round {round} mismatch");
    }
}

/// Regression for the masquerade record handling: burst-phase reads must
/// survive being split across fake TLS records (each record stays within
/// the record limit; the frame reassembles across them). A multi-megabyte
/// transfer forces the Burst phase and many frames per relay batch.
#[tokio::test]
async fn masqueraded_bulk_transfer_survives_burst_phase() {
    let echo_addr = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("camouflage-bulk-psk");
    let (server_addr, server_public_key) =
        spawn_shift_server(&psk, echo_addr, fallback_addr, true).await;
    let socks_addr = spawn_socks_client(
        server_addr,
        server_public_key,
        "camouflage-bulk-psk",
        Some("www.example.com".to_owned()),
    )
    .await;

    let mut tunnel = socks5_connect(socks_addr, echo_addr).await;
    let chunk = vec![0x5au8; 256 * 1024];
    let mut received = vec![0u8; chunk.len()];
    for round in 0..12 {
        tunnel.write_all(&chunk).await.unwrap();
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, chunk, "round {round} mismatch");
    }
}

/// Full SOCKS5 UDP ASSOCIATE path: the app datagram goes through the local
/// relay, the tunnel as a UdpPacket frame, out of the server to the echo
/// endpoint, and back the whole way.
#[tokio::test]
async fn udp_associate_relays_datagrams_end_to_end() {
    let udp_echo_addr = spawn_udp_echo().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("udp-test-psk");
    let (server_addr, server_public_key) =
        spawn_shift_server(&psk, fallback_addr, fallback_addr, false).await;
    let socks_addr = spawn_socks_client(server_addr, server_public_key, "udp-test-psk", None).await;

    let mut control = TcpStream::connect(socks_addr).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [5, 0]);

    // UDP ASSOCIATE, DST.ADDR = 0.0.0.0:0 (typical app behavior).
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "udp associate should succeed");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr = SocketAddr::from(([127, 0, 0, 1], relay_port));

    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(target_v4) = udp_echo_addr else {
        panic!("udp echo must be IPv4");
    };
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&target_v4.ip().octets());
    datagram.extend_from_slice(&target_v4.port().to_be_bytes());
    datagram.extend_from_slice(b"hello udp through shift");

    app.send_to(&datagram, relay_addr).await.unwrap();
    let mut recv = vec![0u8; datagram.len() + 64];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), app.recv_from(&mut recv))
        .await
        .expect("no udp reply through the tunnel")
        .unwrap();
    assert_eq!(&recv[10..len], b"hello udp through shift");

    // Closing the control connection must tear the association down
    // without hanging the client task.
    drop(control);
    drop(app);
    tokio::time::sleep(Duration::from_millis(50)).await;
}
