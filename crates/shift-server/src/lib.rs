pub mod capture;
pub mod config;
pub mod fallback;
pub mod forwarder;
pub mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use shift_proto::masquerade;
use shift_proto::tunnel::{tune_socket, unix_now, Established};
use shift_proto::{
    AdaptiveShaper, ClientInit, Host, OpenRequest, OpenStatus, ServerHandshake, Target,
    CLIENT_INIT_LEN,
};

pub use config::{load_identity, Cli, Identity, RuntimeConfig};

pub async fn serve(
    listener: TcpListener,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let runtime = Arc::clone(&runtime);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let result = if runtime.camouflage {
                handle_connection_masqueraded(stream, peer, runtime, server).await
            } else {
                handle_connection_plain(stream, peer, runtime, server).await
            };
            if let Err(err) = result {
                tracing::debug!(%peer, error = %err, "connection ended");
            }
        });
    }
}

pub async fn handle_connection_plain(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> anyhow::Result<()> {
    tune_socket(&stream)?;

    let mut init_buf = BytesMut::with_capacity(CLIENT_INIT_LEN);
    let filled = tokio::time::timeout(
        runtime.handshake_timeout,
        ensure_captured(&mut stream, &mut init_buf, CLIENT_INIT_LEN),
    )
    .await;
    if !matches!(filled, Ok(true)) {
        let target = runtime.fallback.to_string();
        fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
        return Ok(());
    }

    let init = match ClientInit::from_bytes(&init_buf[..CLIENT_INIT_LEN]) {
        Ok(init) => init,
        Err(_) => {
            let target = runtime.fallback.to_string();
            fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
            return Ok(());
        }
    };

    let (reply, keys) = match server.accept(&init, unix_now()) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(%peer, error = %err, "handshake rejected, falling back to decoy");
            let target = runtime.fallback.to_string();
            fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
            return Ok(());
        }
    };

    if tokio::time::timeout(
        runtime.handshake_timeout,
        stream.write_all(&reply.to_bytes()),
    )
    .await
    .is_err()
    {
        return Ok(());
    }

    let remainder = if init_buf.len() > CLIENT_INIT_LEN {
        init_buf.split_off(CLIENT_INIT_LEN)
    } else {
        BytesMut::with_capacity(4096)
    };

    let shaper = AdaptiveShaper::new(runtime.shaper.clone(), Instant::now())?;
    let session = Established::new(keys.keys, remainder, shaper);
    finish_connection(stream, peer, runtime, session).await
}

pub async fn handle_connection_masqueraded(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> anyhow::Result<()> {
    tune_socket(&stream)?;

    let mut capture = BytesMut::new();
    let (hello, consumed) =
        match capture::read_client_hello(&mut stream, &mut capture, runtime.handshake_timeout).await
        {
            Ok(pair) => pair,
            Err(capture::FallbackNow) => {
                decoy_fallback(stream, capture, None, &runtime).await;
                return Ok(());
            }
        };

    let Some(init) = hello.client_init() else {
        decoy_fallback(stream, capture, hello.server_name.as_deref(), &runtime).await;
        return Ok(());
    };

    let (reply, keys) = match server.accept(&init, unix_now()) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(%peer, error = %err, sni = ?hello.server_name, "handshake rejected, falling back to decoy");
            decoy_fallback(stream, capture, hello.server_name.as_deref(), &runtime).await;
            return Ok(());
        }
    };

    let shaper = AdaptiveShaper::new(runtime.shaper.clone(), Instant::now())?;
    let mut session = Established::new_with_masquerade(keys.keys, BytesMut::new(), shaper, true);

    let mut flight = BytesMut::with_capacity(8192);
    masquerade::build_server_hello(&init, &reply, &hello.cipher_suites, &mut flight);
    session.encode_cover_records(&masquerade::server_flight_record_lens(), &mut flight)?;
    let sent = tokio::time::timeout(runtime.handshake_timeout, stream.write_all(&flight)).await;
    if !matches!(sent, Ok(Ok(()))) {
        return Ok(());
    }

    let after_spec = consumed + masquerade::CHANGE_CIPHER_SPEC_RECORD.len();
    if capture::read_change_cipher_spec(
        &mut stream,
        &mut capture,
        consumed,
        runtime.handshake_timeout,
    )
    .await
    .is_err()
    {
        return Ok(());
    }
    let remainder = capture.split_off(after_spec);
    session.feed_leftover(&remainder);

    finish_connection(stream, peer, runtime, session).await
}

async fn decoy_fallback(
    stream: TcpStream,
    capture: BytesMut,
    sni: Option<&str>,
    runtime: &RuntimeConfig,
) {
    let candidates = fallback::decoy_candidates(
        sni,
        runtime.camouflage_port,
        runtime.fallback,
        runtime.forward,
        runtime.fallback_drain,
    )
    .await;
    fallback::drain_to_decoy_chain(stream, capture, &candidates, runtime.fallback_drain).await;
}

/// Common tail shared by both accept paths once a `Established` session is
/// ready: read the first in-tunnel frame as an [`OpenRequest`], then dial
/// the requested (or configured) upstream and relay — or, for
/// [`OpenRequest::Udp`], hand the session to the UDP relay.
async fn finish_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    mut session: Established,
) -> anyhow::Result<()> {
    let request_bytes = match tokio::time::timeout(
        runtime.handshake_timeout,
        session.recv_frame(&mut stream),
    )
    .await
    {
        Ok(Ok(Some(bytes))) => bytes,
        _ => return Ok(()),
    };
    let request = OpenRequest::decode(&request_bytes)?;

    if matches!(&request, OpenRequest::Udp) {
        session.send(&mut stream, &[OpenStatus::Ok.byte()]).await?;
        return udp::serve(stream, session, peer, runtime.udp_idle_timeout).await;
    }

    let target = match &request {
        OpenRequest::Raw => DialTarget::Addr(runtime.forward),
        OpenRequest::Connect(target) => DialTarget::Named(target_to_string(target)),
        OpenRequest::Udp => unreachable!("udp associations are handled above"),
    };

    let remote = match dial(target, runtime.handshake_timeout).await {
        Ok(remote) => remote,
        Err(err) => {
            tracing::debug!(%peer, ?request, error = %err, "upstream dial failed");
            let _ = session
                .send(&mut stream, &[OpenStatus::Failed.byte()])
                .await;
            return Ok(());
        }
    };

    session.send(&mut stream, &[OpenStatus::Ok.byte()]).await?;
    tracing::info!(%peer, target = %describe(&request), "tunnel established");
    shift_proto::tunnel::relay(remote, stream, session).await?;
    Ok(())
}

enum DialTarget {
    Addr(SocketAddr),
    Named(String),
}

async fn dial(target: DialTarget, timeout: Duration) -> std::io::Result<TcpStream> {
    let stream = match target {
        DialTarget::Addr(addr) => forwarder::dial(addr, timeout).await?,
        DialTarget::Named(name) => {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(name))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timed out")
                })??;
            tune_socket(&stream)?;
            stream
        }
    };
    Ok(stream)
}

fn target_to_string(target: &Target) -> String {
    match &target.host {
        Host::Domain(name) => format!("{name}:{}", target.port),
        other => format!("{other}:{}", target.port),
    }
}

fn describe(request: &OpenRequest) -> String {
    match request {
        OpenRequest::Raw => "forward".to_owned(),
        OpenRequest::Connect(target) => target.to_string(),
        OpenRequest::Udp => "udp".to_owned(),
    }
}
