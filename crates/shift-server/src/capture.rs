//! Staged reading of the camouflage-mode connection preamble: a TLS
//! ClientHello record carrying the Shift `ClientInit`, and — after the
//! server flight — the client's ChangeCipherSpec. Every stage appends to
//! the same `capture` buffer and addresses it by absolute offset, so the
//! bytes can always be handed to the decoy fallback verbatim if
//! interpretation fails at any point.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use shift_proto::masquerade::{self, ParsedClientHello, RECORD_HANDSHAKE, RECORD_HEADER_LEN};

const MAX_CLIENT_HELLO_LEN: usize = 4096;

/// Marker error meaning "stop trying to interpret this connection as a
/// Shift client; hand `capture` to the decoy fallback as-is."
pub(crate) struct FallbackNow;

/// Reads the ClientHello record from the start of the connection. Returns
/// its parsed fields alongside how many bytes of `capture` it
/// occupies, so the next stage knows where to continue reading from.
/// `capture` may end up holding a few bytes beyond that boundary already —
/// TCP has no message framing, so a single `read_buf` can pull in the
/// start of the next record too; every stage therefore addresses `capture`
/// by absolute offset rather than by `capture.len()` at call time.
pub(crate) async fn read_client_hello(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    timeout: Duration,
) -> Result<(ParsedClientHello, usize), FallbackNow> {
    let read = async {
        if !ensure_captured(stream, capture, RECORD_HEADER_LEN).await {
            return Err(FallbackNow);
        }
        if capture[0] != RECORD_HANDSHAKE {
            return Err(FallbackNow);
        }
        let len = u16::from_be_bytes([capture[3], capture[4]]) as usize;
        if len == 0 || len > MAX_CLIENT_HELLO_LEN {
            return Err(FallbackNow);
        }
        let total = RECORD_HEADER_LEN + len;
        if !ensure_captured(stream, capture, total).await {
            return Err(FallbackNow);
        }
        let body = &capture[RECORD_HEADER_LEN..total];
        match masquerade::parse_client_hello(body) {
            Ok(parsed) => Ok((parsed, total)),
            Err(_) => Err(FallbackNow),
        }
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(FallbackNow),
    }
}

/// Waits for the client's ChangeCipherSpec record at absolute offset
/// `offset` within `capture`, the last step of the TLS-shaped handshake.
/// See [`read_client_hello`] for why offsets are absolute.
pub(crate) async fn read_change_cipher_spec(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    offset: usize,
    timeout: Duration,
) -> Result<(), FallbackNow> {
    let total = offset + masquerade::CHANGE_CIPHER_SPEC_RECORD.len();
    let read = async {
        if !ensure_captured(stream, capture, total).await {
            return Err(FallbackNow);
        }
        if capture[offset..total] != masquerade::CHANGE_CIPHER_SPEC_RECORD[..] {
            return Err(FallbackNow);
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(FallbackNow),
    }
}

/// Grows `capture` (appending, never discarding) until it holds at least
/// `need_total` bytes from the start of the connection, regardless of
/// whether the read ultimately succeeds — so a caller can always hand the
/// exact bytes seen so far to the decoy fallback. Returns `false` on EOF
/// or a socket error before that many bytes arrived. `capture` may end up
/// slightly longer than `need_total`, since a single `read_buf` call can
/// pull in more than requested when the OS has more already buffered.
pub(crate) async fn ensure_captured(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    need_total: usize,
) -> bool {
    while capture.len() < need_total {
        capture.reserve(need_total - capture.len());
        match stream.read_buf(capture).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    true
}
