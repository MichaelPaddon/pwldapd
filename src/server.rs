//! TCP listener management. Spawns one accept loop per listener address;
//! plain and TLS listeners run concurrently via a `JoinSet`. The server
//! exits as soon as any listener returns (normally because of a fatal error).

use crate::config::Config;
use crate::handler::handle_connection;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

pub async fn run(config: Config) -> Result<()> {
    let tls_acceptor = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(build_tls_acceptor(cert, key)?),
        _ => None,
    };

    let mut set: JoinSet<Result<()>> = JoinSet::new();

    for addr in &config.listen {
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {addr}");
        let cfg = config.clone();
        set.spawn(accept_plain(listener, cfg));
    }

    for addr in &config.tls_listen {
        let acceptor = tls_acceptor.clone()
            .expect("tls_acceptor set when tls_listen is non-empty");
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {addr} (TLS)");
        let cfg = config.clone();
        set.spawn(accept_tls(listener, acceptor, cfg));
    }

    for path in &config.unix_listen {
        // Remove a stale socket file left by a previous run.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)
            .map_err(|e| anyhow::anyhow!("cannot bind to {:?}: {e}", path))?;
        info!("Listening on {:?} (unix)", path);
        let cfg = config.clone();
        let p = path.clone();
        set.spawn(accept_unix(listener, cfg, p));
    }

    if set.is_empty() {
        anyhow::bail!("no listeners configured (listen, tls_listen, and unix_listen are all empty)");
    }

    // Return when any listener exits (normally an error).
    if let Some(res) = set.join_next().await {
        res??;
    }
    Ok(())
}

/// Accept loop for plain (non-TLS) connections. Runs until a fatal accept
/// error occurs; individual connection errors are logged and ignored.
async fn accept_plain(listener: TcpListener, config: Config) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = config.clone();
        let label = peer.to_string();
        tokio::spawn(async move {
            info!("Connection from {label}");
            if let Err(e) = handle_connection(stream, cfg, &label).await {
                error!("Connection error from {label}: {e}");
            }
        });
    }
}

/// Accept loop for TLS (LDAPS) connections. The TLS handshake is performed
/// before handing off to the connection handler; handshake errors are logged
/// and the connection is dropped without affecting the listener.
async fn accept_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: Config,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = config.clone();
        let acc = acceptor.clone();
        let label = peer.to_string();
        tokio::spawn(async move {
            info!("Connection from {label}");
            match acc.accept(stream).await {
                Ok(s) => {
                    if let Err(e) = handle_connection(s, cfg, &label).await {
                        error!("Connection error from {label}: {e}");
                    }
                }
                Err(e) => error!("TLS handshake error from {label}: {e}"),
            }
        });
    }
}

/// Accept loop for Unix domain socket connections.
async fn accept_unix(listener: UnixListener, config: Config, path: PathBuf) -> Result<()> {
    let label = format!("unix:{}", path.display());
    loop {
        let (stream, _peer) = listener.accept().await?;
        let cfg = config.clone();
        let lbl = label.clone();
        tokio::spawn(async move {
            info!("Connection on {lbl}");
            if let Err(e) = handle_connection(stream, cfg, &lbl).await {
                error!("Connection error on {lbl}: {e}");
            }
        });
    }
}

/// Build a `TlsAcceptor` from PEM certificate and private-key files.
fn build_tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TlsAcceptor> {
    use tokio_rustls::rustls::ServerConfig;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(
    path: &Path,
) -> Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn annotate_bind_error(e: std::io::Error, addr: &str) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        // Parse the port from the address to give a targeted hint.
        let port: Option<u16> = addr
            .rsplit(':')
            .next()
            .and_then(|p| p.trim_end_matches(']').parse().ok());
        if let Some(port) = port.filter(|&p| p < 1024) {
            return anyhow::anyhow!(
                "cannot bind to {addr}: permission denied\n\
                 Port {port} requires elevated privileges. Either:\n\
                 \x20 sudo setcap cap_net_bind_service=ep {}\n\
                 or set a high port in the config file (listen = [\"127.0.0.1:3389\"])",
                std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "pwldapd".into()),
            );
        }
    }
    anyhow::anyhow!("cannot bind to {addr}: {e}")
}

fn load_private_key(
    path: &Path,
) -> Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", path))
}
