use std::{borrow::Cow, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use axum::Router;
use axum_server::{accept::Accept, Handle};
use pem::parse_many;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Notify,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::warn;

use crate::{application::logging::LogEvent, domain::DescribeError};

use super::WebTlsConfig;

pub enum TlsConfig {
    Http(SocketAddr),
    Https(SocketAddr, Arc<ServerConfig>),
}

pub async fn build_tls_config(
    addr: SocketAddr,
    tls: Option<&WebTlsConfig>,
) -> Result<TlsConfig, DescribeError> {
    if let Some(tls_cfg) = tls {
        let rustls = build_rustls_config(tls_cfg).await?;
        Ok(TlsConfig::Https(addr, rustls))
    } else {
        Ok(TlsConfig::Http(addr))
    }
}

pub async fn serve(
    router: Router,
    cfg: TlsConfig,
    interval_secs: f64,
    shutdown: Arc<Notify>,
) -> Result<(), DescribeError> {
    match cfg {
        TlsConfig::Http(addr) => run_http_plain(router, addr, interval_secs, shutdown).await,
        TlsConfig::Https(addr, rustls) => {
            run_http_tls(router, rustls, addr, interval_secs, shutdown).await
        }
    }
}

async fn run_http_plain(
    router: Router,
    bind_addr: SocketAddr,
    interval_secs: f64,
    shutdown: Arc<Notify>,
) -> Result<(), DescribeError> {
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(err) => {
            let msg = err.to_string();
            LogEvent::HttpBindFailed {
                addr: Cow::Owned(bind_addr.to_string()),
                error: Cow::Owned(msg),
            }
            .emit();
            return Err(map_io(err));
        }
    };
    let actual = listener.local_addr().unwrap_or(bind_addr);
    LogEvent::HttpServerStarted {
        addr: Cow::Owned(format!("http://{}", actual)),
        interval_s: interval_secs,
        tls: false,
    }
    .emit();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown.clone()))
    .await
    .map_err(map_io)
}

async fn run_http_tls(
    router: Router,
    rustls: Arc<ServerConfig>,
    bind_addr: SocketAddr,
    interval_secs: f64,
    shutdown: Arc<Notify>,
) -> Result<(), DescribeError> {
    LogEvent::HttpServerStarted {
        addr: Cow::Owned(format!("https://{}", bind_addr)),
        interval_s: interval_secs,
        tls: true,
    }
    .emit();
    let handle = Handle::new();
    let notify = shutdown.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_task = tokio::spawn({
        let handle = handle.clone();
        async move {
            tokio::select! {
                _ = wait_for_shutdown(notify) => handle.shutdown(),
                _ = shutdown_rx => {}
            }
        }
    });
    let tls_acceptor = RustlsAcceptor::new(rustls);
    let result = axum_server::bind(bind_addr)
        .acceptor(tls_acceptor)
        .handle(handle)
        .serve(
            router
                .clone()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    let _ = shutdown_tx.send(());
    let _ = shutdown_task.await;
    result.map_err(map_io)
}

async fn wait_for_shutdown(notify: Arc<Notify>) {
    let signal = wait_for_shutdown_signal().await;
    LogEvent::HttpServerShutdown {
        signal: Cow::Owned(signal.to_string()),
    }
    .emit();
    notify.notify_waiters();
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> &'static str {
    use std::future::pending;
    use tokio::signal::unix::{signal as unix_signal, SignalKind};

    let mut sigterm = unix_signal(SignalKind::terminate()).ok();
    let mut sighup = unix_signal(SignalKind::hangup()).ok();

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            match res {
                Ok(()) => "ctrl_c",
                Err(err) => {
                    warn!(error = ?err, "ctrl_c_wait_failed");
                    "ctrl_c_error"
                }
            }
        }
        _ = async {
            if let Some(signal) = sigterm.as_mut() {
                signal.recv().await;
            } else {
                pending::<()>().await;
            }
        } => "sigterm",
        _ = async {
            if let Some(signal) = sighup.as_mut() {
                signal.recv().await;
            } else {
                pending::<()>().await;
            }
        } => "sighup",
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> &'static str {
    match tokio::signal::ctrl_c().await {
        Ok(()) => "ctrl_c",
        Err(err) => {
            warn!(error = ?err, "ctrl_c_wait_failed");
            "ctrl_c_error"
        }
    }
}

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}

async fn build_rustls_config(cfg: &WebTlsConfig) -> Result<Arc<ServerConfig>, DescribeError> {
    let cert = cfg.cert_path.trim();
    let key = cfg.key_path.trim();
    if cert.is_empty() || key.is_empty() {
        return Err(DescribeError::Config(
            "web.tls nécessite cert_path et key_path".into(),
        ));
    }
    let cert_bytes = tokio::fs::read(cert)
        .await
        .map_err(|err| DescribeError::Config(format!("lecture certificat {cert}: {err}")))?;
    let cert_chain = load_cert_chain(&cert_bytes, cert)?;
    let key_bytes = tokio::fs::read(key)
        .await
        .map_err(|err| DescribeError::Config(format!("lecture clé {key}: {err}")))?;
    let private_key = load_private_key(&key_bytes, key)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| DescribeError::Config(format!("config TLS {cert}/{key}: {err}")))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn load_cert_chain(
    bytes: &[u8],
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, DescribeError> {
    let blocks = parse_many(bytes)
        .map_err(|err| DescribeError::Config(format!("certificat PEM {path}: {err}")))?;
    let certs: Vec<_> = blocks
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| CertificateDer::from(block.into_contents()))
        .collect();
    if certs.is_empty() {
        return Err(DescribeError::Config(format!(
            "certificat PEM {path}: aucun bloc CERTIFICATE détecté"
        )));
    }
    Ok(certs)
}

fn load_private_key(bytes: &[u8], path: &str) -> Result<PrivateKeyDer<'static>, DescribeError> {
    let blocks =
        parse_many(bytes).map_err(|err| DescribeError::Config(format!("clé PEM {path}: {err}")))?;
    for block in blocks {
        match block.tag() {
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                match PrivateKeyDer::try_from(block.into_contents()) {
                    Ok(key) => return Ok(key),
                    Err(err) => {
                        warn!(error = %err, "tls_private_key_parse_failed");
                    }
                }
            }
            _ => continue,
        }
    }
    Err(DescribeError::Config(format!(
        "clé PEM {path}: aucune clé privée reconnue (PRIVATE KEY / RSA PRIVATE KEY / EC PRIVATE KEY attendue)"
    )))
}

#[derive(Clone)]
struct RustlsAcceptor {
    tls: TlsAcceptor,
}

impl RustlsAcceptor {
    fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            tls: TlsAcceptor::from(config),
        }
    }
}

impl<S> Accept<TcpStream, S> for RustlsAcceptor
where
    S: Send + 'static,
{
    type Stream = TlsStream<TcpStream>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let tls = self.tls.clone();
        let peer_addr = stream.peer_addr().ok();
        Box::pin(async move {
            match tls.accept(stream).await {
                Ok(stream) => Ok((stream, service)),
                Err(err) => {
                    if let Some(addr) = peer_addr {
                        warn!(error = ?err, %addr, "tls_handshake_failed");
                    } else {
                        warn!(error = ?err, "tls_handshake_failed");
                    }
                    Err(err)
                }
            }
        })
    }
}
