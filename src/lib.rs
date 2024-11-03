use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

use color_eyre::eyre::{eyre, Report, Result};
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{Acceptor, ResolvesServerCert};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

#[derive(Copy, Clone, Debug)]
pub enum Protocol {
    Mutual,
    Public,
}

impl FromStr for Protocol {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "mtls" => Ok(Self::Mutual),
            "public" => Ok(Self::Public),
            _ => Err(eyre!("invalid protocol '{value}' provided")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionContext {
    /// The common name provided on the client certificate, if using mTLS.
    pub common_name: Option<String>,
}

pub struct MutualTlsServer<F> {
    /// Information about which domains are using mTLS or not.
    protocols: HashMap<String, Protocol>,
    /// Verifier for client certificates, when using mTLS.
    verifier: Arc<dyn ClientCertVerifier>,
    /// Resolver for server certificates, based on the SNI host.
    resolver: Arc<dyn ResolvesServerCert>,
    /// Factory for creating services to handle client connections.
    service_factory: F,
}

impl<F, S> MutualTlsServer<F>
where
    F: Fn(ConnectionContext) -> S,
    S: Service<Request<Incoming>, Response = Response<BoxBody<Bytes, hyper::Error>>>
        + Send
        + 'static,
    S::Future: 'static,
    <S as Service<Request<Incoming>>>::Future: Send,
    <S as Service<Request<Incoming>>>::Error: Into<Box<dyn Error + Send + Sync>>,
{
    /// Creates a new instance of the server.
    pub fn new(
        protocols: HashMap<String, Protocol>,
        verifier: Arc<dyn ClientCertVerifier>,
        resolver: Arc<dyn ResolvesServerCert>,
        service_factory: F,
    ) -> Self {
        Self {
            protocols,
            verifier,
            resolver,
            service_factory,
        }
    }

    /// Runs the server on the provided address.
    pub async fn run(&self, mut listener: TcpListener) {
        loop {
            if let Err(e) = self.try_handle_connection(&mut listener).await {
                tracing::warn!(%e, "failed to handle connection");
            }
        }
    }

    async fn try_handle_connection(&self, listener: &mut TcpListener) -> Result<()> {
        let default_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&self.resolver)),
        );

        let mtls_config = Arc::new(
            ServerConfig::builder()
                .with_client_cert_verifier(Arc::clone(&self.verifier))
                .with_cert_resolver(Arc::clone(&self.resolver)),
        );

        let (tcp_stream, _remote_addr) = listener.accept().await?;
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);

        tokio::pin!(acceptor);

        match acceptor.as_mut().await {
            Ok(start) => {
                let client_hello = start.client_hello();
                let server_name = client_hello.server_name();
                tracing::debug!(?server_name, "the client greeted us");

                let Some(server_name) = server_name else {
                    handle_bad_request(&mut acceptor).await?;
                    return Ok(());
                };

                let Some(config) = self
                    .protocols
                    .get(server_name)
                    .map(|protocol| match protocol {
                        Protocol::Mutual => Arc::clone(&mtls_config),
                        Protocol::Public => Arc::clone(&default_config),
                    })
                else {
                    handle_bad_request(&mut acceptor).await?;
                    return Ok(());
                };

                let stream = match start.into_stream(config).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::debug!(?e, "failed to upgrade to a tls stream");
                        handle_bad_request(&mut acceptor).await?;
                        return Ok(());
                    }
                };

                let conn = stream.get_ref().1;

                tracing::debug!(
                    certificates = ?conn.peer_certificates().map(|certs| certs.len()),
                    "acquired some certificates from the client"
                );

                let common_name = if let Some(certs) = conn.peer_certificates() {
                    let (_, client_cert) = x509_parser::parse_x509_certificate(&certs[0])?;

                    let common_name = client_cert
                        .subject
                        .iter_common_name()
                        .next()
                        .ok_or_else(|| eyre!("invalid certificate provided"))?
                        .as_str()?;

                    tracing::info!(?common_name, "parsed a client certificate");

                    Some(common_name.to_owned())
                } else {
                    None
                };

                let ctx = ConnectionContext { common_name };
                let service = (self.service_factory)(ctx);

                tokio::spawn(async move {
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::debug!(?err, "failed to serve connection");
                    }
                });
            }
            Err(err) => {
                tracing::debug!(?err, "error occurred when accepting connections");

                handle_bad_request(&mut acceptor).await?;
            }
        }

        Ok(())
    }
}

async fn handle_bad_request<IO: AsyncRead + AsyncWrite + Unpin>(
    acceptor: &mut LazyConfigAcceptor<IO>,
) -> Result<()> {
    if let Some(mut stream) = acceptor.take_io() {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
    }

    Ok(())
}
