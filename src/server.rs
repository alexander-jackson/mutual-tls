use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use color_eyre::eyre::{eyre, Result};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{Acceptor, ResolvesServerCert};
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::args::Protocol;

pub struct MutualTlsServer {
    protocols: HashMap<String, Protocol>,
    verifier: Arc<dyn ClientCertVerifier>,
    resolver: Arc<dyn ResolvesServerCert>,
    downstream: Arc<str>,
}

impl MutualTlsServer {
    pub fn new(
        protocols: HashMap<String, Protocol>,
        verifier: Arc<dyn ClientCertVerifier>,
        resolver: Arc<dyn ResolvesServerCert>,
        downstream: Arc<str>,
    ) -> Self {
        Self {
            protocols,
            verifier,
            resolver,
            downstream,
        }
    }

    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let incoming = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "listening for incoming requests");

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

        loop {
            let (tcp_stream, _remote_addr) = incoming.accept().await?;
            let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);

            tokio::pin!(acceptor);

            match acceptor.as_mut().await {
                Ok(start) => {
                    let client_hello = start.client_hello();
                    let server_name = client_hello.server_name();
                    tracing::debug!(?server_name, "the client greeted us");

                    let Some(server_name) = server_name else {
                        if let Some(mut stream) = acceptor.take_io() {
                            stream
                                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                                .await?;
                        }

                        continue;
                    };

                    let config = self
                        .protocols
                        .get(server_name)
                        .map(|protocol| match protocol {
                            Protocol::Mutual => Arc::clone(&mtls_config),
                            Protocol::Public => Arc::clone(&default_config),
                        })
                        .ok_or_else(|| eyre!("failed to get host from SNI"))?;

                    let stream = match start.into_stream(config).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::debug!(?e, "failed to upgrade to a tls stream");

                            if let Some(mut stream) = acceptor.take_io() {
                                stream
                                    .write_all(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
                                    .await?;
                            }

                            continue;
                        }
                    };

                    let conn = stream.get_ref().1;

                    tracing::debug!(
                        certificates = ?conn.peer_certificates().map(|certs| certs.len()),
                        "acquired some certificates from the client"
                    );

                    let unit = if let Some(certs) = conn.peer_certificates() {
                        let (_, client_cert) = x509_parser::parse_x509_certificate(&certs[0])?;

                        let unit = client_cert
                            .tbs_certificate
                            .subject
                            .iter_organizational_unit()
                            .next()
                            .ok_or_else(|| eyre!("invalid certificate provided"))?
                            .as_str()?;

                        tracing::info!(?unit, "parsed a client certificate");

                        Some(unit.to_owned())
                    } else {
                        None
                    };

                    let downstream = Arc::clone(&self.downstream);

                    tokio::spawn(async move {
                        if let Err(err) = Builder::new(TokioExecutor::new())
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|req| {
                                    let downstream = Arc::clone(&downstream);
                                    let unit = unit.clone();

                                    async move { crate::proxy::handle(req, unit, downstream).await }
                                }),
                            )
                            .await
                        {
                            tracing::debug!(?err, "failed to serve connection");
                        }
                    });
                }
                Err(err) => {
                    if let Some(mut stream) = acceptor.take_io() {
                        stream
                            .write_all(
                                format!("HTTP/1.1 400 Bad Request\r\n\r\n\r\n{:?}\n", err)
                                    .as_bytes(),
                            )
                            .await?;
                    }
                }
            }
        }
    }
}
