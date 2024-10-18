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

use crate::args::{Authorisation, Protocol};

pub struct MutualTlsServer {
    domains: HashMap<String, Authorisation>,
    verifier: Arc<dyn ClientCertVerifier>,
    resolver: Arc<dyn ResolvesServerCert>,
    downstream: Arc<str>,
}

impl MutualTlsServer {
    pub fn new(
        domains: HashMap<String, Authorisation>,
        verifier: Arc<dyn ClientCertVerifier>,
        resolver: Arc<dyn ResolvesServerCert>,
        downstream: Arc<str>,
    ) -> Self {
        Self {
            domains,
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
                    tracing::debug!(name = ?client_hello.server_name(), "the client greeted us");

                    let Some(server_name) = client_hello.server_name() else {
                        return Err(eyre!("failed to get host from SNI"));
                    };

                    let config = self
                        .domains
                        .get(server_name)
                        .map(|auth| match auth.protocol {
                            Protocol::Mutual => Arc::clone(&mtls_config),
                            Protocol::Public => Arc::clone(&default_config),
                        })
                        .ok_or_else(|| eyre!("failed to get host from SNI"))?;

                    let stream = match start.into_stream(config).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::debug!(?e, "failed to upgrade to a tls stream");

                            if let Some(mut stream) = acceptor.take_io() {
                                stream.write_all(b"foobar").await?;
                            }

                            continue;
                        }
                    };

                    let downstream = Arc::clone(&self.downstream);

                    tokio::spawn(async move {
                        if let Err(err) = Builder::new(TokioExecutor::new())
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|req| {
                                    let downstream = Arc::clone(&downstream);

                                    async move { crate::proxy::handle(req, downstream).await }
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
                                format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err)
                                    .as_bytes(),
                            )
                            .await?;
                    }
                }
            }
        }
    }
}