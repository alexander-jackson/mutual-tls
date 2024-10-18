use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use args::Authorisation;
use color_eyre::eyre::{eyre, Result};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{Acceptor, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod args;
mod proxy;
mod tls;

use crate::args::{Args, Protocol};
use crate::tls::CertificateResolver;

const ROOT_CERT_PATH: &str = "/certs/ca.crt";

fn setup() -> Result<()> {
    color_eyre::install()?;

    let fmt_layer = tracing_subscriber::fmt::layer();
    let env_filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()?;

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter_layer)
        .init();

    Ok(())
}

struct MutualTlsServer {
    domains: HashMap<String, Authorisation>,
    verifier: Arc<dyn ClientCertVerifier>,
    resolver: Arc<dyn ResolvesServerCert>,
    downstream: Arc<str>,
}

impl MutualTlsServer {
    async fn run(&self, addr: SocketAddr) -> Result<()> {
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

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let args: Args = argh::from_env();

    let domains: HashMap<_, _> = args
        .domains
        .iter()
        .map(|domain| (domain.host.to_owned(), domain.authorisation.clone()))
        .collect();

    tracing::info!(?domains, "parsed some arguments for domains");

    let store = crate::tls::initialise_root_cert_store(ROOT_CERT_PATH)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;

    let mut certificates = HashMap::new();

    for (host, auth) in &domains {
        let (chain, key) = crate::tls::get_server_credentials(&auth.chain, &auth.key)?;

        certificates.insert(host.to_string(), Arc::new(CertifiedKey::new(chain, key)));
    }

    let resolver = CertificateResolver::new(certificates);

    let server = MutualTlsServer {
        domains,
        verifier,
        resolver,
        downstream: Arc::from(args.downstream.as_str()),
    };

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443).into();
    server.run(addr).await?;

    Ok(())
}
