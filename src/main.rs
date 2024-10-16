use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;

use color_eyre::eyre::Result;
use http::{Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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

fn initialise_root_cert_store<P: AsRef<Path>>(path: P) -> Result<RootCertStore> {
    let path = path.as_ref();

    let mut store = RootCertStore::empty();
    let mut rdr = BufReader::new(File::open(path)?);

    let certs = rustls_pemfile::certs(&mut rdr).filter_map(Result::ok);
    let (added, ignored) = store.add_parsable_certificates(certs);

    tracing::info!(?path, %added, %ignored, "set up the trust store");

    Ok(store)
}

async fn root(req: Request<Incoming>) -> Result<Response<String>, hyper::Error> {
    tracing::info!(?req, "handling a request");

    Ok(Response::new("foobar".to_owned()))
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let store = initialise_root_cert_store("certs/ca.crt")?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;

    let server_certificate = rustls_pemfile::certs(&mut BufReader::new(File::open(
        "certs/localhost.bundle.crt",
    )?))
    .filter_map(Result::ok)
    .collect();

    let private_key = PrivateKeyDer::from_pem_file("certs/localhost.key")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certificate, private_key)?;

    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000);

    let incoming = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    tracing::info!(%addr, "listening for incoming requests");

    let service = service_fn(root);

    loop {
        let (tcp_stream, _remote_addr) = incoming.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    tracing::error!(?err, "failed to perform tls handshake");
                    return;
                }
            };

            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                tracing::error!(?err, "failed to serve connection");
            }
        });
    }
}
