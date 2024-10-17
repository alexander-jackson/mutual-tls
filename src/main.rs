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
use itertools::Itertools;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const ROOT_CERT_PATH: &str = "certs/ca.crt";
const CERT_CHAIN_PATH: &str = "certs/localhost.bundle.crt";
const KEY_PATH: &str = "certs/localhost.key";

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

fn get_server_credentials<C: AsRef<Path>, K: AsRef<Path>>(
    chain_path: C,
    key_path: K,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let chain_path = chain_path.as_ref();
    let key_path = key_path.as_ref();

    let mut rdr = BufReader::new(File::open(chain_path)?);
    let server_certificate = rustls_pemfile::certs(&mut rdr).try_collect()?;
    tracing::info!(path = ?chain_path, "read a certificate chain for the server");

    let private_key = PrivateKeyDer::from_pem_file(key_path)?;
    tracing::info!(path = ?key_path, "read a private key for the server");

    Ok((server_certificate, private_key))
}

async fn root(req: Request<Incoming>) -> Result<Response<String>, hyper::Error> {
    tracing::info!(?req, "handling a request");

    Ok(Response::new("foobar".to_owned()))
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let store = initialise_root_cert_store(ROOT_CERT_PATH)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;

    let (certificate_chain, private_key) = get_server_credentials(CERT_CHAIN_PATH, KEY_PATH)?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)?;

    let config = Arc::new(config);

    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000);
    let incoming = TcpListener::bind(addr).await?;

    tracing::info!(%addr, "listening for incoming requests");

    let service = service_fn(root);

    loop {
        let (tcp_stream, _remote_addr) = incoming.accept().await?;
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);

        tokio::pin!(acceptor);

        match acceptor.as_mut().await {
            Ok(start) => {
                let client_hello = start.client_hello();
                tracing::info!(name = ?client_hello.server_name(), "the client greeted us");

                let config = Arc::clone(&config);
                let stream = start.into_stream(config).await.unwrap();

                tokio::spawn(async move {
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::error!(?err, "failed to serve connection");
                    }
                });
            }
            Err(err) => {
                if let Some(mut stream) = acceptor.take_io() {
                    stream
                        .write_all(
                            format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err).as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            }
        }
    }
}
