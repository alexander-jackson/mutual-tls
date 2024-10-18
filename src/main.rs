use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use argh::FromArgs;
use color_eyre::eyre::{eyre, Result};
use http::header::{HOST, USER_AGENT};
use http::uri::PathAndQuery;
use http::{Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use itertools::Itertools;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
) -> Result<(Vec<CertificateDer<'static>>, Arc<dyn SigningKey>)> {
    let chain_path = chain_path.as_ref();
    let key_path = key_path.as_ref();

    let mut rdr = BufReader::new(File::open(chain_path)?);
    let server_certificate = rustls_pemfile::certs(&mut rdr).try_collect()?;
    tracing::info!(path = ?chain_path, "read a certificate chain for the server");

    let private_key = PrivateKeyDer::from_pem_file(key_path)?;
    tracing::info!(path = ?key_path, "read a private key for the server");

    let private_key = any_supported_type(&private_key)?;

    Ok((server_certificate, private_key))
}

async fn root(
    mut req: Request<Incoming>,
    downstream: Arc<str>,
) -> Result<Response<Incoming>, hyper::Error> {
    let method = req.method();
    let uri = req.uri();
    let host = req.headers().get(HOST);
    let user_agent = req.headers().get(USER_AGENT);

    tracing::info!(%method, %uri, ?host, ?user_agent, "handling a request");

    let client: Client<HttpConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build_http();

    let path_and_query = uri.path_and_query().map_or("/", PathAndQuery::as_str);

    *req.uri_mut() = format!("{downstream}{path_and_query}").parse().unwrap();

    let res = client.request(req).await.unwrap();

    Ok(res)
}

#[derive(Clone, Debug)]
struct CertificateResolver {
    certificates: Arc<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;

        self.certificates.get(server_name).cloned()
    }
}

#[derive(Debug)]
enum Protocol {
    Mutual,
    Public,
}

impl FromStr for Protocol {
    type Err = color_eyre::Report;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "mtls" => Ok(Self::Mutual),
            "public" => Ok(Self::Public),
            _ => Err(eyre!("invalid protocol '{value}' provided")),
        }
    }
}

#[derive(Debug)]
struct Authorisation {
    protocol: Protocol,
    chain: PathBuf,
    key: PathBuf,
}

struct Domain {
    host: String,
    authorisation: Authorisation,
}

impl FromStr for Domain {
    type Err = color_eyre::Report;

    fn from_str(value: &str) -> Result<Self> {
        let (host, protocol, chain, key) = value
            .splitn(4, ':')
            .collect_tuple()
            .ok_or_else(|| eyre!("invalid argument provided ({value})"))?;

        let authorisation = Authorisation {
            protocol: Protocol::from_str(protocol)?,
            chain: PathBuf::from(chain),
            key: PathBuf::from(key),
        };

        let domain = Self {
            host: host.to_owned(),
            authorisation,
        };

        Ok(domain)
    }
}

#[derive(FromArgs)]
#[argh(description = "program arguments")]
struct Args {
    #[argh(option, description = "details for reverse proxying")]
    domains: Vec<Domain>,
    #[argh(option, description = "downstream server to proxy to")]
    downstream: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let args: Args = argh::from_env();

    let domains: HashMap<_, _> = args
        .domains
        .iter()
        .map(|domain| (domain.host.to_owned(), &domain.authorisation))
        .collect();

    tracing::info!(?domains, "parsed some arguments for domains");

    let store = initialise_root_cert_store(ROOT_CERT_PATH)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;

    let mut certificates = HashMap::new();

    for (host, auth) in &domains {
        let (chain, key) = get_server_credentials(&auth.chain, &auth.key)?;

        certificates.insert(host.to_string(), Arc::new(CertifiedKey::new(chain, key)));
    }

    let resolver = CertificateResolver {
        certificates: Arc::new(certificates),
    };

    let no_auth_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver.clone())),
    );

    let mtls_config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(resolver)),
    );

    let downstream = Arc::from(args.downstream.as_str());

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443);
    let incoming = TcpListener::bind(addr).await?;

    tracing::info!(%addr, "listening for incoming requests");

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

                let config = domains
                    .get(server_name)
                    .map(|auth| match auth.protocol {
                        Protocol::Mutual => Arc::clone(&mtls_config),
                        Protocol::Public => Arc::clone(&no_auth_config),
                    })
                    .ok_or_else(|| eyre!("failed to get host from SNI"))?;

                let stream = match start.into_stream(config).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::debug!(?e, "failed to upgrade to a tls stream");

                        if let Some(mut stream) = acceptor.take_io() {
                            stream.write(b"foobar").await?;
                        }

                        continue;
                    }
                };

                let downstream = Arc::clone(&downstream);

                tokio::spawn(async move {
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|req| {
                                let downstream = Arc::clone(&downstream);

                                async move { root(req, downstream).await }
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
                            format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err).as_bytes(),
                        )
                        .await?;
                }
            }
        }
    }
}
