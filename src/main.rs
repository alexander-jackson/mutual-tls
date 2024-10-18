use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use color_eyre::eyre::Result;
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use server::MutualTlsServer;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod args;
mod proxy;
mod server;
mod tls;

use crate::args::Args;
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

    let server = MutualTlsServer::new(
        domains,
        verifier,
        resolver,
        Arc::from(args.downstream.as_str()),
    );

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443).into();
    server.run(addr).await?;

    Ok(())
}
