use std::sync::Arc;

use args::{Authorisation, Domain};
use color_eyre::eyre::Result;
use hyper::service::service_fn;
use rustls::server::{ResolvesServerCertUsingSni, WebPkiClientVerifier};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod args;
mod proxy;
mod server;
mod tls;

use crate::args::Args;
use crate::server::{ConnectionContext, MutualTlsServer};

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

    let Args {
        domains,
        downstream,
        mtls_certificate,
        addr,
    } = argh::from_env();

    let protocols = domains
        .iter()
        .map(|domain| (domain.host.to_owned(), domain.authorisation.protocol))
        .collect();

    tracing::info!(?protocols, "parsed some arguments for protocols");

    let store = crate::tls::initialise_root_cert_store(mtls_certificate)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;

    let mut resolver = ResolvesServerCertUsingSni::new();

    for domain in &domains {
        let Domain {
            host,
            authorisation: Authorisation { chain, key, .. },
        } = domain;

        resolver.add(host, crate::tls::get_certified_key(chain, key)?)?;
    }

    let downstream = Arc::from(downstream.as_str());

    let service_factory = |ctx: ConnectionContext| {
        let downstream = Arc::clone(&downstream);
        let ctx = ctx.clone();

        service_fn(move |req| {
            let downstream = Arc::clone(&downstream);
            let ctx = ctx.clone();

            async move { crate::proxy::handle(req, ctx, downstream).await }
        })
    };

    let server = MutualTlsServer::new(protocols, verifier, Arc::new(resolver), service_factory);

    server.run(addr).await?;

    Ok(())
}
