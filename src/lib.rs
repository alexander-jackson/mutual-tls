//! This crate provides a server implementation that supports both standard TLS and mutual TLS
//! (mTLS) authentication.
//!
//! It allows for dynamic resolution of authentication levels based on the requested server name
//! and provides a flexible way to handle client connections with different authentication
//! requirements.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{eyre, Report, Result};
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{Acceptor, ResolvesServerCert};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;
use tracing::Instrument;

/// Represents the authentication level for a connection.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationLevel {
    /// Standard TLS, without mutual authentication.
    Standard,
    /// Mutual TLS, requiring client certificates.
    Mutual,
}

impl FromStr for AuthenticationLevel {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "mutual" => Ok(Self::Mutual),
            "standard" => Ok(Self::Standard),
            _ => Err(eyre!("invalid protocol '{value}' provided")),
        }
    }
}

/// Represents the context of a connection.
#[derive(Clone, Debug)]
pub struct ConnectionContext {
    /// The common name provided on the client certificate, if using mTLS.
    pub common_name: Option<String>,
}

/// A trait for verifying client certificates in a server context.
pub trait AuthenticationLevelResolver: Send + Sync {
    /// Resolves the authentication level for a given domain.
    ///
    /// Returning [`Option::None`] indicates that the domain is not recognized. Implementations should always
    /// return an authentication level for known domains.
    fn resolve(&self, domain: &str) -> Option<AuthenticationLevel>;
}

/// A resolver for authentication levels based on static configuration.
pub struct StaticAuthenticationLevelResolver {
    inner: HashMap<String, AuthenticationLevel>,
}

impl StaticAuthenticationLevelResolver {
    /// Creates a new instance of [`StaticAuthenticationLevelResolver`] with the provided mapping.
    ///
    /// # Examples
    /// ```
    /// # use std::collections::HashMap;
    /// # use mutual_tls::{StaticAuthenticationLevelResolver, AuthenticationLevel};
    /// let mut levels = HashMap::new();
    /// levels.insert("example.com".to_string(), AuthenticationLevel::Standard);
    /// levels.insert("private.example.com".to_string(), AuthenticationLevel::Mutual);
    ///
    /// let resolver = StaticAuthenticationLevelResolver::new(levels);
    /// ```
    pub fn new(inner: HashMap<String, AuthenticationLevel>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl AuthenticationLevelResolver for StaticAuthenticationLevelResolver {
    fn resolve(&self, domain: &str) -> Option<AuthenticationLevel> {
        self.inner.get(domain).copied()
    }
}

/// Represents the timeout configuration for the server.
#[derive(Copy, Clone, Debug)]
pub struct ServerTimeouts {
    /// Timeout for the client to say hello.
    hello_timeout: Duration,
    /// Timeout for the entire connection.
    connection_timeout: Duration,
}

impl ServerTimeouts {
    /// Creates a new instance of [`ServerTimeouts`] with the specified timeouts.
    pub fn new(hello_timeout: Duration, connection_timeout: Duration) -> Self {
        Self {
            hello_timeout,
            connection_timeout,
        }
    }
}

impl Default for ServerTimeouts {
    fn default() -> Self {
        Self {
            hello_timeout: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(30),
        }
    }
}

/// Represents the configuration for the server.
#[derive(Copy, Clone, Debug, Default)]
pub struct ServerConfiguration {
    /// Timeouts for various operations in the server.
    timeouts: ServerTimeouts,
}

impl ServerConfiguration {
    /// Creates a new instance of [`ServerConfiguration`] with the specified timeouts.
    pub fn new(timeouts: ServerTimeouts) -> Self {
        Self { timeouts }
    }
}

/// Represents a server that handles incoming connections and serves requests.
pub struct Server<F> {
    /// Information about which domains are using mTLS or not.
    authentication_level_resolver: Arc<dyn AuthenticationLevelResolver>,
    /// Verifier for client certificates, when using mTLS.
    client_certificate_verifier: Arc<dyn ClientCertVerifier>,
    /// Resolver for server certificates, based on the SNI host.
    server_certificate_resolver: Arc<dyn ResolvesServerCert>,
    /// Factory for creating services to handle client connections.
    service_factory: Arc<F>,
    /// Configuration for the server.
    configuration: Arc<ServerConfiguration>,
}

impl<F, S> Server<F>
where
    F: Fn(ConnectionContext) -> S + Send + Sync + 'static,
    S: Service<Request<Incoming>, Response = Response<BoxBody<Bytes, hyper::Error>>>
        + Send
        + 'static,
    S::Future: 'static,
    <S as Service<Request<Incoming>>>::Future: Send,
    <S as Service<Request<Incoming>>>::Error: Into<Box<dyn Error + Send + Sync>>,
{
    /// Creates a new instance of the server.
    pub fn new(
        authentication_level_resolver: Arc<dyn AuthenticationLevelResolver>,
        client_certificate_verifier: Arc<dyn ClientCertVerifier>,
        server_certificate_resolver: Arc<dyn ResolvesServerCert>,
        service_factory: F,
        configuration: ServerConfiguration,
    ) -> Self {
        Self {
            authentication_level_resolver,
            client_certificate_verifier,
            server_certificate_resolver,
            service_factory: Arc::new(service_factory),
            configuration: Arc::new(configuration),
        }
    }

    /// Runs the server on the provided address.
    pub async fn run(&self, mut listener: TcpListener) {
        loop {
            if let Err(e) = self.try_handle_connection(&mut listener).await {
                tracing::warn!(%e, "failed to handle connection");
            } else {
                tracing::trace!("handled a connection from a client");
            }
        }
    }

    async fn try_handle_connection(&self, listener: &mut TcpListener) -> Result<()> {
        let default_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&self.server_certificate_resolver)),
        );

        let mtls_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::clone(&self.client_certificate_verifier))
                .with_cert_resolver(Arc::clone(&self.server_certificate_resolver)),
        );

        let (tcp_stream, remote_addr) = listener.accept().await?;
        let span = tracing::info_span!("connection", %remote_addr);
        let _enter = span.enter();

        tracing::trace!("accepted a connection from a client");

        let authentication_level_resolver = Arc::clone(&self.authentication_level_resolver);
        let mtls_config = Arc::clone(&mtls_config);
        let default_config = Arc::clone(&default_config);
        let service_factory = Arc::clone(&self.service_factory);
        let configuration = Arc::clone(&self.configuration);

        let future = async move {
            let timeout = configuration.timeouts.connection_timeout;
            let future = handle_connection(
                tcp_stream,
                remote_addr,
                authentication_level_resolver,
                mtls_config,
                default_config,
                service_factory,
                configuration,
            );

            let Ok(res) = tokio::time::timeout(timeout, future).await else {
                tracing::debug!("client did not say hello in time");
                return;
            };

            if let Err(e) = res {
                tracing::debug!(%e, "failed to handle connection");
            }
        };

        let span = tracing::info_span!("handle_connection", %remote_addr);
        let instrumented = future.instrument(span);

        tokio::spawn(instrumented);

        Ok(())
    }
}

async fn handle_connection<F, S>(
    tcp_stream: TcpStream,
    remote_addr: SocketAddr,
    authentication_level_resolver: Arc<dyn AuthenticationLevelResolver>,
    mtls_config: Arc<rustls::ServerConfig>,
    default_config: Arc<rustls::ServerConfig>,
    service_factory: Arc<F>,
    configuration: Arc<ServerConfiguration>,
) -> Result<()>
where
    F: Fn(ConnectionContext) -> S,
    S: Service<Request<Incoming>, Response = Response<BoxBody<Bytes, hyper::Error>>>
        + Send
        + 'static,
    S::Future: 'static,
    <S as Service<Request<Incoming>>>::Future: Send,
    <S as Service<Request<Incoming>>>::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);
    tokio::pin!(acceptor);

    tracing::trace!(%remote_addr, "waiting for the client to say hello");

    let timeout = configuration.timeouts.hello_timeout;
    let future = acceptor.as_mut();

    let Ok(accepted) = tokio::time::timeout(timeout, future).await else {
        tracing::debug!(%remote_addr, "client did not say hello in time");
        handle_bad_request(&mut acceptor).await?;
        return Ok(());
    };

    match accepted {
        Ok(start) => {
            let client_hello = start.client_hello();
            let server_name = client_hello.server_name();
            tracing::debug!(?server_name, "the client greeted us");

            let Some(server_name) = server_name else {
                tracing::trace!(%remote_addr, "client did not provide a server name");
                handle_bad_request(&mut acceptor).await?;
                return Ok(());
            };

            let Some(config) = authentication_level_resolver
                .resolve(server_name)
                .map(|protocol| match protocol {
                    AuthenticationLevel::Mutual => Arc::clone(&mtls_config),
                    AuthenticationLevel::Standard => Arc::clone(&default_config),
                })
            else {
                tracing::trace!(%remote_addr, %server_name, "client request did not match a known server name");
                handle_bad_request(&mut acceptor).await?;
                return Ok(());
            };

            tracing::trace!(%remote_addr, "converting the start into a proper stream");

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
            let service = (service_factory)(ctx);

            tracing::trace!("spawning a task to serve the connection");

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::{
        AuthenticationLevel, AuthenticationLevelResolver, StaticAuthenticationLevelResolver,
    };

    #[test]
    fn static_authenticate_level_resolver_works_as_expected() {
        let public_domain = "example.com";
        let private_domain = "private.example.com";
        let unknown_domain = "unknown.com";

        let mut levels = HashMap::new();
        levels.insert(public_domain.to_string(), AuthenticationLevel::Standard);
        levels.insert(private_domain.to_string(), AuthenticationLevel::Mutual);

        let resolver = StaticAuthenticationLevelResolver::new(levels);

        assert_eq!(
            resolver.resolve(public_domain),
            Some(AuthenticationLevel::Standard)
        );

        assert_eq!(
            resolver.resolve(private_domain),
            Some(AuthenticationLevel::Mutual)
        );

        assert_eq!(resolver.resolve(unknown_domain), None);
    }

    #[test]
    fn can_parse_authentication_levels_from_strings() {
        assert_eq!(
            AuthenticationLevel::from_str("mutual").unwrap(),
            AuthenticationLevel::Mutual
        );

        assert_eq!(
            AuthenticationLevel::from_str("standard").unwrap(),
            AuthenticationLevel::Standard
        );

        assert!(AuthenticationLevel::from_str("invalid").is_err());
    }
}
