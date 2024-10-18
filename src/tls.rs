use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use color_eyre::eyre::Result;
use itertools::Itertools;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::RootCertStore;

pub fn initialise_root_cert_store<P: AsRef<Path>>(path: P) -> Result<RootCertStore> {
    let path = path.as_ref();

    let mut store = RootCertStore::empty();
    let mut rdr = BufReader::new(File::open(path)?);

    let certs = rustls_pemfile::certs(&mut rdr).filter_map(Result::ok);
    let (added, ignored) = store.add_parsable_certificates(certs);

    tracing::info!(?path, %added, %ignored, "set up the trust store");

    Ok(store)
}

pub fn get_server_credentials<C: AsRef<Path>, K: AsRef<Path>>(
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

#[derive(Clone, Debug)]
pub struct CertificateResolver {
    certificates: Arc<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateResolver {
    pub fn new(certificates: HashMap<String, Arc<CertifiedKey>>) -> Self {
        Self {
            certificates: Arc::new(certificates),
        }
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;

        self.certificates.get(server_name).cloned()
    }
}
