use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use argh::FromArgs;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use itertools::Itertools;
use mutual_tls::AuthenticationLevel;

#[derive(Clone, Debug)]
pub struct Authorisation {
    pub protocol: AuthenticationLevel,
    pub chain: PathBuf,
    pub key: PathBuf,
}

pub struct Domain {
    pub host: String,
    pub authorisation: Authorisation,
}

impl FromStr for Domain {
    type Err = color_eyre::Report;

    fn from_str(value: &str) -> Result<Self> {
        let (host, protocol, chain, key) = value
            .splitn(4, ':')
            .collect_tuple()
            .ok_or_else(|| eyre!("invalid argument provided ({value})"))?;

        let authorisation = Authorisation {
            protocol: AuthenticationLevel::from_str(protocol)?,
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
pub struct Args {
    #[argh(option, description = "details for reverse proxying")]
    pub domains: Vec<Domain>,
    #[argh(option, description = "downstream server to proxy to")]
    pub downstream: String,
    #[argh(option, description = "path to the certificate to use for mTLS")]
    pub mtls_certificate: PathBuf,
    #[argh(option, description = "address to bind the server to")]
    pub addr: SocketAddr,
}
