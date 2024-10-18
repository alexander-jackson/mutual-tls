use std::path::PathBuf;
use std::str::FromStr;

use argh::FromArgs;
use color_eyre::eyre::eyre;
use color_eyre::{Report, Result};
use itertools::Itertools;

#[derive(Debug)]
pub enum Protocol {
    Mutual,
    Public,
}

impl FromStr for Protocol {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "mtls" => Ok(Self::Mutual),
            "public" => Ok(Self::Public),
            _ => Err(eyre!("invalid protocol '{value}' provided")),
        }
    }
}

#[derive(Debug)]
pub struct Authorisation {
    pub protocol: Protocol,
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
pub struct Args {
    #[argh(option, description = "details for reverse proxying")]
    pub domains: Vec<Domain>,
    #[argh(option, description = "downstream server to proxy to")]
    pub downstream: String,
}
