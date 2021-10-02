use std::convert::TryInto;
use std::fmt::{Debug, Display, Formatter};

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
pub struct Hash([u8; 32]);

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

fn to_fixed(bytes: Vec<u8>) -> Result<[u8; 32]> {
    let output: Box<[u8; 32]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid length for SHA256 based hash"))?;

    Ok(*output)
}

impl Hash {
    pub fn new(data: impl AsRef<[u8]>) -> Result<Self> {
        let mut hasher = Sha256::new();

        hasher.update(data);

        let digest = hasher.finalize();

        Ok(Hash(to_fixed(digest.to_vec())?))
    }

    pub fn parse(source: Vec<u8>) -> Result<Self> {
        Ok(Hash(to_fixed(source)?))
    }

    pub fn parse_hex(source: &[u8]) -> Result<Self> {
        Self::parse(hex::decode(source)?)
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
