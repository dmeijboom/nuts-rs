use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

use biscuit::jwa::SignatureAlgorithm;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jws::{Compact, Header, Secret};
use biscuit::CompactJson;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use crate::network::Hash;
use crate::pki::{Key, KeyStore};

#[derive(Debug)]
pub enum ParseError {
    NutsValidationError(String),
    JoseError(biscuit::errors::Error),
    Other(anyhow::Error),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse transaction: {}",
            match self {
                ParseError::NutsValidationError(e) => format!("{}", e),
                ParseError::JoseError(e) => format!("{}", e),
                ParseError::Other(e) => format!("{}", e),
            }
        )
    }
}

impl Error for ParseError {}

impl From<biscuit::errors::Error> for ParseError {
    fn from(e: biscuit::errors::Error) -> Self {
        ParseError::JoseError(e)
    }
}

impl From<anyhow::Error> for ParseError {
    fn from(e: anyhow::Error) -> Self {
        ParseError::Other(e)
    }
}

pub type Result<T> = result::Result<T, ParseError>;

#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: Hash,
    pub data: Vec<u8>,
    pub prevs: Vec<Hash>,
    pub payload: Hash,
    pub payload_type: String,
    pub version: usize,
    pub key: Option<Key>,
    pub key_id: String,
    pub sign_at: NaiveDateTime,
    pub sign_algo: SignatureAlgorithm,
}

impl Transaction {
    /// A transaction is considered to be a root transaction if it doesn't have any previous transactions
    pub fn is_root(&self) -> bool {
        self.prevs.is_empty()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            id: Hash::default(),
            data: vec![],
            prevs: vec![],
            payload: Hash::default(),
            payload_type: "".to_string(),
            version: 0,
            key: None,
            key_id: "".to_string(),
            sign_at: NaiveDateTime::from_timestamp(0, 0),
            sign_algo: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionHeader {
    #[serde(rename = "ver")]
    pub version: usize,
    #[serde(rename = "sigt")]
    pub sign_time: i64,
    #[serde(rename = "prevs")]
    pub previous: Vec<String>,
}

impl CompactJson for TransactionHeader {}

fn parse_key(header: &Header<TransactionHeader>) -> Result<(Option<Key>, String)> {
    Ok(match &header.registered.key_id {
        Some(key_id) => (None, key_id.clone()),
        None => {
            let key = header.registered.web_key.clone().ok_or_else(|| {
                ParseError::NutsValidationError(
                    "unable to add transaction without key or key ID".to_string(),
                )
            })?;

            // Get the key ID either from the key itself or the from the key ID header
            let key_id = key
                .common
                .key_id
                .clone()
                .or_else(|| header.registered.key_id.clone())
                .ok_or_else(|| {
                    ParseError::NutsValidationError(
                        "missing ID for transaction signing key".to_string(),
                    )
                })?;

            (Some(key), key_id)
        }
    })
}

fn parse_transaction(
    raw: &str,
    header: &Header<TransactionHeader>,
    payload: &[u8],
) -> Result<Transaction> {
    let payload = Hash::parse_hex(payload)?;

    // Validate supported algorithms in line with: https://nuts-foundation.gitbook.io/drafts/rfc/rfc004-verifiable-transactional-graph#3-1-jws-implementation
    if !matches!(
        header.registered.algorithm,
        SignatureAlgorithm::ES256
            | SignatureAlgorithm::ES384
            | SignatureAlgorithm::ES512
            | SignatureAlgorithm::PS256
            | SignatureAlgorithm::PS384
            | SignatureAlgorithm::PS512
    ) {
        return Err(ParseError::NutsValidationError(format!(
            "unsupported algorithm: {:?}",
            header.registered.algorithm
        )));
    }

    let payload_type = header.registered.content_type.clone().ok_or_else(|| {
        ParseError::NutsValidationError("transaction is missing the payload-type".to_string())
    })?;
    let sign_at = NaiveDateTime::from_timestamp(header.private.sign_time, 0);
    let (key, key_id) = parse_key(header)?;

    let mut prevs = vec![];

    for hash in header.private.previous.iter() {
        prevs.push(Hash::parse_hex(hash.as_bytes())?);
    }

    let data = raw.as_bytes().to_vec();
    let id = Hash::new(&data)?;

    Ok(Transaction {
        id,
        data,
        prevs,
        payload,
        payload_type,
        version: header.private.version,
        key,
        key_id,
        sign_at,
        sign_algo: header.registered.algorithm,
    })
}

impl Transaction {
    /// Parses a transaction from the compact JWS representation without verifying the signature
    pub fn parse_unsafe(raw: impl AsRef<str>) -> Result<Transaction> {
        let compact: Compact<Vec<u8>, TransactionHeader> = Compact::new_encoded(raw.as_ref());

        parse_transaction(
            raw.as_ref(),
            &compact.unverified_header()?,
            &compact.unverified_payload()?,
        )
    }

    /// Parses and verifies a transaction from the compact JWS representation
    pub fn parse(store: &KeyStore, raw: impl AsRef<str>) -> Result<Transaction> {
        let compact: Compact<Vec<u8>, TransactionHeader> = Compact::new_encoded(raw.as_ref());
        let header = compact.unverified_header()?;
        let compact = match header.registered.web_key {
            None => compact.decode_with_jwks(store.as_ref(), None)?,
            Some(key) => compact.decode(
                &match key.algorithm {
                    AlgorithmParameters::RSA(rsa) => rsa.jws_public_key_secret(),
                    AlgorithmParameters::OctetKey(oct) => Secret::Bytes(oct.value.clone()),
                    _ => {
                        return Err(biscuit::errors::Error::ValidationError(
                            biscuit::errors::ValidationError::UnsupportedKeyAlgorithm,
                        )
                        .into())
                    }
                },
                header.registered.algorithm,
            )?,
        };

        parse_transaction(raw.as_ref(), compact.header()?, compact.payload()?)
    }
}
