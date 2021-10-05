use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

use anyhow::anyhow;
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jws::{Compact, Header, Secret};
use biscuit::CompactJson;
use chrono::NaiveDateTime;
use ecdsa::signature::Verifier;
use ecdsa::{EncodedPoint, Signature, VerifyingKey};
use p256::NistP256;
use serde::{Deserialize, Serialize};

use crate::network::Hash;
use crate::pki::{Key, KeyStore};

#[derive(Debug)]
pub enum ParseError {
    NutsValidationError(String),
    JoseError(biscuit::errors::Error),
    ECDSAError(ecdsa::Error),
    Other(anyhow::Error),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse transaction: {}",
            match self {
                ParseError::NutsValidationError(e) => e.to_string(),
                ParseError::JoseError(e) => e.to_string(),
                ParseError::ECDSAError(e) => e.to_string(),
                ParseError::Other(e) => e.to_string(),
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

impl From<ecdsa::Error> for ParseError {
    fn from(e: ecdsa::Error) -> Self {
        ParseError::ECDSAError(e)
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
    Ok(match &header.registered.web_key {
        Some(key) => {
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

            (Some(key.clone()), key_id)
        }
        None => {
            let key_id = header.registered.key_id.clone().ok_or_else(|| {
                ParseError::NutsValidationError(
                    "unable to add transaction without key or key ID".to_string(),
                )
            })?;

            (None, key_id)
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
        let (key, key_id) = parse_key(&header)?;
        let key = if let Some(key) = key {
            key
        } else {
            store
                .get(&key_id)?
                .ok_or_else(|| anyhow!("unable to find verification key: {}", key_id))?
        };
        let compact = compact.decode(
            &match key.algorithm {
                AlgorithmParameters::RSA(rsa) => rsa.jws_public_key_secret(),
                AlgorithmParameters::OctetKey(oct) => Secret::Bytes(oct.value),
                // It seems like `biscuit` doesn't support elliptic curve public key based verifications so instead
                // we validate the signature up front and return the 'unverified' data if that succeeds
                AlgorithmParameters::EllipticCurve(params) => {
                    let point: EncodedPoint<NistP256> = EncodedPoint::from_affine_coordinates(
                        params.x.as_slice().into(),
                        params.y.as_slice().into(),
                        false,
                    );
                    let ec_key = VerifyingKey::from_encoded_point(&point)?;
                    let signature = Signature::try_from(compact.signature()?.as_slice())?;
                    let components = raw.as_ref().split('.').collect::<Vec<_>>();
                    let signature_payload = format!("{}.{}", components[0], components[1]);

                    ec_key.verify(signature_payload.as_bytes(), &signature)?;

                    return parse_transaction(
                        raw.as_ref(),
                        &compact.unverified_header()?,
                        &compact.unverified_payload()?,
                    );
                }
                _ => {
                    return Err(biscuit::errors::Error::ValidationError(
                        biscuit::errors::ValidationError::UnsupportedKeyAlgorithm,
                    )
                    .into())
                }
            },
            header.registered.algorithm,
        )?;

        parse_transaction(raw.as_ref(), compact.header()?, compact.payload()?)
    }
}
