use anyhow::{anyhow, Result};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::Compact;
use biscuit::CompactJson;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use crate::network::Hash;

#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: Hash,
    pub data: Vec<u8>,
    pub prevs: Vec<Hash>,
    pub payload: Hash,
    pub payload_type: String,
    pub version: usize,
    pub sign_key_id: String,
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
            sign_key_id: "".to_string(),
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

impl Transaction {
    /// Parses a transaction from the compact JWS representation without verifying the signature
    pub fn parse_unsafe(raw: impl AsRef<str>) -> Result<Transaction> {
        let compact: Compact<Vec<u8>, TransactionHeader> = Compact::new_encoded(raw.as_ref());
        let header = compact.unverified_header()?;
        let payload = compact.unverified_payload()?;
        let payload = Hash::parse_hex(&payload)?;

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
            return Err(anyhow!(
                "unsupported algorithm: {:?}",
                header.registered.algorithm
            ));
        }

        let payload_type = header
            .registered
            .content_type
            .ok_or_else(|| anyhow!("transaction is missing the payload-type"))?;
        let sign_at = NaiveDateTime::from_timestamp(header.private.sign_time, 0);

        let sign_key_id = match header.registered.key_id {
            Some(key_id) => Ok(key_id),
            None => header
                .registered
                .web_key
                .and_then(|key| key.common.key_id)
                .ok_or_else(|| anyhow!("unable to parse key ID from transaction")),
        }?;

        let mut prevs = vec![];

        for hash in header.private.previous {
            prevs.push(Hash::parse_hex(hash.as_bytes())?);
        }

        let data = raw.as_ref().as_bytes().to_vec();
        let id = Hash::new(&data)?;

        Ok(Transaction {
            id,
            data,
            prevs,
            payload,
            payload_type,
            version: header.private.version,
            sign_key_id,
            sign_at,
            sign_algo: header.registered.algorithm,
        })
    }
}
