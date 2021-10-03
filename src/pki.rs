use anyhow::{anyhow, Result};
use biscuit::{jwk::JWK, Empty};
use rmp_serde::{decode, encode};
use sled::Db;

pub type Key = JWK<Empty>;

pub struct KeyStore {
    db: Db,
}

impl KeyStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Get a key by it's key ID
    pub fn get(&self, id: &str) -> Result<Option<Key>> {
        let tree = self.db.open_tree("nuts/keys")?;

        if let Some(value) = tree.get(id)? {
            return Ok(Some(decode::from_read(value.as_ref())?));
        }

        Ok(None)
    }

    pub fn contains(&self, id: &str) -> Result<bool> {
        let tree = self.db.open_tree("nuts/keys")?;

        Ok(tree.contains_key(id)?)
    }

    /// Adds a key to the store (note that the key ID MUST not be empty)
    pub fn add(&mut self, id: String, key: Key) -> Result<()> {
        let tree = self.db.open_tree("nuts/keys")?;

        log::debug!(target: "nuts::pki", "adding a key: {}", id);

        if tree.contains_key(&id)? {
            return Err(anyhow!("key with ID '{}' already exists", id));
        }

        tree.insert(id, encode::to_vec(&key)?)?;

        Ok(())
    }
}
