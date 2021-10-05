use anyhow::Result;
use clap::Clap;
use sled::Db;

use crate::pki::KeyStore;

#[derive(Clap)]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Clap)]
pub enum Cmd {
    /// Lists all keys in the key-store
    ListKeys,
}

async fn list_keys(db: Db) -> Result<()> {
    let store = KeyStore::open(db)?;
    let jwk_set = store.as_ref();

    for key in jwk_set.keys.iter() {
        println!("- {}", key.common.key_id.as_ref().unwrap());
    }

    Ok(())
}

pub async fn cmd(db: Db, opts: Opts) -> Result<()> {
    match opts.cmd {
        Cmd::ListKeys => list_keys(db),
    }
    .await
}
