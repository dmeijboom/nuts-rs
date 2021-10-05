use anyhow::Result;
use clap::Clap;
use sled::Db;

use crate::network::{Graph, Hash};

#[derive(Clap)]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Clap)]
pub struct GetOpts {
    id: String,
}

#[derive(Clap)]
pub enum Cmd {
    /// Lists all transactions in the DAG
    List,

    /// Get, and decode a transaction by it's hash
    Get(GetOpts),
}

async fn list_transactions(db: Db) -> Result<()> {
    let store = Graph::open(db)?;

    store.walk(|tx| {
        println!("{}", tx.id);
    });

    Ok(())
}

async fn get_transaction(db: Db, opts: GetOpts) -> Result<()> {
    let store = Graph::open(db)?;
    let hash = Hash::parse_hex(opts.id.as_bytes())?;

    match store.get(&hash) {
        Some(tx) => {
            println!("id: {}", tx.id);
            println!("key: {:?}", tx.key);
            println!("key_id: {}", tx.key_id);
            println!("version: {}", tx.version);
            println!("sign_algorithm: {:?}", tx.sign_algo);
            println!("sign_at: {}", tx.sign_at);
            println!("payload_type: {}", tx.payload_type);
            println!(
                "previous: {}",
                tx.prevs
                    .iter()
                    .map(|id| format!("{}", id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        None => eprintln!("transaction not found with id: {}", hash),
    };

    Ok(())
}

pub async fn cmd(db: Db, opts: Opts) -> Result<()> {
    match opts.cmd {
        Cmd::List => list_transactions(db).await,
        Cmd::Get(opts) => get_transaction(db, opts).await,
    }
}
