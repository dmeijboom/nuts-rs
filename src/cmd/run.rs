use anyhow::Result;
use clap::Clap;
use sled::Db;
use tokio::fs;
use tonic::transport::{Certificate, Identity};

use crate::network::Server;

#[derive(Clap)]
pub struct Opts {
    bootstrap_node: Vec<String>,
}

pub async fn cmd(db: Db, opts: Opts) -> Result<()> {
    let ca_pem = fs::read("tls/truststore.pem").await?;
    let ca = Certificate::from_pem(ca_pem);
    let (cert, key) = (
        fs::read("tls/localhost.pem").await?,
        fs::read("tls/localhost.key").await?,
    );
    let identity = Identity::from_pem(cert, key);
    let mut server = Server::new(db, ca, identity)?;

    for addr in opts.bootstrap_node {
        server.connect_to_peer(addr).await?;
    }

    server.run().await;

    log::info!("shutting down");

    Ok(())
}
