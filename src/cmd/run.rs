use anyhow::Result;
use tokio::fs;
use tonic::transport::{Certificate, Identity};

use crate::network::Server;

pub async fn cmd(bootstrap_node: String) -> Result<()> {
    let ca_pem = fs::read("tls/truststore.pem").await?;
    let ca = Certificate::from_pem(ca_pem);
    let (cert, key) = (
        fs::read("tls/localhost.pem").await?,
        fs::read("tls/localhost.key").await?,
    );
    let identity = Identity::from_pem(cert, key);

    let mut server = Server::new(
        ca,
        identity,
    );

    server.connect_to_peer(bootstrap_node).await?;
    server.run().await;

    log::info!("shutting down");

    Ok(())
}
