use std::time::Duration;

use anyhow::Result;
use tokio::time;
use tonic::{Request, transport::Certificate};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Identity};
use uuid::Uuid;

use crate::network::{
    network_client::NetworkClient,
    network_message::Message,
    NetworkMessage,
    TransactionList,
};

pub struct Server {
    ca: Certificate,
    identity: Identity,
    bootstrap_node: String,
}

impl Server {
    pub fn new(ca: Certificate, identity: Identity, bootstrap_node: String) -> Self {
        Self {
            ca,
            identity,
            bootstrap_node,
        }
    }

    pub async fn run(self) -> Result<()> {
        println!("[network] connecting..");

        // Configure mTLS and initialize the client
        let tls = ClientTlsConfig::new()
            .ca_certificate(self.ca)
            .identity(self.identity);
        let channel = Channel::from_shared(self.bootstrap_node)?
            .tls_config(tls)?
            .connect()
            .await?;
        let mut client = NetworkClient::new(channel);

        // Setup an outbound stream of network messages
        let outbound = async_stream::stream! {
            let mut interval = time::interval(Duration::from_secs(60));

            while let _ = interval.tick().await {
                yield NetworkMessage {
                    message: Some(Message::TransactionList(TransactionList {
                        block_date: 0,
                        transactions: vec![],
                    })),
                };
            }
        };

        // Create the initial connection request
        let mut request = Request::new(outbound);

        // Sets the Peer ID as described in: https://nuts-foundation.gitbook.io/drafts/rfc/rfc005-distributed-network-using-grpc#6-1-peer-identification
        let peer_id = Uuid::new_v4();

        println!("[network] set peer ID: {}", &peer_id);

        request.metadata_mut().insert(
            "peerid",
            MetadataValue::from_str(&peer_id.to_string())?,
        );

        let mut stream = client.connect_method(request)
            .await?
            .into_inner();

        println!("[network] connected");

        while let Some(message) = stream.message().await? {
            println!("message: {:?}", message);
        }

        Ok(())
    }
}
