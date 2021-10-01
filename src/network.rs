use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::Stream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time;
use tonic::{Request, transport::Certificate};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Identity};
use uuid::Uuid;

use crate::proto::{
    network_client::NetworkClient,
    network_message::Message,
    NetworkMessage,
    TransactionList,
};

#[derive(Debug)]
pub struct Msg {
    peer_id: Uuid,
    message: Message,
}

pub struct Server {
    peer_id: Uuid,
    ca: Certificate,
    identity: Identity,

    rx: Receiver<Msg>,
    tx: Sender<Msg>,
}

impl Server {
    pub fn new(ca: Certificate, identity: Identity) -> Self {
        let (tx, rx) = channel(10);

        Self {
            ca,
            identity,
            peer_id: Uuid::new_v4(),
            tx,
            rx,
        }
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            log::info!(target: "network", "incoming: {:?}", msg);
        }
    }

    async fn connect(&self, addr: String) -> Result<NetworkClient<Channel>> {
        // Configure mTLS and initialize the client
        let tls = ClientTlsConfig::new()
            .ca_certificate(self.ca.clone())
            .identity(self.identity.clone());
        let channel = Channel::from_shared(addr.into_bytes())?
            .tls_config(tls)?
            .connect()
            .await?;

        Ok(NetworkClient::new(channel))
    }

    fn client_stream(&self) -> Result<impl Stream<Item=NetworkMessage>> {
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

        Ok(outbound)
    }

    pub async fn connect_to_peer(&mut self, addr: String) -> Result<()> {
        log::info!(target: "network", "connecting to {}..", addr);

        let mut client = self.connect(addr.clone()).await?;
        let tx = self.tx.clone();

        // Create the initial connection request
        let mut request = Request::new(self.client_stream()?);

        // Sets the Peer ID as described in: https://nuts-foundation.gitbook.io/drafts/rfc/rfc005-distributed-network-using-grpc#6-1-peer-identification
        request.metadata_mut().insert(
            "peerid",
            MetadataValue::from_str(&self.peer_id.to_string())?,
        );

        // Connect to the peer, get it's peer ID and start the message loop in a task
        let response = client.connect_method(request).await?;
        let peer_id = match response.metadata().get("peerid") {
            Some(peer_id) => peer_id,
            None => return Err(anyhow!("unable to connect to peer because of missing peer ID")),
        }.to_str()?;
        let peer_id = Uuid::parse_str(peer_id)?;

        tokio::spawn(async move {
            let mut stream = response.into_inner();

            log::info!(target: "network", "connected to peer: {}", peer_id);

            loop {
                match stream.message().await {
                    Ok(network_message) => {
                        if let Some(network_message) = network_message {
                            if let Some(message) = network_message.message {
                                if let Err(e) = tx.send(Msg {
                                    peer_id,
                                    message,
                                }).await {
                                    log::error!(target: "network", "failed to handle message for peer '{}': {}", peer_id, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!(target: "network", "failed to receiver message for peer '{}': {}", peer_id, e)
                    }
                }
            }
        });

        Ok(())
    }
}
