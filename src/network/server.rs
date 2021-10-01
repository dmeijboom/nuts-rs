use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::Stream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::{Request, Response};
use uuid::Uuid;

use crate::network::Graph;
use crate::proto::{
    network_client::NetworkClient, network_message::Message, NetworkMessage, TransactionList,
    TransactionListQuery,
};

macro_rules! netmsg {
    ($message: expr) => {
        NetworkMessage {
            message: Some($message),
        }
    };
}

#[derive(Debug)]
pub struct Msg {
    peer_id: Uuid,
    message: Message,
}

pub struct Server {
    strict: bool,
    peer_id: Uuid,
    ca: Certificate,
    identity: Identity,
    graph: Graph,

    rx: Receiver<Msg>,
    tx: Sender<Msg>,
}

impl Server {
    pub fn new(ca: Certificate, identity: Identity) -> Self {
        let (tx, rx) = channel(10);

        Self {
            strict: false,
            ca,
            identity,
            peer_id: Uuid::new_v4(),
            tx,
            rx,
            graph: Graph::new(),
        }
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            if let Err(e) = match msg.message {
                Message::TransactionList(data) => self.handle_transaction_list(data),
                message => {
                    log::debug!(target: "network", "ignoring unsupported message: {:?}", message);

                    Ok(())
                }
            } {
                log::error!(target: "network", "error handling message for peer '{}': {}", msg.peer_id, e);
            }
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

    fn client_stream(&self) -> Result<impl Stream<Item = NetworkMessage>> {
        let outbound = async_stream::stream! {
            let mut interval = time::interval(Duration::from_secs(60));

            // Initially, ask for the complete transaction list
            yield netmsg!(Message::TransactionListQuery(TransactionListQuery {
                block_date: 0,
            }));

            while let _ = interval.tick().await {
                yield netmsg!(Message::TransactionList(TransactionList {
                    block_date: 0,
                    transactions: vec![],
                }));
            }
        };

        Ok(outbound)
    }

    fn new_request<T>(&self, body: T) -> Result<Request<T>> {
        let mut request = Request::new(body);
        let metadata = request.metadata_mut();

        // Sets the Peer ID as described in: https://nuts-foundation.gitbook.io/drafts/rfc/rfc005-distributed-network-using-grpc#6-1-peer-identification
        metadata.insert(
            "peerid",
            MetadataValue::from_str(&self.peer_id.to_string())?,
        );

        // Sets the protocol version described in: https://nuts-foundation.gitbook.io/drafts/rfc/rfc005-distributed-network-using-grpc#6-4-protocol-version
        metadata.insert("version", MetadataValue::from_static("1"));

        Ok(request)
    }

    fn parse_metadata<'r, T>(&self, response: &'r Response<T>) -> Result<(Uuid, &'r str)> {
        let metadata = response.metadata();
        let peer_id = metadata
            .get("peerid")
            .ok_or_else(|| anyhow!("unable to connect to peer because of missing peer ID"))?
            .to_str()?;

        // It looks like the protocol version header is not implemented yet, so when strict isn't enabled just return 1 instead
        if !self.strict {
            return Ok((Uuid::parse_str(peer_id)?, "1"));
        }

        let version = metadata
            .get("version")
            .ok_or_else(|| anyhow!("peer didn't provide the protocol version"))?
            .to_str()?;

        Ok((Uuid::parse_str(peer_id)?, version))
    }

    pub async fn connect_to_peer(&mut self, addr: String) -> Result<()> {
        log::info!(target: "network", "connecting to {}..", addr);

        let mut client = self.connect(addr.clone()).await?;
        let tx = self.tx.clone();

        // Create the initial connection request
        let request = self.new_request(self.client_stream()?)?;

        // Connect to the peer, get it's peer ID and start the message loop in a task
        let response: Response<_> = client.connect_method(request).await?;
        let (peer_id, version) = self.parse_metadata(&response)?;

        // Currently only protocol version 1 is supported
        if version != "1" {
            log::info!(target: "network", "closing connection to peer '{}' due to invalid protocol version: {}", peer_id, version);

            return Err(anyhow!("invalid protocol version: {}", version));
        }

        tokio::spawn(async move {
            let mut stream = response.into_inner();

            log::info!(target: "network", "connected to peer: {}", peer_id);

            loop {
                match stream.message().await {
                    Ok(network_message) => {
                        if let Some(network_message) = network_message {
                            if let Some(message) = network_message.message {
                                if let Err(e) = tx.send(Msg { peer_id, message }).await {
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
