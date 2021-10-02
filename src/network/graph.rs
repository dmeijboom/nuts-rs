use std::fmt::{Debug, Formatter};
use std::sync::mpsc::channel;

use anyhow::{anyhow, Result};
use daggy::{Dag, NodeIndex, Walker};
use serde::{Deserialize, Serialize};
use sled::Db;

use crate::network::{Hash, Transaction};

fn walk_recursive<T>(
    dag: &Dag<Transaction, Transaction>,
    idx: NodeIndex<u32>,
    predicate: impl Fn(&Transaction, NodeIndex<u32>) -> Option<T> + Clone,
) -> Option<T> {
    if let Some(tx) = dag.node_weight(idx) {
        if let Some(output) = predicate(tx, idx) {
            return Some(output);
        }
    }

    for (_, n) in dag.children(idx).iter(dag) {
        if let Some(output) = walk_recursive(dag, n, predicate.clone()) {
            return Some(output);
        }
    }

    None
}

#[derive(Serialize, Deserialize)]
struct Node {
    idx: u32,
    tx_id: Hash,
    tx_data: String,
}

pub struct Graph {
    db: Db,
    dag: Dag<Transaction, Transaction>,
}

impl Debug for Graph {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.dag.fmt(f)
    }
}

impl Graph {
    pub fn open(db: Db) -> Result<Self> {
        let mut graph = Self {
            db,
            dag: Dag::new(),
        };

        let tree = graph.db.open_tree("nuts/dag")?;
        let mut transactions = vec![];

        for record in tree.iter() {
            let (_, value) = record?;
            let node: Node = bincode::deserialize(value.as_ref())?;
            let tx = Transaction::parse_unsafe(node.tx_data)?;

            transactions.push((node.idx, tx));
        }

        transactions.sort_unstable_by_key(|(idx, _)| *idx);

        for (_, tx) in transactions {
            graph.add_local(tx)?;
        }

        Ok(graph)
    }

    pub fn to_vec(&self) -> Result<Vec<Transaction>> {
        let (sender, receiver) = channel();

        if let Some(e) = walk_recursive(&self.dag, 0.into(), |tx, _| {
            // Returning none here means that we will walk the entire DAG
            sender.send(tx.clone()).err()
        }) {
            return Err(anyhow::anyhow!(e));
        }

        Ok(receiver.iter().collect::<Vec<_>>())
    }

    pub fn root(&self) -> Option<&Transaction> {
        self.dag.node_weight(0.into())
    }

    pub fn find(&self, id: &Hash) -> Option<NodeIndex<u32>> {
        match self.root() {
            Some(_) => walk_recursive(&self.dag, 0.into(), |tx, idx| {
                if &tx.id == id {
                    Some(idx)
                } else {
                    None
                }
            }),
            None => None,
        }
    }

    pub fn add(&mut self, tx: Transaction) -> Result<NodeIndex<u32>> {
        log::debug!(
            target: "nuts::network",
            "adding a {}transaction: {}", tx.id, if tx.is_root() { "root " } else { "" },
        );

        let tx_id = tx.id.clone();
        let tx_data = String::from_utf8(tx.data.clone())?;
        let idx = self.add_local(tx)?;
        let tree = self.db.open_tree("nuts/dag")?;

        tree.insert(
            tx_id.clone(),
            bincode::serialize(&Node {
                // This shouldn't overflow as the index type used is `u32`
                idx: idx.index() as u32,
                tx_id,
                tx_data,
            })?,
        )?;

        Ok(idx)
    }

    /// Adds a transaction to the DAG but doesn't write it to the database
    fn add_local(&mut self, tx: Transaction) -> Result<NodeIndex<u32>> {
        if self.find(&tx.id).is_some() {
            return Err(anyhow!(
                "transaction '{}' is already present in graph",
                tx.id,
            ));
        }

        if tx.is_root() {
            if self.root().is_some() {
                return Err(anyhow!(
                    "unable to add a root transaction to a graph with an existing root transaction"
                ));
            }

            return Ok(self.dag.add_node(tx));
        }

        // Make sure all previous transactions are present
        let mut prevs = vec![];

        for id in tx.prevs.iter() {
            match self.find(id) {
                Some(idx) => prevs.push(idx),
                None => {
                    return Err(anyhow!(
                    "unable to process transaction '{}' when previous transaction '{}' is missing",
                    tx.id,
                    id
                ))
                }
            };
        }

        let parent_idx = *prevs.last().unwrap();
        let idx = self.dag.add_node(tx);

        self.dag.extend_with_edges(&[(parent_idx, idx)])?;

        Ok(idx)
    }
}
