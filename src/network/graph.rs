use std::fmt::{Debug, Formatter};

use anyhow::{anyhow, Result};
use daggy::{Dag, NodeIndex, Walker};

use crate::network::{Hash, Transaction};

pub struct Graph {
    dag: Dag<Transaction, Transaction>,
}

impl Debug for Graph {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.dag.fmt(f)
    }
}

fn find_recursive(
    dag: &Dag<Transaction, Transaction>,
    id: &Hash,
    idx: NodeIndex<u32>,
) -> Option<NodeIndex<u32>> {
    if let Some(tx) = dag.node_weight(idx) {
        if &tx.id == id {
            return Some(idx);
        }
    }

    for (_, n) in dag.children(idx).iter(dag) {
        if let Some(tx) = find_recursive(dag, id, n) {
            return Some(tx);
        }
    }

    None
}

impl Graph {
    pub fn new() -> Self {
        Self { dag: Dag::new() }
    }

    pub fn root(&self) -> Option<&Transaction> {
        self.dag.node_weight(0.into())
    }

    pub fn find(&self, id: &Hash) -> Option<NodeIndex<u32>> {
        match self.root() {
            Some(_) => find_recursive(&self.dag, id, 0.into()),
            None => None,
        }
    }

    pub fn add(&mut self, tx: Transaction) -> Result<NodeIndex<u32>> {
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

            log::debug!(target: "nuts::network", "adding a root transaction: {}", tx.id);

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

        log::debug!(target: "nuts::network", "adding a transaction: {}", tx.id);

        let parent_idx = *prevs.last().unwrap();
        let idx = self.dag.add_node(tx);

        self.dag.extend_with_edges(&[(parent_idx, idx)])?;

        Ok(idx)
    }
}
