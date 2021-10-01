use daggy::Dag;

use crate::network::transaction::Transaction;

pub type Graph = Dag<Transaction, usize, usize>;
