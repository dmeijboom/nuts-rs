use anyhow::Result;

use crate::network::{Server, Transaction};
use crate::proto::TransactionList;

impl Server {
    pub fn handle_transaction_list(&mut self, data: TransactionList) -> Result<()> {
        for raw_tx in data.transactions {
            let tx = Transaction::parse_unsafe(String::from_utf8(raw_tx.data)?)?;

            println!("{:#?}", tx);
        }

        Ok(())
    }
}
