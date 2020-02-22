use std::{sync::Arc, time::Duration};

use bitcoin::{
    consensus::encode::Error as BitcoinError, util::psbt::serialize::Deserialize, Transaction,
    TxOut,
};
use dashmap::DashMap;
use tokio::time::delay_for;

use protobuf::bip70::Payment;

pub enum WalletError {
    NotFound,
    IncorrectAmount,
    MalformedTx(BitcoinError),
}

#[derive(Clone)]
pub struct Wallet<K> {
    timeout: Duration,
    pending: Arc<DashMap<K, Vec<TxOut>>>, // script:amount
}

impl<K> Wallet<K>
where
    K: std::hash::Hash + std::cmp::Eq,
    K: Clone + Send + Sync + 'static,
{
    pub fn new(timeout: Duration) -> Self {
        Wallet {
            timeout,
            pending: Default::default(),
        }
    }

    pub fn add_outputs(&self, key: K, outputs: Vec<TxOut>) {
        // Remove from pending map after timeout
        // TODO: Check whether pre-existing?

        let key_inner = key.clone();
        let pending_inner = self.pending.clone();
        let timeout_inner = self.timeout;
        let cleanup = async move {
            delay_for(timeout_inner).await;
            pending_inner.remove(&key_inner);
        };
        self.pending.insert(key, outputs);
        tokio::spawn(cleanup);
    }

    pub fn recv_outputs(&self, key: &K, outputs: &[TxOut]) -> Result<(), WalletError> {
        // TODO: Use conditional remove here
        let expected_outputs = self.pending.get(key).ok_or(WalletError::NotFound)?;
        if outputs
            .iter()
            .all(|output| expected_outputs.value().contains(output))
        {
            self.pending.remove(key);
            Ok(())
        } else {
            Err(WalletError::IncorrectAmount)
        }
    }

    pub fn process_payment(&self, key: &K, payment: &Payment) -> Result<(), WalletError>
    where
        K: std::hash::Hash + std::cmp::Eq,
        K: Clone + Send + Sync + 'static,
    {
        let txs_res: Result<Vec<Transaction>, BitcoinError> = payment
            .transactions
            .iter()
            .map(|raw_tx| Transaction::deserialize(raw_tx))
            .collect();
        let txs = txs_res.map_err(WalletError::MalformedTx)?;
        let outputs: Vec<TxOut> = txs.into_iter().map(move |tx| tx.output).flatten().collect();

        self.recv_outputs(key, &outputs)
    }
}
