use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::time::delay_for;

use protobuf::bip70::Payment;

#[derive(Debug)]
pub enum WalletError {
    NotFound,
    IncorrectAmount,
}

#[derive(Clone)]
pub struct Wallet<K, O> {
    timeout: Duration,
    pending: Arc<DashMap<K, Vec<O>>>, // script:amount
}

impl<K, O> Wallet<K, O>
where
    K: std::hash::Hash + std::cmp::Eq,
    K: Clone + Send + Sync + 'static,
    O: std::cmp::PartialEq,
{
    pub fn new(timeout: Duration) -> Self {
        Wallet {
            timeout,
            pending: Default::default(),
        }
    }

    pub async fn add_outputs<F: std::future::Future<Output = ()>>(&self, key: K, outputs: Vec<O>) {
        // Remove from pending map after timeout
        // TODO: Check whether pre-existing?

        let key_inner = key.clone();

        self.pending.insert(key, outputs);

        let pending_inner = self.pending.clone();
        let timeout_inner = self.timeout;
        delay_for(timeout_inner).await;
        pending_inner.remove(&key_inner);
    }

    pub fn recv_outputs(&self, key: &K, outputs: &[O]) -> Result<(), WalletError> {
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
}
