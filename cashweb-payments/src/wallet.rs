use std::{fmt, sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::time::delay_for;

#[derive(Debug)]
pub enum WalletError {
    NotFound,
    InvalidOutputs,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::NotFound => "pending payment not found or expired",
            Self::InvalidOutputs => "invalid outputs",
        };
        f.write_str(printable)
    }
}

#[derive(Clone)]
pub struct Wallet<K, O> {
    timeout: Duration,
    pending: Arc<DashMap<K, Vec<O>>>, // script:amount
}

// NOTE: CHALK will remove the need for this manual impl
impl <K: fmt::Debug + std::cmp::Eq, O: fmt::Debug> fmt::Debug for Wallet<K, O>
where K: fmt::Debug + std::cmp::Eq + std::hash::Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wallet {{\n\ttimeout: {:?},\n\tpending: {:?}\n}}", self.timeout, self.pending)
    }
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

    pub fn add_outputs<F: std::future::Future<Output = ()>>(
        &self,
        key: K,
        outputs: Vec<O>,
    ) -> impl std::future::Future<Output = ()> {
        // TODO: Check whether pre-existing?
        let key_inner = key.clone();
        self.pending.insert(key, outputs);

        let pending_inner = self.pending.clone();
        let timeout_inner = self.timeout;

        // Remove from pending map after timeout
        let cleanup = async move {
            delay_for(timeout_inner).await;
            pending_inner.remove(&key_inner);
        };
        cleanup
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
            Err(WalletError::InvalidOutputs)
        }
    }
}
