pub mod bip32;
pub mod prelude;
pub mod transaction;
pub mod var_int;

use std::convert::TryFrom;

use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct InsufficientCapacity;

/// Provides a common interface for the serialization of bitcoin structures.
pub trait Encodable: Sized {
    /// Returns the encoded length of the message.
    fn encoded_len(&self) -> usize;

    /// Encodes structure to a buffer.
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), InsufficientCapacity> {
        if buf.remaining_mut() < self.encoded_len() {
            return Err(InsufficientCapacity);
        }
        self.encode_raw(buf);
        Ok(())
    }

    /// Encodes structure to a buffer. This panics if buffer contains insufficient capacity.
    fn encode_raw<B: BufMut>(&self, buf: &mut B);
}

/// Provides a common interface for the deserialization of bitcoin structures.
pub trait Decodable: Sized {
    type Error;

    /// Decode a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>;
}

/// Enumeration of all standard Bitcoin networks.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

/// Network was unexpected.
#[derive(Debug)]
pub struct UnexpectedNetwork;

impl TryFrom<String> for Network {
    type Error = UnexpectedNetwork;

    fn try_from(network: String) -> Result<Self, Self::Error> {
        match network.as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(UnexpectedNetwork),
        }
    }
}

impl Into<String> for Network {
    fn into(self) -> String {
        match self {
            Self::Mainnet => "mainnet".to_string(),
            Self::Testnet => "testnet".to_string(),
            Self::Regtest => "regtest".to_string(),
        }
    }
}

impl std::string::ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Self::Mainnet => "mainnet".to_string(),
            Self::Testnet => "testnet".to_string(),
            Self::Regtest => "regtest".to_string(),
        }
    }
}
