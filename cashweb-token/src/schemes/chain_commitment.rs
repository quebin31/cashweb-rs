//! This module contains the [`ChainCommitmentScheme`] which provides the ability to validate POP 
//! tokens given in the [`Keyserver Protocol`].
//!
//! [`Keyserver Protocol`]: https://github.com/cashweb/specifications/blob/master/keyserver-protocol/specification.mediawiki


use std::{convert::TryInto, fmt};

use bitcoin::{
    prelude::{Transaction, TransactionDecodeError},
    Decodable,
};
use bitcoin_client::{BitcoinClient, HttpClient, HttpsClient, NodeError};
use hyper::{Body, Request as HttpRequest, Response as HttpResponse};
use ring::digest::{Context, SHA256};
use tower_service::Service;

/// Error associated with token validation.
#[derive(Debug)]
pub enum ValidationError<E> {
    /// Failed to decode token.
    Base64(base64::DecodeError),
    /// Speficied script was unexpected length.
    IncorrectLength,
    /// Token was invalid.
    Invalid,
    /// Error occured when communicating with bitcoind.
    Node(NodeError<E>),
    /// Specified output was not an `OP_RETURN`.
    NotOpReturn,
    /// Specified output did not exist.
    OutputNotFound,
    /// Error decoding specified transaction.
    Transaction(TransactionDecodeError),
    /// Token was unexpected length.
    TokenLength,
}

impl<E: fmt::Display> fmt::Display for ValidationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::Base64(err) => return err.fmt(f),
            Self::IncorrectLength => "unexpected script length",
            Self::Invalid => "invalid token",
            Self::Node(err) => return err.fmt(f),
            Self::NotOpReturn => "not op return",
            Self::OutputNotFound => "output missing",
            Self::Transaction(err) => return err.fmt(f),
            Self::TokenLength => "unexpected token length",
        };
        f.write_str(printable)
    }
}

/// Chain commitment scheme used in the keyserver protocol.
#[derive(Clone, Debug)]
pub struct ChainCommitmentScheme<S> {
    client: BitcoinClient<S>,
}

const COMMITMENT_LEN: usize = 32;

/// Construct the commitment.
pub fn construct_commitment(pub_key_hash: &[u8], address_metadata_hash: &[u8]) -> Vec<u8> {
    let mut sha256_context = Context::new(&SHA256);
    sha256_context.update(pub_key_hash);
    sha256_context.update(address_metadata_hash);
    sha256_context.finish().as_ref().to_vec()
}

/// Construct the raw token.
pub fn construct_token_raw(tx_id: &[u8], vout: u32) -> Vec<u8> {
    [tx_id, &vout.to_le_bytes()[..]].concat()
}

/// Construct the token.
pub fn construct_token(tx_id: &[u8], vout: u32) -> String {
    let raw_token = construct_token_raw(tx_id, vout);
    let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    base64::encode_config(raw_token, url_safe_config)
}

impl<S> ChainCommitmentScheme<S> {
    /// Create a [`ChainCommitmentScheme`] from a [`BitcoinClient`].
    pub fn from_client(client: BitcoinClient<S>) -> Self {
        ChainCommitmentScheme { client }
    }
}

impl ChainCommitmentScheme<HttpClient> {
    /// Create a [`ChainCommitmentScheme`] from a [`BitcoinClient`] using a standard HTTP connector.
    pub fn new(endpoint: String, username: String, password: String) -> Self {
        Self {
            client: BitcoinClient::new(endpoint, username, password),
        }
    }
}

impl ChainCommitmentScheme<HttpsClient> {
    /// Create a [`ChainCommitmentScheme`] from a [`BitcoinClient`] using a standard HTTPS connector.
    pub fn new_tls(endpoint: String, username: String, password: String) -> Self {
        Self {
            client: BitcoinClient::new_tls(endpoint, username, password),
        }
    }
}

impl<S> ChainCommitmentScheme<S>
where
    S: Service<HttpRequest<Body>, Response = HttpResponse<Body>> + Clone,
    S::Error: 'static,
    S::Future: Send + 'static,
{
    /// Validate a token.
    pub async fn validate_token(
        &self,
        pub_key_hash: &[u8],
        address_metadata_hash: &[u8],
        token: &str,
    ) -> Result<Vec<u8>, ValidationError<S::Error>> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let outpoint_raw =
            base64::decode_config(token, url_safe_config).map_err(ValidationError::Base64)?;

        // Check token length
        const PAYLOAD_LEN: usize = 32 + 4;
        if outpoint_raw.len() != PAYLOAD_LEN {
            return Err(ValidationError::TokenLength);
        }

        // Parse ID
        let tx_id = &outpoint_raw[..32];

        // Get transaction
        let raw_transaction = self
            .client
            .get_raw_transaction(tx_id)
            .await
            .map_err(ValidationError::Node)?;
        let transaction = Transaction::decode(&mut raw_transaction.as_slice())
            .map_err(ValidationError::Transaction)?;

        // Get vout
        let vout_raw: [u8; 4] = outpoint_raw[32..36].try_into().unwrap(); // This is safe
        let vout = u32::from_le_bytes(vout_raw);

        // Parse script
        let output = transaction
            .outputs
            .get(vout as usize)
            .ok_or(ValidationError::OutputNotFound)?;

        if !output.script.is_op_return() {
            return Err(ValidationError::NotOpReturn);
        }

        let raw_script = output.script.as_bytes();

        // Check length
        if raw_script.len() != 2 + COMMITMENT_LEN || raw_script[1] != COMMITMENT_LEN as u8 {
            return Err(ValidationError::IncorrectLength);
        }

        // Check commitment
        let commitment = &raw_script[2..34];
        let expected_commitment = construct_commitment(pub_key_hash, address_metadata_hash);
        if expected_commitment != commitment {
            return Err(ValidationError::Invalid);
        }
        Ok(outpoint_raw)
    }
}
