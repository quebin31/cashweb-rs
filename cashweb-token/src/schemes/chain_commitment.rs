use std::{convert::TryInto, fmt};

use bitcoin::{
    consensus::encode::{Decodable, Error as BitcoinError},
    Transaction,
};
use bitcoin_client::{BitcoinClient, HttpConnector, NodeError};
use ring::hmac;

#[derive(Debug)]
pub struct ChainCommitmentScheme<C> {
    client: BitcoinClient<C>,
}

impl ChainCommitmentScheme<HttpConnector> {
    pub fn new(endpoint: String, username: String, password: String) -> Self {
        Self {
            client: BitcoinClient::new(endpoint, username, password),
        }
    }

    pub fn construct_token(&self, pub_key: &[u8], address_metadata: &[u8]) -> String {
        let tag = create_tag(pub_key, address_metadata);
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        base64::encode_config(tag.as_ref(), url_safe_config)
    }
}

fn create_key(pub_key: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, pub_key)
}

fn create_tag(pub_key: &[u8], address_metadata: &[u8]) -> hmac::Tag {
    let key = create_key(pub_key);
    hmac::sign(&key, address_metadata)
}

impl<C> ChainCommitmentScheme<C> {}

#[derive(Debug)]
pub enum ValidationError {
    Base64(base64::DecodeError),
    IncorrectLength,
    Invalid,
    Node(NodeError),
    NotOpReturn,
    OutputNotFound,
    Transaction(BitcoinError),
    TokenLength,
}

impl fmt::Display for ValidationError {
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

const SCRIPT_LEN: usize = 32 + 4;

impl ChainCommitmentScheme<HttpConnector> {
    pub async fn validate_token(
        &self,
        pub_key: &[u8],
        address_metadata: &[u8],
        token: &str,
    ) -> Result<(), ValidationError> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let outpoint_raw =
            base64::decode_config(token, url_safe_config).map_err(ValidationError::Base64)?;

        if outpoint_raw.len() != SCRIPT_LEN {
            return Err(ValidationError::TokenLength);
        }

        // Get ID
        let tx_id = &outpoint_raw[..32];

        // Get transaction
        let raw_transaction = self
            .client
            .get_raw_transaction(tx_id)
            .await
            .map_err(ValidationError::Node)?;
        let transaction = Transaction::consensus_decode(&raw_transaction[..])
            .map_err(ValidationError::Transaction)?;

        // Get vout
        let vout_raw: [u8; 4] = outpoint_raw[32..36].try_into().unwrap(); // This is safe
        let vout = u32::from_le_bytes(vout_raw);

        // Parse script
        let output = transaction
            .output
            .get(vout as usize)
            .ok_or(ValidationError::OutputNotFound)?;

        if !output.script_pubkey.is_op_return() {
            return Err(ValidationError::NotOpReturn);
        }

        let raw_script = output.script_pubkey.as_bytes();

        // Check length
        let script_len = raw_script.len();
        if script_len != 2 + 32 || raw_script[1] != 2 + 32 {
            return Err(ValidationError::IncorrectLength);
        }

        let tag = &raw_script[2..34];
        let key = create_key(pub_key);
        hmac::verify(&key, address_metadata, &tag).map_err(|_| ValidationError::Invalid)
    }
}
