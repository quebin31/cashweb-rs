mod models;
pub mod stamp;

use std::convert::TryInto;

use aes::{
    block_cipher::generic_array::{typenum::U16, GenericArray},
    Aes128,
};
use bitcoin::{transaction::Transaction, Network};
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use prost::{DecodeError as MessageDecodeError, Message as _};
use ring::{
    digest::{digest, SHA256},
    hmac::{sign as hmac, Key, HMAC_SHA256},
};
use secp256k1::{key::PublicKey, Error as SecpError, Secp256k1};

pub use crate::models::{message::EncryptionScheme, Message, Payload};
use stamp::*;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

/// Represents a message post-parsing.
pub struct ParsedMessage {
    pub source_public_key: PublicKey,
    pub destination_public_key: PublicKey,
    pub timestamp: i64,
    pub received_time: i64,
    pub payload_digest: [u8; 32],
    pub stamp_data: StampData,
    pub scheme: EncryptionScheme,
    pub salt: Vec<u8>,
    pub payload_hmac: [u8; 32],
    pub payload_size: u64,
    pub payload: Vec<u8>,
}

/// Error associated with `Message` parsing.
#[derive(Debug)]
pub enum ParseError {
    SourcePublicKey(SecpError),
    DestinationPublicKey(SecpError),
    DigestAndPayloadMissing,
    FraudulentDigest,
    IncorrectLengthDigest,
    MissingStampData,
    UnsupportedStampType,
    UnexpectedLengthPayloadHmac,
}

impl Message {
    /// Parse a [`Message`].
    ///
    /// The involves deserialization of both public keys, calculation of the payload digest, and coercion of 
    pub fn parse(self) -> Result<ParsedMessage, ParseError> {
        // Decode public keys
        let source_public_key =
            PublicKey::from_slice(&self.source_pub_key).map_err(ParseError::SourcePublicKey)?;
        let destination_public_key = PublicKey::from_slice(&self.destination_pub_key)
            .map_err(ParseError::DestinationPublicKey)?;

        // Calculate payload digest
        let payload_digest: [u8; 32] = match self.payload_digest.len() {
            0 => {
                // Check payload is not missing too
                if self.payload.is_empty() {
                    return Err(ParseError::DigestAndPayloadMissing);
                }
                let slice = &self.payload_digest[..];
                slice.try_into().unwrap()
            }
            32 => {
                // Check digest is correct when payload is not missing
                if !self.payload.is_empty() {
                    // Calculate digest
                    let payload_digest: [u8; 32] =
                        digest(&SHA256, &self.payload).as_ref().try_into().unwrap(); // This is safe

                    if payload_digest[..] == self.payload_digest[..] {
                        return Err(ParseError::FraudulentDigest);
                    }
                    payload_digest
                } else {
                    let slice = &self.payload_digest[..];
                    slice.try_into().unwrap()
                }
            }
            _ => return Err(ParseError::IncorrectLengthDigest),
        };

        // Parse stamp data
        let stamp_data = self.stamp_data.ok_or(ParseError::MissingStampData)?;

        // Parse scheme
        let scheme =
            EncryptionScheme::from_i32(self.scheme).ok_or(ParseError::UnsupportedStampType)?;

        // Parse payload_hmac
        let payload_hmac: [u8; 32] = self.payload_hmac[..]
            .try_into()
            .map_err(|_| ParseError::UnexpectedLengthPayloadHmac)?;

        Ok(ParsedMessage {
            source_public_key,
            destination_public_key,
            timestamp: self.timestamp,
            received_time: self.received_time,
            payload_digest,
            stamp_data,
            scheme,
            salt: self.salt,
            payload_hmac,
            payload_size: self.payload_size,
            payload: self.payload,
        })
    }
}

/// Error associated with authentication of the payload.
#[derive(Debug)]
pub enum AuthenticationError {
    SourcePublicKey(SecpError),
    Mul(SecpError),
    InvalidHmac,
    DigestAndPayloadMissing,
    FraudulentDigest,
    IncorrectLengthDigest,
}

/// Authenticate the HMAC payload and return the merged key.
pub fn authenticate(
    source_public_key: PublicKey,
    private_key: &[u8],
    payload_digest: &[u8],
    salt: &[u8],
    timestamp: i64,
) -> Result<[u8; 33], AuthenticationError> {
    // Create merged key
    let mut merged_key = source_public_key;
    merged_key
        .mul_assign(&Secp256k1::verification_only(), private_key)
        .map_err(AuthenticationError::Mul)?;
    let raw_merged_key = merged_key.serialize();

    // HMAC with timestamp
    let raw_timestamp = timestamp.to_le_bytes();
    let timestamp_key = Key::new(HMAC_SHA256, &raw_timestamp);
    let digest = hmac(&timestamp_key, &raw_merged_key);

    // HMAC with salt
    let salt_key = Key::new(HMAC_SHA256, salt);
    let digest = hmac(&salt_key, digest.as_ref());
    if digest.as_ref() != payload_digest {
        return Err(AuthenticationError::InvalidHmac);
    }
    Ok(raw_merged_key)
}

pub struct DecryptResult {
    pub txs: Vec<Transaction>,
    pub payload: Payload,
}

#[derive(Debug)]
pub enum DecryptError {
    Stamp(StampError),
    Authentication(AuthenticationError),
    Payload(MessageDecodeError),
    Decrypt(BlockModeError),
    Mul(SecpError),
}

impl ParsedMessage {
    /// Calculate the merged key from the destination private key.
    #[inline]
    pub fn calculate_merged_key(&self, private_key: &[u8]) -> Result<[u8; 33], SecpError> {
        // Create merged key
        let mut merged_key = self.source_public_key;
        merged_key.mul_assign(&Secp256k1::verification_only(), private_key)?;
        let raw_merged_key = merged_key.serialize();
        Ok(raw_merged_key)
    }

    /// Authenticate the HMAC payload and return the merged key.
    #[inline]
    pub fn authenticate(&self, private_key: &[u8]) -> Result<[u8; 33], AuthenticationError> {
        // Authenticate
        let merged_key = authenticate(
            self.source_public_key,
            private_key,
            &self.payload_digest,
            &self.salt,
            self.timestamp,
        )?;

        Ok(merged_key)
    }

    /// Validate that the stamp on the message. Returns decoded transactions
    #[inline]
    pub fn verify_stamp(&self, network: Network) -> Result<Vec<Transaction>, StampError> {
        self.stamp_data
            .verify_stamp(&self.payload_digest, &self.destination_public_key, network)
    }

    #[inline]
    pub fn validate_decrypt_in_place(
        &mut self,
        private_key: &[u8],
        network: Network,
    ) -> Result<DecryptResult, DecryptError> {
        // Verify stamp
        let txs = self.verify_stamp(network).map_err(DecryptError::Stamp)?;

        // Authenticate HMAC payload
        let raw_merged_key = self
            .authenticate(private_key)
            .map_err(DecryptError::Authentication)?;

        // Decrypt
        let mut raw_payload = &mut self.payload;
        let (key, iv) = raw_merged_key.split_at(16);
        let key = GenericArray::<u8, U16>::from_slice(&key);
        let iv = GenericArray::<u8, U16>::from_slice(&iv);
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap(); // This is safe
        cipher
            .decrypt(&mut raw_payload)
            .map_err(DecryptError::Decrypt)?;

        // Decode
        let payload =
            Payload::decode(&mut raw_payload.as_slice()).map_err(DecryptError::Payload)?;

        Ok(DecryptResult { txs, payload })
    }

    #[inline]
    pub fn validate_decrypt(
        &self,
        private_key: &[u8],
        network: Network,
    ) -> Result<DecryptResult, DecryptError> {
        // Verify stamp
        let txs = self.verify_stamp(network).map_err(DecryptError::Stamp)?;

        // Authenticate HMAC payload
        let raw_merged_key = self
            .authenticate(private_key)
            .map_err(DecryptError::Authentication)?;

        // Decrypt
        let raw_payload = &self.payload;
        let (key, iv) = raw_merged_key.split_at(16);
        let key = GenericArray::<u8, U16>::from_slice(&key);
        let iv = GenericArray::<u8, U16>::from_slice(&iv);
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap(); // This is safe
        cipher
            .decrypt_vec(raw_payload)
            .map_err(DecryptError::Decrypt)?;

        // Decode
        let payload =
            Payload::decode(&mut raw_payload.as_slice()).map_err(DecryptError::Payload)?;

        Ok(DecryptResult { txs, payload })
    }
}
