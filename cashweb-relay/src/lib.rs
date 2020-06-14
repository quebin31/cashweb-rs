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

/// Represents a [Message](struct.Message.html) post-parsing.
#[derive(Debug)]
pub struct ParsedMessage {
    pub source_public_key: PublicKey,
    pub destination_public_key: PublicKey,
    pub received_time: i64,
    pub payload_digest: [u8; 32],
    pub stamp: Stamp,
    pub scheme: EncryptionScheme,
    pub salt: Vec<u8>,
    pub payload_hmac: [u8; 32],
    pub payload_size: u64,
    pub payload: Vec<u8>,
}

/// Error associated with [Message](struct.Message.html) parsing.
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
    /// Parse a [Message](struct.Message.html) to construct a [ParsedMessage](struct.ParsedMessage.html).
    ///
    /// The involves deserialization of both public keys, calculation of the payload digest, and coercion of byte fields into arrays.
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
        let stamp = self.stamp.ok_or(ParseError::MissingStampData)?;

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
            received_time: self.received_time,
            payload_digest,
            stamp,
            scheme,
            salt: self.salt,
            payload_hmac,
            payload_size: self.payload_size,
            payload: self.payload,
        })
    }
}

/// Error associated with authentication of the [Payload](struct.Payload.html).
#[derive(Debug)]
pub enum AuthenticationError {
    SourcePublicKey(SecpError),
    Mul(SecpError),
    InvalidHmac,
    DigestAndPayloadMissing,
    FraudulentDigest,
    IncorrectLengthDigest,
}

/// Calculate the merged key from the destination private key.
pub fn calculate_merged_key(
    source_public_key: PublicKey,
    private_key: &[u8],
) -> Result<PublicKey, SecpError> {
    // Create merged key
    let mut merged_key = source_public_key;
    merged_key.mul_assign(&Secp256k1::verification_only(), private_key)?;
    Ok(merged_key)
}

/// Authenticate the [Payload](struct.Payload.html) and return the raw merged key.
#[inline]
fn authenticate_raw(
    source_public_key: PublicKey,
    private_key: &[u8],
    payload_digest: &[u8],
    salt: &[u8],
) -> Result<[u8; 33], AuthenticationError> {
    // Create merged key
    let merged_key =
        calculate_merged_key(source_public_key, private_key).map_err(AuthenticationError::Mul)?;
    let raw_merged_key = merged_key.serialize();

    // HMAC with salt
    let salt_key = Key::new(HMAC_SHA256, salt);
    let digest = hmac(&salt_key, &raw_merged_key);

    // Check equality
    if digest.as_ref() != payload_digest {
        return Err(AuthenticationError::InvalidHmac);
    }
    Ok(raw_merged_key)
}

/// Authenticate the [Payload](struct.Payload.html) and return the merged key.
#[inline]
pub fn authenticate(
    source_public_key: PublicKey,
    private_key: &[u8],
    payload_digest: &[u8],
    salt: &[u8],
) -> Result<PublicKey, AuthenticationError> {
    // Create merged key
    let merged_key =
        calculate_merged_key(source_public_key, private_key).map_err(AuthenticationError::Mul)?;
    let raw_merged_key = merged_key.serialize();

    // HMAC with salt
    let salt_key = Key::new(HMAC_SHA256, salt);
    let digest = hmac(&salt_key, &raw_merged_key);

    if digest.as_ref() != payload_digest {
        return Err(AuthenticationError::InvalidHmac);
    }
    Ok(merged_key)
}

/// The result of [validate_decrypt](struct.ParsedMessage.html#method.validate_decrypt) or [validate_decrypt_in_place](struct.ParsedMessage.html#method.validate_decrypt_in_place).
#[derive(Debug)]
pub struct DecryptResult {
    pub txs: Vec<Transaction>,
    pub payload: Payload,
}

/// Error associated with [validate_decrypt](struct.ParsedMessage.html#method.validate_decrypt) or [validate_decrypt_in_place](struct.ParsedMessage.html#method.validate_decrypt_in_place).
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
    pub fn calculate_merged_key(&self, private_key: &[u8]) -> Result<PublicKey, SecpError> {
        calculate_merged_key(self.source_public_key, private_key)
    }

    /// Authenticate the HMAC payload and return the raw merged key.
    #[inline]
    fn authenticate_raw(&self, private_key: &[u8]) -> Result<[u8; 33], AuthenticationError> {
        // Authenticate
        let merged_key = authenticate_raw(
            self.source_public_key,
            private_key,
            &self.payload_digest,
            &self.salt,
        )?;

        Ok(merged_key)
    }

    /// Authenticate the HMAC payload and return the merged key.
    #[inline]
    pub fn authenticate(&self, private_key: &[u8]) -> Result<PublicKey, AuthenticationError> {
        // Authenticate
        let merged_key = authenticate(
            self.source_public_key,
            private_key,
            &self.payload_digest,
            &self.salt,
        )?;

        Ok(merged_key)
    }

    /// Verify the stamp on the message and return the decoded transactions.
    #[inline]
    pub fn verify_stamp(&self, network: Network) -> Result<Vec<Transaction>, StampError> {
        self.stamp
            .verify_stamp(&self.payload_digest, &self.destination_public_key, network)
    }

    /// Verify the stamp, authenticate the HMAC payload, and then decrypt and decode the payload.
    ///
    /// This is done in-place, replacing the encrypted [payload] field with the plain text.
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
            .authenticate_raw(private_key)
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

    /// Verify the stamp, authenticate the HMAC payload, and then decrypt and decode the payload.
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
            .authenticate_raw(private_key)
            .map_err(DecryptError::Authentication)?;

        // Calculate shared key
        let shared_key = digest(&SHA256, &raw_merged_key);

        // Decrypt
        let raw_payload = &self.payload;
        let (key, iv) = shared_key.as_ref().split_at(16);
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
