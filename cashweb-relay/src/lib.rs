mod models;
pub mod stamp;
pub use secp256k1;

use std::{convert::TryInto, fmt};

use aes::{
    block_cipher::generic_array::{typenum::U16, GenericArray},
    Aes128,
};
use bitcoin::{transaction::Transaction, Network};
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use prost::{DecodeError as MessageDecodeError, Message as _};
use ring::{
    digest::{digest, SHA256},
    hkdf::{self, HKDF_SHA256},
};
use secp256k1::{key::PublicKey, Error as SecpError, Secp256k1};

pub use crate::models::{
    message::EncryptionScheme, Message, MessagePage, MessageSet, Payload, PayloadPage,
};
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
    Digest(DigestError),
    SourcePublicKey(SecpError),
    DestinationPublicKey(SecpError),
    DigestAndPayloadMissing,
    FraudulentDigest,
    UnexpectedLengthDigest,
    MissingStamp,
    UnsupportedStampType,
    UnexpectedLengthPayloadHmac,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::Digest(err) => return err.fmt(f),
            Self::SourcePublicKey(err) => return writeln!(f, "source public key: {}", err),
            Self::DestinationPublicKey(err) => {
                return writeln!(f, "destination public key: {}", err)
            }
            Self::DigestAndPayloadMissing => "digest and payload missing",
            Self::FraudulentDigest => "fraudulent digest",
            Self::UnexpectedLengthDigest => "unexpected length digest",
            Self::MissingStamp => "missing stamp",
            Self::UnsupportedStampType => "unsupported stamp type",
            Self::UnexpectedLengthPayloadHmac => "unexpected length payload hmac",
        };
        f.write_str(printable)
    }
}

/// Error associated with getting the `payload_digest`.
#[derive(Debug)]
pub enum DigestError {
    DigestAndPayloadMissing,
    FraudulentDigest,
    UnexpectedLengthDigest,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::DigestAndPayloadMissing => "digest and payload missing",
            Self::FraudulentDigest => "fraudulent digest",
            Self::UnexpectedLengthDigest => "unexpected length digest",
        };
        f.write_str(printable)
    }
}

impl Message {
    /// Get payload digest, if `payload_digest` is missing then calculate it.
    pub fn payload_digest(&self) -> Result<[u8; 32], DigestError> {
        // Calculate payload digest
        let payload_digest: [u8; 32] = match self.payload_digest.len() {
            0 => {
                // Check payload is not missing too
                if self.payload.is_empty() {
                    return Err(DigestError::DigestAndPayloadMissing);
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
                        return Err(DigestError::FraudulentDigest);
                    }
                    payload_digest
                } else {
                    let slice = &self.payload_digest[..];
                    slice.try_into().unwrap()
                }
            }
            _ => return Err(DigestError::UnexpectedLengthDigest),
        };

        Ok(payload_digest)
    }

    /// Parse the [Message](struct.Message.html) to construct a [ParsedMessage](struct.ParsedMessage.html).
    ///
    /// The involves deserialization of both public keys, calculation of the payload digest, and coercion of byte fields into arrays.
    pub fn parse(self) -> Result<ParsedMessage, ParseError> {
        // Decode public keys
        let source_public_key =
            PublicKey::from_slice(&self.source_pub_key).map_err(ParseError::SourcePublicKey)?;
        let destination_public_key = PublicKey::from_slice(&self.destination_pub_key)
            .map_err(ParseError::DestinationPublicKey)?;

        // Calculate payload digest
        let payload_digest = self.payload_digest().map_err(ParseError::Digest)?;

        // Parse stamp data
        let stamp = self.stamp.ok_or(ParseError::MissingStamp)?;

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

/// Create the merged key from the source public key and destination private key.
pub fn create_merged_key(
    source_public_key: PublicKey,
    private_key: &[u8],
) -> Result<PublicKey, SecpError> {
    // Create merged key
    let mut merged_key = source_public_key;
    merged_key.mul_assign(&Secp256k1::verification_only(), private_key)?;
    Ok(merged_key)
}

/// Error associated with creating the shared key.
#[derive(Debug)]
pub enum SharedKeyError {
    Mul(SecpError),
    Expand,
}

/// Create shared key.
pub fn create_shared_key<'a>(
    source_public_key: PublicKey,
    private_key: &[u8],
    salt: &[u8],
    info: &'a [&'a [u8]],
) -> Result<[u8; 32], SharedKeyError> {
    // Create merged key
    let merged_key =
        create_merged_key(source_public_key, private_key).map_err(SharedKeyError::Mul)?;
    let raw_merged_key = merged_key.serialize();

    let salt = hkdf::Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(&raw_merged_key);
    let okm = prk
        .expand(info, HKDF_SHA256)
        .map_err(|_| SharedKeyError::Expand)?;

    let mut shared_key = [0; 32];
    okm.fill(&mut shared_key).unwrap(); // This is safe
    Ok(shared_key)
}

/// Error associated with authentication of the [Payload](struct.Payload.html).
#[derive(Debug)]
pub enum AuthenticationError {
    InvalidHmac,
    Expand,
}

/// Authenticate the [Payload](struct.Payload.html) and return the merged key.
#[inline]
pub fn authenticate(
    shared_key: &[u8],
    payload_digest: &[u8],
    auth_salt: &[u8],
) -> Result<(), AuthenticationError> {
    let shared_key = hkdf::Prk::new_less_safe(HKDF_SHA256, shared_key);

    let info = [auth_salt];

    // HMAC with salt
    let okm = shared_key
        .expand(&info, HKDF_SHA256)
        .map_err(|_| AuthenticationError::Expand)?;
    let mut digest = [0; 32];
    okm.fill(&mut digest).unwrap(); // This is safe

    // Check equality
    if digest.as_ref() != payload_digest {
        return Err(AuthenticationError::InvalidHmac);
    }
    Ok(())
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
    SharedKey(SharedKeyError),
    Authentication(AuthenticationError),
    Payload(MessageDecodeError),
    Decrypt(BlockModeError),
    Mul(SecpError),
}

impl ParsedMessage {
    /// Calculate the merged key from the destination private key.
    #[inline]
    pub fn create_merged_key(&self, private_key: &[u8]) -> Result<PublicKey, SecpError> {
        create_merged_key(self.source_public_key, private_key)
    }

    /// Create the shared key from the destination private key, a salt, and a list of HKDF info.
    #[inline]
    pub fn create_shared_key<'a>(
        &self,
        private_key: &[u8],
        salt: &[u8],
        info: &'a [&'a [u8]],
    ) -> Result<[u8; 32], SharedKeyError> {
        create_shared_key(self.source_public_key, private_key, salt, info)
    }

    /// Authenticate the HMAC payload and return the merged key.
    #[inline]
    pub fn authenticate(&self, shared_key: &[u8; 32]) -> Result<(), AuthenticationError> {
        authenticate(shared_key, &self.payload_digest, &self.salt)?;

        Ok(())
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
        auth_salt: &[u8],
        info: &[&[u8]],
        network: Network,
    ) -> Result<DecryptResult, DecryptError> {
        // Verify stamp
        let txs = self.verify_stamp(network).map_err(DecryptError::Stamp)?;

        // Create shared key
        let shared_key = self
            .create_shared_key(private_key, auth_salt, info)
            .map_err(DecryptError::SharedKey)?;

        // Authenticate HMAC payload
        self.authenticate(&shared_key)
            .map_err(DecryptError::Authentication)?;

        // Decrypt
        let mut raw_payload = &mut self.payload;
        let (key, iv) = shared_key.split_at(16);
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
        auth_salt: &[u8],
        info: &[&[u8]],
        network: Network,
    ) -> Result<DecryptResult, DecryptError> {
        // Verify stamp
        let txs = self.verify_stamp(network).map_err(DecryptError::Stamp)?;

        // Create shared key
        let shared_key = self
            .create_shared_key(private_key, auth_salt, info)
            .map_err(DecryptError::SharedKey)?;

        // Authenticate HMAC payload
        self.authenticate(&shared_key)
            .map_err(DecryptError::Authentication)?;

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

impl MessagePage {
    /// Convert the [MessagePage](struct.MessagePage.html) into a [PayloadPage](struct.PayloadPage.html).
    pub fn into_payload_page(self) -> PayloadPage {
        self.into()
    }
}

impl Into<PayloadPage> for MessagePage {
    fn into(self) -> PayloadPage {
        let payloads: Vec<Vec<u8>> = self
            .messages
            .into_iter()
            .map(|message| message.payload)
            .collect();
        PayloadPage {
            start_time: self.start_time,
            end_time: self.end_time,
            start_digest: self.start_digest,
            end_digest: self.end_digest,
            payloads,
        }
    }
}
