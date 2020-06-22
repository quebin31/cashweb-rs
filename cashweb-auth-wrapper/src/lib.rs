use std::{
    convert::{Infallible, TryInto},
    fmt,
};

use ring::digest::{digest, SHA256};
use secp256k1::{key::PublicKey, Error as SecpError, Message, Secp256k1, Signature};

include!(concat!(env!("OUT_DIR"), "/wrapper.rs"));

/// The error associated with validation and parsing of the [AuthorizationWrapper](struct.AuthorizationWrapper.html).
#[derive(Debug)]
pub enum ValidationError {
    InvalidSignature(SecpError),
    Message(SecpError),
    PublicKey(SecpError),
    Signature(SecpError),
    UnsupportedScheme,
    FraudulentDigest,
    DigestAndPayloadMissing,
    UnexpectedLengthDigest,
}

#[derive(Debug)]
pub enum ValidateDecodeError<E> {
    Validate(ValidationError),
    Decode(E),
}

impl<E> From<ValidationError> for ValidateDecodeError<E> {
    fn from(err: ValidationError) -> Self {
        Self::Validate(err)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::InvalidSignature(err) => return err.fmt(f),
            Self::Message(err) => return err.fmt(f),
            Self::PublicKey(err) => return err.fmt(f),
            Self::Signature(err) => return err.fmt(f),
            Self::UnsupportedScheme => "unsupported signature scheme",
            Self::FraudulentDigest => "fraudulent digest",
            Self::DigestAndPayloadMissing => "digest and payload missing",
            Self::UnexpectedLengthDigest => "unexpected length digest",
        };
        f.write_str(printable)
    }
}

/// Represents a [AuthorizationWrapper](struct.AuthorizationWrapper.html) post-parsing.
///
/// Generic over the payload type.
pub struct ParsedAuthWrapper<P> {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub scheme: auth_wrapper::SignatureScheme,
    pub payload: P,
    pub payload_digest: [u8; 32],
}

impl AuthWrapper {
    /// Validate the [AuthorizationWrapper](struct.AuthorizationWrapper.html).
    pub fn validate(self) -> Result<ParsedAuthWrapper<Vec<u8>>, ValidationError> {
        self.validate_decode(|x| Ok::<_, Infallible>(x))
            .map_err(|err| match err {
                ValidateDecodeError::Decode(_) => unreachable!(), // This is safe
                ValidateDecodeError::Validate(err) => err,
            })
    }

    /// Decode and validate the [AuthorizationWrapper](struct.AuthorizationWrapper.html).
    ///
    /// Must supply a function to decode the payload.
    pub fn validate_decode<P, F, E>(
        self,
        decoder: F,
    ) -> Result<ParsedAuthWrapper<P>, ValidateDecodeError<E>>
    where
        F: Fn(Vec<u8>) -> Result<P, E>,
    {
        // Parse public key
        let public_key =
            PublicKey::from_slice(&self.pub_key).map_err(ValidationError::PublicKey)?;

        // Parse scheme
        let scheme = auth_wrapper::SignatureScheme::from_i32(self.scheme)
            .ok_or(ValidationError::UnsupportedScheme)?;
        if self.scheme != 1 {
            // TODO: Support Schnorr
            return Err(ValidationError::UnsupportedScheme.into());
        }

        // Parse signature
        let signature =
            Signature::from_compact(&self.signature).map_err(ValidationError::Signature)?;
        let secp = Secp256k1::verification_only();

        // Construct and validate payload digest
        let payload_digest = match self.payload_digest.len() {
            0 => {
                if self.serialized_payload.is_empty() {
                    return Err(ValidationError::DigestAndPayloadMissing.into());
                } else {
                    let payload_digest = digest(&SHA256, &self.serialized_payload);
                    let digest_arr: [u8; 32] = payload_digest.as_ref().try_into().unwrap();
                    digest_arr
                }
            }
            32 => {
                let payload_digest = digest(&SHA256, &self.serialized_payload);
                if *payload_digest.as_ref() != self.payload_digest[..] {
                    return Err(ValidationError::FraudulentDigest.into());
                }
                let digest_arr: [u8; 32] = self.payload_digest[..].try_into().unwrap();
                digest_arr
            }
            _ => return Err(ValidationError::UnexpectedLengthDigest.into()),
        };

        // Verify signature on the message
        let msg = Message::from_slice(payload_digest.as_ref()).map_err(ValidationError::Message)?;
        secp.verify(&msg, &signature, &public_key)
            .map_err(ValidationError::InvalidSignature)?;

        let payload = decoder(self.serialized_payload).map_err(ValidateDecodeError::Decode)?;

        Ok(ParsedAuthWrapper {
            public_key,
            signature,
            scheme,
            payload,
            payload_digest,
        })
    }
}
