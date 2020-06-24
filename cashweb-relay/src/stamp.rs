use std::fmt;

use bitcoin::{
    bip32::*,
    transaction::{DecodeError as TransactionDecodeError, Transaction},
    Decodable,
};
use ring::digest::{digest, SHA256};
use ripemd160::{Digest, Ripemd160};
use secp256k1::{
    key::{PublicKey, SecretKey},
    Error as SecpError, Secp256k1,
};

pub use crate::{
    create_shared_key,
    models::{stamp::StampType, Stamp, StampOutpoints},
    SharedKeyError,
};

/// Error associated with verification of stamps.
#[derive(Debug)]
pub enum StampError {
    Decode(TransactionDecodeError),
    MissingOutput,
    NotP2PKH,
    UnexpectedAddress,
    DegenerateCombination,
    ChildNumberOverflow,
    UnsupportedStampType,
    NoneType,
}

impl fmt::Display for StampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::Decode(err) => return err.fmt(f),
            Self::MissingOutput => "missing output",
            Self::NotP2PKH => "non-p2pkh",
            Self::UnexpectedAddress => "unexpected address",
            Self::DegenerateCombination => "degenerate pubkey combination",
            Self::ChildNumberOverflow => "child number is too large",
            Self::UnsupportedStampType => "unsupported stamp type",
            Self::NoneType => "stamp type is none",
        };
        f.write_str(printable)
    }
}

impl Stamp {
    /// Verify that the stamp covers the payload_digest.
    #[inline]
    pub fn verify_stamp(
        &self,
        payload_digest: &[u8; 32],
        destination_public_key: &PublicKey,
    ) -> Result<Vec<Transaction>, StampError> {
        verify_stamp(
            &self.stamp_outpoints,
            payload_digest,
            destination_public_key,
            StampType::from_i32(self.stamp_type).ok_or(StampError::UnsupportedStampType)?, // This is safe
        )
    }
}

/// Verify that the stamp covers the payload_digest.
#[inline]
pub fn verify_stamp(
    stamp_outpoints: &[StampOutpoints],
    payload_digest: &[u8; 32],
    destination_public_key: &PublicKey,
    stamp_type: StampType,
) -> Result<Vec<Transaction>, StampError> {
    if stamp_type == StampType::None {
        return Err(StampError::NoneType);
    }

    // Calculate master pubkey
    let payload_secret_key = SecretKey::from_slice(&payload_digest.as_ref()).unwrap(); // This is safe
    let payload_public_key =
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &payload_secret_key);
    let combined_key = destination_public_key
        .combine(&payload_public_key)
        .map_err(|_| StampError::DegenerateCombination)?;
    let master_pk = ExtendedPublicKey::new_master(combined_key, *payload_digest);

    // Calculate intermediate child
    let intermediate_child = master_pk
        .derive_public_path(
            &Secp256k1::verification_only(),
            &[
                ChildNumber::from_normal_idx(44).unwrap(),
                ChildNumber::from_normal_idx(145).unwrap(),
            ],
        )
        .unwrap(); // This is safe

    let context = Secp256k1::verification_only();
    let mut txs = Vec::with_capacity(stamp_outpoints.len());
    for (tx_num, outpoint) in stamp_outpoints.iter().enumerate() {
        let tx =
            Transaction::decode(&mut outpoint.stamp_tx.as_slice()).map_err(StampError::Decode)?;

        // Calculate intermediate child
        let child_number = ChildNumber::from_normal_idx(tx_num as u32)
            .map_err(|_| StampError::ChildNumberOverflow)?;
        let tx_child = intermediate_child
            .derive_public_child(&context, child_number)
            .unwrap(); // TODO: Double check this is safe

        for vout in &outpoint.vouts {
            let output = tx
                .outputs
                .get(*vout as usize)
                .ok_or(StampError::MissingOutput)?;
            let script = &output.script;
            if !script.is_p2pkh() {
                return Err(StampError::NotP2PKH);
            }
            let pubkey_hash = &script.as_bytes()[3..23]; // This is safe as we've checked it's a p2pkh

            // Derive child key
            let child_number =
                ChildNumber::from_normal_idx(*vout).map_err(|_| StampError::ChildNumberOverflow)?;
            let child_key = tx_child
                .derive_public_child(&context, child_number)
                .unwrap(); // TODO: Double check this is safe
            let raw_child_key = child_key.public_key().serialize();
            let sha256_digest = digest(&SHA256, &raw_child_key);
            let hash160_digest = Ripemd160::digest(sha256_digest.as_ref());

            // Check equivalence
            if &hash160_digest[..] != pubkey_hash {
                return Err(StampError::UnexpectedAddress);
            }
        }

        txs.push(tx);
    }

    Ok(txs)
}
