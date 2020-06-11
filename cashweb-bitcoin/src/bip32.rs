use std::convert::TryInto;

use ring::hmac::{sign as hmac, Key as HmacKey, HMAC_SHA512};
use secp256k1::{Error as SecpError, PublicKey, Secp256k1};

/// A BIP32 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Error creating a master seed --- for application use
    RngError(String),
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
}

/// Error associated with child number construction.
#[derive(Debug)]
pub struct IndexError(u32);

/// Public key to public key derivation can not be performed for a hardened key.
#[derive(Debug)]
pub struct HardenedDeriveError;

#[derive(Clone, Copy, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Clone, Copy, Debug)]
pub enum ChildNumber {
    Normal(u32),
    Hardened(u32),
}

#[derive(Debug)]
pub enum DeriveError {
    /// Public key to public key derivation can not be performed for a hardened key.
    HardenedDeriveError,
    /// Invalid Tweak.
    InvalidTweak(SecpError),
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, IndexError> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal(index))
        } else {
            Err(IndexError(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, IndexError> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened(index))
        } else {
            Err(IndexError(index))
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened(number ^ (1 << 31))
        } else {
            ChildNumber::Normal(number)
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedPublicKey {
    child_number: ChildNumber,
    depth: u8,
    parent_fingerprint: u32,
    public_key: PublicKey,
    network: Network,
    chain_code: [u8; 32],
}

impl ExtendedPublicKey {
    /// Construct a new master public key.
    pub fn new_master(public_key: PublicKey, network: Network, chain_code: [u8; 32]) -> Self {
        Self {
            child_number: ChildNumber::from(0),
            depth: 0,
            parent_fingerprint: 0,
            public_key,
            network,
            chain_code,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_public_path<C: secp256k1::Verification, P>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPublicKey, DeriveError>
    where
        for<'a> &'a P: IntoIterator<Item = &'a ChildNumber>,
    {
        let mut path_iter = path.into_iter();
        let mut pk: ExtendedPublicKey = if let Some(num) = path_iter.next() {
            self.derive_public_child(secp, *num)?
        } else {
            return Ok(self.clone());
        };
        for num in path {
            pk = pk.derive_public_child(secp, *num)?
        }
        Ok(pk)
    }

    /// Derive child public key.
    pub fn derive_public_child<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        num: ChildNumber,
    ) -> Result<ExtendedPublicKey, DeriveError> {
        let index = match num {
            ChildNumber::Hardened(_) => return Err(DeriveError::HardenedDeriveError),
            ChildNumber::Normal(index) => index,
        };
        let key = HmacKey::new(HMAC_SHA512, &self.chain_code);
        let data = [&self.public_key.serialize()[..], &index.to_be_bytes()[..]].concat();
        let hmac_result = hmac(&key, &data);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32]).unwrap(); // This is safe
        let chain_code: [u8; 32] = hmac_result.as_ref()[32..].try_into().unwrap(); // This is safe
        let mut pk = self.public_key.clone();
        pk.add_exp_assign(secp, &private_key[..])
            .map_err(DeriveError::InvalidTweak)?;

        Ok(ExtendedPublicKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.parent_fingerprint,
            child_number: num,
            public_key: pk,
            chain_code: chain_code,
        })
    }
}
