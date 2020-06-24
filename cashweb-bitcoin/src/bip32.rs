use std::convert::TryInto;

use ring::hmac::{sign as hmac, Key as HmacKey, HMAC_SHA512};
use secp256k1::{Error as SecpError, PublicKey, Secp256k1, SecretKey};

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
    public_key: PublicKey,
    chain_code: [u8; 32],
}

impl ExtendedPublicKey {
    /// Construct a new master public key.
    pub fn new_master(public_key: PublicKey, chain_code: [u8; 32]) -> Self {
        Self {
            public_key,
            chain_code,
        }
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn into_public_key(self) -> PublicKey {
        self.public_key
    }

    pub fn into_parts(&self) -> (&PublicKey, &[u8; 32]) {
        (&self.public_key, &self.chain_code)
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
        let mut public_key = if let Some(num) = path_iter.next() {
            self.derive_public_child(secp, *num)?
        } else {
            return Ok(self.clone());
        };
        for num in path {
            public_key = public_key.derive_public_child(secp, *num)?
        }
        Ok(public_key)
    }

    /// Derive child public key.
    pub fn derive_public_child<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        child_number: ChildNumber,
    ) -> Result<ExtendedPublicKey, DeriveError> {
        let index = match child_number {
            ChildNumber::Hardened(_) => return Err(DeriveError::HardenedDeriveError),
            ChildNumber::Normal(index) => index,
        };
        let key = HmacKey::new(HMAC_SHA512, &self.chain_code);
        let data = [&self.public_key.serialize()[..], &index.to_be_bytes()[..]].concat();
        let hmac_result = hmac(&key, &data);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32]).unwrap(); // This is safe
        let chain_code: [u8; 32] = hmac_result.as_ref()[32..].try_into().unwrap(); // This is safe
        let mut public_key = self.public_key.clone();
        public_key
            .add_exp_assign(secp, &private_key[..])
            .map_err(DeriveError::InvalidTweak)?;

        Ok(ExtendedPublicKey {
            public_key,
            chain_code,
        })
    }
}

#[derive(Copy, Clone)]
pub struct ExtendedPrivateKey {
    private_key: SecretKey,
    chain_code: [u8; 32],
}

impl ExtendedPrivateKey {
    /// Construct a new master private key.
    pub fn new_master(private_key: SecretKey, chain_code: [u8; 32]) -> Self {
        ExtendedPrivateKey {
            private_key,
            chain_code,
        }
    }

    /// Get private key.
    pub fn get_private_key(&self) -> &SecretKey {
        &self.private_key
    }

    pub fn into_private_key(self) -> SecretKey {
        self.private_key
    }

    pub fn into_parts(&self) -> (&SecretKey, &[u8; 32]) {
        (&self.private_key, &self.chain_code)
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_private_path<C: secp256k1::Signing, P>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> ExtendedPrivateKey
    where
        for<'a> &'a P: IntoIterator<Item = &'a ChildNumber>,
    {
        let mut path_iter = path.into_iter();
        let mut private_key = if let Some(num) = path_iter.next() {
            self.derive_private_child(secp, *num)
        } else {
            return self.clone();
        };
        for num in path {
            private_key = private_key.derive_private_child(secp, *num);
        }
        private_key
    }

    /// Derive child private key.
    pub fn derive_private_child<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        child_number: ChildNumber,
    ) -> ExtendedPrivateKey {
        // Calculate HMAC
        let key = HmacKey::new(HMAC_SHA512, &self.chain_code);
        let hmac_result = match child_number {
            ChildNumber::Normal(index) => {
                // Non-hardened key: compute public data and use that
                let raw_public_key =
                    PublicKey::from_secret_key(secp, &self.private_key).serialize();
                let data = [&raw_public_key[..], &index.to_be_bytes()].concat();
                hmac(&key, &data)
            }
            ChildNumber::Hardened(index) => {
                // Hardened key: use only secret data to prevent public derivation
                let data = [&[0], &self.private_key[..], &index.to_be_bytes()].concat();
                hmac(&key, &data)
            }
        };

        // Construct new private key
        let mut private_key =
            secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32]).unwrap(); // This is safe
        private_key.add_assign(&self.private_key[..]).unwrap(); // This is safe

        // Construct new extended private key
        let chain_code = hmac_result.as_ref()[32..].try_into().unwrap(); // This is safe
        ExtendedPrivateKey {
            private_key,
            chain_code,
        }
    }
}
