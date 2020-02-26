use std::fmt;

use ring::hmac;
use async_trait::async_trait;

use crate::*;


pub struct HmacTokenScheme {
    key: hmac::Key,
}

impl HmacTokenScheme {
    pub fn new(key: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Self { key }
    }
}

impl TokenGenerator for HmacTokenScheme {
    type Data = Vec<u8>;
    type Error = ();

    fn construct_token(&self, data: Self::Data) -> Result<String, Self::Error> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let tag = hmac::sign(&self.key, &data);
        Ok(base64::encode_config(tag.as_ref(), url_safe_config))
    }
}

#[derive(Debug)]
pub enum ValidationError {
    Base64(base64::DecodeError),
    Invalid,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64(err) => return err.fmt(f),
            Self::Invalid => f.write_str("invalid token")
        }
    }
}

#[async_trait]
impl TokenValidator for HmacTokenScheme {
    type Data = Vec<u8>; // TODO: Fix this once async traits are stable
    type Error = ValidationError;

    async fn validate_token(&self, data: Self::Data, token: &str) -> Result<(), Self::Error> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let tag = base64::decode_config(token, url_safe_config).map_err(ValidationError::Base64)?;
        hmac::verify(&self.key, &data, &tag).map_err(|_| ValidationError::Invalid)
    }
}
