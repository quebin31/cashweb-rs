use ring::hmac;

use crate::*;

use async_trait::async_trait;

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

pub enum ValidationError {
    Base64(base64::DecodeError),
    Invalid,
}

#[async_trait]
impl TokenValidator for HmacTokenScheme {
    type Data = Vec<u8>;
    type Error = ValidationError;

    async fn validate_token(&self, data: Self::Data, token: &str) -> Result<(), Self::Error> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let tag = base64::decode_config(token, url_safe_config).map_err(ValidationError::Base64)?;
        hmac::verify(&self.key, &data, &tag).map_err(|_| ValidationError::Invalid)
    }
}
