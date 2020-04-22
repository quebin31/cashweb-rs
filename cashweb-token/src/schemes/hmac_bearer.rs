use std::fmt;

use ring::hmac;

#[derive(Debug)]
pub enum ValidationError {
    Base64(base64::DecodeError),
    Invalid,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64(err) => err.fmt(f),
            Self::Invalid => f.write_str("invalid token"),
        }
    }
}

/// Basic HMAC token scheme.
#[derive(Debug)]
pub struct HmacScheme {
    key: hmac::Key,
}

impl HmacScheme {
    pub fn new(key: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Self { key }
    }

    /// Construct a token.
    pub fn construct_token(&self, data: &[u8]) -> String {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let tag = hmac::sign(&self.key, data);
        base64::encode_config(tag.as_ref(), url_safe_config)
    }

    /// Validate a token.
    pub async fn validate_token(&self, data: &[u8], token: &str) -> Result<(), ValidationError> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let tag = base64::decode_config(token, url_safe_config).map_err(ValidationError::Base64)?;
        hmac::verify(&self.key, data, &tag).map_err(|_| ValidationError::Invalid)
    }
}
