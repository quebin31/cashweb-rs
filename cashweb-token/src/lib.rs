pub mod schemes;

use async_trait::async_trait;
use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};

#[async_trait]
pub trait TokenValidator {
    type Data;
    type Error;

    async fn validate_token(&self, data: Self::Data, token: &str) -> Result<(), Self::Error>;
}

pub trait TokenGenerator {
    type Data;
    type Error;

    fn construct_token(&self, data: Self::Data) -> Result<String, Self::Error>;
}

/// Extract POP token from `Authorization` header.
pub fn extract_pop_header(value: &HeaderValue) -> Option<&str> {
    if let Ok(header_str) = value.to_str() {
        if &header_str[..4] == "POP " {
            Some(&header_str[4..])
        } else {
            None
        }
    } else {
        None
    }
}

/// Extract POP token from `HeaderMap`.
pub fn extract_pop(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(AUTHORIZATION)
        .iter()
        .find_map(extract_pop_header)
}
