pub mod schemes;

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use protobuf::bip70::Payment;

pub trait PreimageExtractor {
    type Error;

    fn extract(&self, payment: &Payment) -> Result<&[u8], Self::Error>;
}

pub trait TokenGenerator {
    type Error;

    fn construct_token(&self, payment: &Payment) -> Result<String, Self::Error>;
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
