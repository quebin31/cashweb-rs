#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-token` is a library providing utility methods for the [`POP Token Protocol`].
//!
//! [`POP Token Protocol`]: https://github.com/cashweb/specifications/blob/master/proof-of-payment-token/specification.mediawiki

pub mod schemes;

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};

/// Extract a POP token from `Authorization` header.
pub fn extract_pop_header(value: &HeaderValue) -> Option<&str> {
    if let Ok(header_str) = value.to_str() {
        return Some(header_str);
    }
    None
}

fn split_pop_token(full_token: &str) -> Option<&str> {
    if &full_token[..4] == "POP " {
        return Some(&full_token[4..]);
    }
    None
}

/// Extract the first POP token from [`HeaderMap`].
pub fn extract_pop<'a>(headers: &'a HeaderMap, query_token: &'a Option<String>) -> Option<&'a str> {
    headers
        .get_all(AUTHORIZATION)
        .iter()
        .find_map(extract_pop_header)
        .or_else(|| query_token.as_ref().map(|token| &token[..]))
        .and_then(split_pop_token)
}
