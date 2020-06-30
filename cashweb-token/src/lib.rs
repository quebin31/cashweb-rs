#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(elided_lifetimes_in_paths)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! `cashweb-token` is a library providing utility methods for the [`POP Token Protocol`].
//!
//! [`POP Token Protocol`]: https://github.com/cashweb/specifications/blob/master/proof-of-payment-token/specification.mediawiki

pub mod schemes;

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};

/// Extract a POP token from `Authorization` header.
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

/// Extract the first POP token from [`HeaderMap`].
pub fn extract_pop(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(AUTHORIZATION)
        .iter()
        .find_map(extract_pop_header)
}
