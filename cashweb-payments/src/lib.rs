pub mod wallet;

use std::fmt;

use bytes::Bytes;
use http::{
    header::{HeaderMap, HeaderValue},
    header::{ACCEPT, CONTENT_TYPE},
};
use prost::{DecodeError, Message};

use protobuf::bip70::Payment;

/// The error type of payment preprocessing.
#[derive(Debug)]
pub enum PreprocessingError {
    /// Missing the `application/bitcoincash-paymentack` header.
    MissingAcceptHeader,
    /// Missing the `application/bitcoincash-payment` header.
    MissingContentTypeHeader,
    /// Failed to decode the `Payment` protobuf.
    PaymentDecode(DecodeError),
}

impl fmt::Display for PreprocessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match self {
            Self::MissingAcceptHeader => "not acceptable",
            Self::MissingContentTypeHeader => "invalid content-type",
            Self::PaymentDecode(err) => return err.fmt(f),
        };
        f.write_str(printable)
    }
}

pub async fn preprocess_payment(
    headers: HeaderMap,
    body: Bytes,
) -> Result<Payment, PreprocessingError> {
    // Bitcoin Cash Headers
    let bch_content_type_value = HeaderValue::from_static("application/bitcoincash-payment");
    let bch_accept_value = HeaderValue::from_static("application/bitcoincash-paymentack");

    // Check for content-type header
    if !headers
        .get_all(CONTENT_TYPE)
        .iter()
        .any(|header_val| header_val == bch_content_type_value)
    {
        return Err(PreprocessingError::MissingContentTypeHeader);
    }

    // Check for accept header
    if !headers
        .get_all(ACCEPT)
        .iter()
        .any(|header_val| header_val == bch_accept_value)
    {
        return Err(PreprocessingError::MissingAcceptHeader);
    }

    // Read and parse payment proto
    let payment = Payment::decode(body).map_err(PreprocessingError::PaymentDecode)?;

    Ok(payment)
}
