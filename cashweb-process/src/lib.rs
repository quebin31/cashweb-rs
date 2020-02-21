use http::{
    header::HeaderValue,
    header::{ACCEPT, CONTENT_TYPE},
    request::Parts,
    Request,
};
use hyper::{body::aggregate, error::Error as HyperError, Body};
use prost::{DecodeError, Message};

use protobuf::bip70::Payment;

/// The error type of payment preprocessing.
#[derive(Debug)]
pub enum PreprocessingError {
    /// An error occurred when streaming the body.
    BodyStream(HyperError),
    /// Missing the `application/bitcoincash-paymentack` header.
    MissingAcceptHeader,
    /// Missing the `application/bitcoincash-payment` header.
    MissingContentTypeHeader,
    /// Failed to decode the `Payment` protobuf.
    PaymentDecode(DecodeError),
}

pub async fn process_payment(req: Request<Body>) -> Result<(Parts, Payment), PreprocessingError> {
    // Bitcoin Cash Headers
    let bch_content_type_value = HeaderValue::from_static("application/bitcoincash-payment");
    let bch_accept_value = HeaderValue::from_static("application/bitcoincash-paymentack");

    // Check for content-type header
    if !req
        .headers()
        .get_all(CONTENT_TYPE)
        .iter()
        .any(|header_val| header_val == bch_content_type_value)
    {
        return Err(PreprocessingError::MissingContentTypeHeader);
    }

    // Check for accept header
    if !req
        .headers()
        .get_all(ACCEPT)
        .iter()
        .any(|header_val| header_val == bch_accept_value)
    {
        return Err(PreprocessingError::MissingAcceptHeader);
    }

    // Read and parse payment proto
    let (parts, body) = req.into_parts();
    let payment_raw = aggregate(body)
        .await
        .map_err(PreprocessingError::BodyStream)?;
    let payment = Payment::decode(payment_raw).map_err(PreprocessingError::PaymentDecode)?;

    Ok((parts, payment))
}
