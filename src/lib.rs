pub mod models {
    include!(concat!(env!("OUT_DIR"), "/models.rs"));
}

use http::{
    header::HeaderValue,
    header::{AUTHORIZATION, CONTENT_TYPE, ACCEPT},
    Request,
};
use bytes::BytesMut;
use prost::{Message, DecodeError};

use models::Payment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<E> {
    NoAuthData,
    TokenValidate(E),
}

impl<E> From<E> for GuardError<E> {
    fn from(err: E) -> Self {
        GuardError::TokenValidate(err)
    }
}

/// Extract POP token string from http header value
fn extract_pop_header(value: &HeaderValue) -> Option<&str> {
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

/// Extract POP token string from query string item
fn extract_pop_query(value: &str) -> Option<&str> {
    if &value[..5] == "code=" {
        Some(&value[5..])
    } else {
        None
    }
}

/// Proof-of-Payment guard surounding protected resource
#[inline]
pub fn pop_resource_guard<T, E, F>(req: &Request<T>, validate_token: F) -> Result<(), GuardError<E>>
where
    F: Fn(&str) -> Result<(), E>,
{
    // Search for POP token
    let token_str = if let Some(token_str) = req
        .headers()
        .get_all(AUTHORIZATION)
        .iter()
        .find_map(extract_pop_header)
    {
        // Found token string in authorization header
        token_str
    } else if let Some(query_str) = req.uri().query() {
        if let Some(token_str) = query_str.split('&').find_map(extract_pop_query) {
            // Found token in query string
            token_str
        } else {
            return Err(GuardError::NoAuthData);
        }
    } else {
        return Err(GuardError::NoAuthData);
    };
    validate_token(token_str)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError<E> {
    Validation(E),
    MissingContentTypeHeader,
    MissingAcceptHeader,
    PaymentDecode(DecodeError)
}

#[inline]
pub async fn process_payment<T, E, F>(req: &Request<T>, validate_payment: F)
where
    F: Fn(),
{
    // BCH Headers
    let bch_content_type_value = HeaderValue::from_static("application/bitcoincash-payment");
    let bch_accept_value = HeaderValue::from_static("application/bitcoincash-paymentack");

    // Check for content-type header
    if !req
        .headers()
        .get_all(CONTENT_TYPE)
        .iter()
        .any(|header_val| header_val == bch_content_type_value)
    {
        return Err(PaymentError::MissingContentTypeHeader);
    }

    // Check for accept header
    if !req
        .headers()
        .get_all(ACCEPT)
        .iter()
        .any(|header_val| header_val == bch_accept_value)
    {
        return Err(PaymentError::MissingAcceptHeader);
    }

    // Read and parse payment proto
    let payment_raw = payload
        .map_err(|_| PaymentError::Payload)
        .fold(BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, PaymentError<E>>(body)
        })
        .await;
    let payment = Payment::decode(payment_raw).map_err(|err| PaymentError::PaymentDecode(err));
    Ok(())
}
