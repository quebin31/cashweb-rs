use std::pin::Pin;

use bytes::BytesMut;
use futures::{
    prelude::*,
    task::{Context, Poll},
};
use http::{
    header::HeaderValue,
    header::{ACCEPT, CONTENT_TYPE},
    request::Parts,
    Request,
};
use hyper::{error::Error as HyperError, Body};
use prost::{DecodeError, Message};
use tower_service::Service;

use crate::models::Payment;

#[derive(Debug)]
pub enum PreprocessingError {
    BodyStream(HyperError),
    MissingAcceptHeader,
    MissingContentTypeHeader,
    MissingTransaction,
    MissingMerchantData,
    PaymentDecode(DecodeError),
}

pub struct PaymentPreprocessor;

impl Service<Request<Body>> for PaymentPreprocessor {
    type Response = (Parts, Payment);
    type Error = PreprocessingError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let fut = async {
            // Bitcoin Cash Headers
            let bch_content_type_value =
                HeaderValue::from_static("application/bitcoincash-payment");
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
            let payment_raw = body
                .map_err(PreprocessingError::BodyStream)
                .try_fold(BytesMut::new(), move |mut body, chunk| {
                    async move {
                        body.extend_from_slice(chunk.as_ref());
                        Ok(body)
                    }
                })
                .await?;
            let payment =
                Payment::decode(payment_raw).map_err(PreprocessingError::PaymentDecode)?;

            Ok((parts, payment))
        };

        Box::pin(fut)
    }
}
