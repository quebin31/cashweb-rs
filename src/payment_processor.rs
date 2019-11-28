use async_trait::async_trait;
use bytes::BytesMut;
use futures::prelude::*;
use http::{
    header::HeaderValue,
    header::{ACCEPT, CONTENT_TYPE},
    Request,
};
use prost::{DecodeError, Message};

use crate::models::{Payment, PaymentAck};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError<P, C, E> {
    Processing(P),
    MissingContentTypeHeader,
    MissingAcceptHeader,
    PaymentDecode(DecodeError),
    BodyStream(C),
    MissingTransaction,
    MissingMerchantData,
    TokenExtraction(E),
}

#[async_trait]
pub trait PaymentProcessor {
    type ProcessingError;
    type Body;
    type Chunk;
    type BodyStreamError;
    type Context;
    type ProcessingResult;
    type TokenExtractionError;

    async fn process_transaction(
        &mut self,
        req: &Request<Self::Body>,
        merchant_data: &[u8],
        raw_tx: &[u8],
        context: &mut Self::Context,
    ) -> Result<Self::ProcessingResult, Self::ProcessingError>;

    async fn generate_token(
        &mut self,
        req: &Request<Self::Body>,
        merchant_data: &[u8],
        raw_tx: &[u8],
        processing_result: &Self::ProcessingResult,
        context: &mut Self::Context,
    ) -> Result<String, Self::TokenExtractionError>;

    async fn create_memo(
        &mut self,
        req: &Request<Self::Body>,
        merchant_data: &[u8],
        raw_tx: &[u8],
        processing_result: &Self::ProcessingResult,
        context: &mut Self::Context,
    ) -> Option<String>;
}

#[async_trait]
pub trait PaymentProcessorExt: PaymentProcessor
where
    Self::Body: TryStream<Ok = Self::Chunk, Error = Self::BodyStreamError> + Sync + Send + Copy,
    Self::Chunk: AsRef<[u8]> + Sync + Send,
    Self::Context: Send,
    Self::TokenExtractionError: Send,
    Self::ProcessingResult: Send + Sync,
{
    #[inline]
    async fn process_payment(
        &mut self,
        req: &Request<Self::Body>,
        context: &mut Self::Context,
    ) -> Result<
        PaymentAck,
        PaymentError<Self::ProcessingError, Self::BodyStreamError, Self::TokenExtractionError>,
    > {
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
        let payment_raw = req
            .body()
            .map_err(PaymentError::BodyStream)
            .try_fold(BytesMut::new(), move |mut body, chunk| {
                async move {
                    body.extend_from_slice(chunk.as_ref());
                    Ok(body)
                }
            })
            .await?;
        let payment = Payment::decode(payment_raw).map_err(PaymentError::PaymentDecode)?;

        // Parse transaction
        // Assuming first transaction
        let raw_tx = payment
            .transactions
            .get(0)
            .ok_or(PaymentError::MissingTransaction)?;

        // Extract merchant data
        let merchant_data = payment
            .merchant_data
            .as_ref()
            .ok_or(PaymentError::MissingMerchantData)?;

        // Process transaction
        let processing_result = self
            .process_transaction(req, &merchant_data, &raw_tx, context)
            .await
            .map_err(PaymentError::Processing)?;

        // Generate token
        let token = self
            .generate_token(req, &merchant_data, &raw_tx, &processing_result, context)
            .await
            .map_err(PaymentError::TokenExtraction)?;

        // Create memo
        let memo = self
            .create_memo(req, &merchant_data, &raw_tx, &processing_result, context)
            .await;

        // Create payment acknowledgement
        let payment_ack = PaymentAck { payment, memo };
        Ok(payment_ack)
    }
}
