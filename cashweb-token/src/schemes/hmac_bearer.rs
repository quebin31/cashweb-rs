use std::pin::Pin;

use futures_core::{
    task::{Context, Poll},
    Future,
};
use futures_util::future;
use http::request::Parts;
use ring::hmac;
use tower_service::Service;

use protobuf::models::Payment;

pub trait PreimageExtractor {
    type Error;
    fn extract(&mut self, parts: &Parts, payment: &Payment) -> Result<&[u8], Self::Error>;
}

pub struct HmacTokenGenerator<E> {
    key: hmac::Key,
    extractor: E,
}

impl<E: PreimageExtractor> Service<(&Parts, &Payment)> for HmacTokenGenerator<E>
where
    E::Error: 'static,
{
    type Response = String;
    type Error = E::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (parts, payment): (&Parts, &Payment)) -> Self::Future {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let preimage = match self.extractor.extract(parts, payment) {
            Ok(ok) => ok,
            Err(err) => return Box::pin(future::err(err)),
        };
        let tag = hmac::sign(&self.key, preimage);
        Box::pin(future::ok(base64::encode_config(
            tag.as_ref(),
            url_safe_config,
        )))
    }
}
