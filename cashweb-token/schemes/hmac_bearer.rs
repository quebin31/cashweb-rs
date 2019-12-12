use ring::hmac;

use futures::{
    future,
    task::{Context, Poll},
};
use http::request::Parts;
use tower_service::Service;

use crate::{models::Payment, ResponseFuture};

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
    type Future = ResponseFuture<Self::Response, Self::Error>;

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
