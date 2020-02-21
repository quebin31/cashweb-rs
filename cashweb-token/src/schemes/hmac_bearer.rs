use http::request::Parts;
use ring::hmac;

use crate::*;
use protobuf::bip70::Payment;

pub struct HmacTokenGenerator<E> {
    key: hmac::Key,
    extractor: E,
}

impl<E: PreimageExtractor> TokenGenerator for HmacTokenGenerator<E> {
    type Error = E::Error;

    fn construct_token(&self, parts: &Parts, payment: &Payment) -> Result<String, Self::Error> {
        let url_safe_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let preimage = self.extractor.extract(&parts, &payment)?;
        let tag = hmac::sign(&self.key, preimage);
        Ok(base64::encode_config(tag.as_ref(), url_safe_config))
    }
}
