use async_trait::async_trait;
use http::Request;

use token::extract_pop;

/// The error type for access attempts to protected resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<E> {
    /// No authorization token was found using the extractor.
    NoAuthData,
    /// The token failed validation.
    TokenValidate(E),
}

#[async_trait]
pub trait TokenValidator {
    type Body;
    type Error;
    type AuxData;

    async fn gather_aux_data(&self, request: &Request<Self::Body>) -> Self::AuxData;

    async fn validate_token(
        &self,
        token: &str,
        aux: Self::AuxData,
    ) -> Result<(), GuardError<Self::Error>>;
}

#[async_trait]
pub trait Protection {
    type Body;
    type Error;

    async fn validate_request(
        &self,
        request: &Request<Self::Body>,
    ) -> Result<(), GuardError<Self::Error>>;
}

#[async_trait]
impl<V> Protection for V
where
    V: TokenValidator,
    V::Body: Sync,
    V::AuxData: Send,
    V: Send + Sync,
{
    type Body = <Self as TokenValidator>::Body;
    type Error = <Self as TokenValidator>::Error;

    async fn validate_request(
        &self,
        request: &Request<Self::Body>,
    ) -> Result<(), GuardError<Self::Error>> {
        // Attempt to extract token string from headers or query string
        let headers = request.headers();
        let token_str = extract_pop(headers).ok_or(GuardError::NoAuthData)?;

        // Validate
        let aux_data = self.gather_aux_data(request).await;
        self.validate_token(token_str, aux_data).await
    }
}
