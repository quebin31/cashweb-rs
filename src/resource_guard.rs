use async_trait::async_trait;
use http::{header::HeaderValue, header::AUTHORIZATION, Request};

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

pub trait ResourceGuard {
    type ValidationError;
    type Body;
    type Context;
    fn validate_token(
        &mut self,
        token: &str,
        context: &mut Self::Context,
    ) -> Result<(), Self::ValidationError>;
}

pub trait ResourceGuardExt: ResourceGuard {
    /// Proof-of-Payment guard surounding protected resource
    #[inline]
    fn pop_resource_guard(
        &mut self,
        req: &Request<Self::Body>,
        context: &mut Self::Context,
    ) -> Result<(), GuardError<Self::ValidationError>> {
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
        self.validate_token(token_str, context)?;
        Ok(())
    }
}

#[async_trait]
pub trait ResourceGuardAsync {
    type ValidationError;
    type Body;
    type Context;
    async fn validate_token(
        &mut self,
        token: &str,
        context: &mut Self::Context,
    ) -> Result<(), Self::ValidationError>;
}

#[async_trait]
pub trait ResourceGuardAsyncExt: ResourceGuardAsync
where
    Self::Body: Sync,
    Self::Context: Sync + Send,
{
    /// Proof-of-Payment guard surounding protected resource
    #[inline]
    async fn guard(
        &mut self,
        req: &Request<Self::Body>,
        context: &mut Self::Context,
    ) -> Result<(), GuardError<Self::ValidationError>> {
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
        self.validate_token(token_str, context).await?;
        Ok(())
    }
}
