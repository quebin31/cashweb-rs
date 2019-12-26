pub mod catcher;

use std::pin::Pin;

use futures_core::{
    task::{Context, Poll},
    Future,
};
use futures_util::future::{self, TryFutureExt};
use http::Request;
use tower_layer::Layer;
use tower_service::Service;

use token::extract_pop;

/// The error type for access attempts to protected resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<S, V> {
    /// No authorization token was found using the extractor.
    NoAuthData,
    /// The token failed validation.
    TokenValidate(V),
    /// An error given by the protected service.
    Service(S),
}

/// A `Service` that protects the inner `Service` with a token validation.
///
/// If the authorization token is not present or the token fails to validate an error is returned.
#[derive(Clone)]
pub struct ProtectedService<S, V> {
    service: S,
    validator: V,
}

impl<S, V> ProtectedService<S, V> {
    fn new(service: S, validator: V) -> Self {
        ProtectedService { service, validator }
    }
}

impl<S, V, B> Service<Request<B>> for ProtectedService<S, V>
where
    B: 'static,
    S: Service<Request<B>> + Clone + 'static,
    V: Service<(Request<B>, String), Response = Request<B>>,
    V::Error: 'static,
    V::Future: 'static,
{
    type Response = S::Response;
    type Error = GuardError<S::Error, V::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Poll::Ready(ready) = self.service.poll_ready(cx) {
            if let Err(err) = ready {
                Poll::Ready(Err(GuardError::Service(err)))
            } else {
                Poll::Ready(Ok(()))
            }
        } else {
            Poll::Pending
        }
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // Attempt to extract token string from headers or query string
        let headers = request.headers();
        let token_str = if let Some(token_str) = extract_pop(headers) {
            token_str.to_string()
        } else {
            return Box::pin(future::err(GuardError::NoAuthData));
        };

        // Validate
        let validation_fut = self
            .validator
            .call((request, token_str))
            .map_err(GuardError::TokenValidate);

        // Call service
        let mut inner_service = self.service.clone();
        let fut = validation_fut
            .and_then(move |request| inner_service.call(request).map_err(GuardError::Service));

        Box::pin(fut)
    }
}

/// A `Layer` to wrap services in a `ProtectionService` middleware.
pub struct ProtectionLayer<V> {
    validator: V,
}

impl<V> ProtectionLayer<V> {
    pub fn new(validator: V) -> Self {
        ProtectionLayer { validator }
    }
}

impl<S, V> Layer<S> for ProtectionLayer<V>
where
    V: Clone,
{
    type Service = ProtectedService<S, V>;

    fn layer(&self, service: S) -> Self::Service {
        ProtectedService::new(service, self.validator.clone())
    }
}
