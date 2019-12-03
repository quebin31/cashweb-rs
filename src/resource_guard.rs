use std::pin::Pin;

use futures::{
    future,
    prelude::*,
    task::{Context, Poll},
};
use http::{header::HeaderValue, header::AUTHORIZATION, Request};
use tower_layer::Layer;
use tower_service::Service;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<V, S> {
    NoAuthData,
    TokenValidate(V),
    Service(S),
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

#[derive(Clone)]
pub struct ResourceGuard<S, V> {
    service: S,
    validator: V,
}

impl<S, V> ResourceGuard<S, V> {
    fn new(service: S, validator: V) -> Self {
        ResourceGuard { service, validator }
    }
}

impl<S, V, B> Service<Request<B>> for ResourceGuard<S, V>
where
    B: 'static,
    S: Service<Request<B>> + Clone + 'static,
    V: Service<(Request<B>, String), Response = Request<B>>,
    V::Error: 'static,
    V::Future: 'static,
{
    type Response = S::Response;
    type Error = GuardError<V::Error, S::Error>;
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
        let token_str = if let Some(token_str) = request
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .find_map(extract_pop_header)
        {
            // Found token string in authorization header
            token_str.to_string()
        } else if let Some(query_str) = request.uri().query() {
            if let Some(token_str) = query_str.split('&').find_map(extract_pop_query) {
                // Found token in query string
                token_str.to_string()
            } else {
                // Query string but no token
                return Box::pin(future::err(GuardError::NoAuthData));
            }
        } else {
            // No token found
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

pub struct ValidationLayer<V> {
    inner: V,
}

impl<S, V> Layer<S> for ValidationLayer<V>
where
    V: Clone,
{
    type Service = ResourceGuard<S, V>;

    fn layer(&self, service: S) -> Self::Service {
        ResourceGuard::new(service, self.inner.clone())
    }
}
