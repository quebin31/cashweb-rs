pub mod token_extractors;

use std::{marker::PhantomData, pin::Pin};

use futures::{
    future,
    prelude::*,
    task::{Context, Poll},
};
use http::Request;
use tower_layer::Layer;
use tower_service::Service;

use token_extractors::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<S, V> {
    NoAuthData,
    TokenValidate(V),
    Service(S),
}

#[derive(Clone)]
pub struct ResourceGuard<S, V, T> {
    service: S,
    validator: V,
    token_extractor: PhantomData<T>,
}

impl<S, V, T> ResourceGuard<S, V, T> {
    fn new(service: S, validator: V) -> Self {
        ResourceGuard {
            service,
            validator,
            token_extractor: PhantomData::<T>,
        }
    }
}

impl<S, V, T, B> Service<Request<B>> for ResourceGuard<S, V, T>
where
    B: 'static,
    S: Service<Request<B>> + Clone + 'static,
    V: Service<(Request<B>, String), Response = Request<B>>,
    V::Error: 'static,
    V::Future: 'static,
    T: TokenExtractor,
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
        let token_str = if let Some(token_str) = T::extract(&request) {
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

pub struct ValidationLayer<V, T> {
    validator: V,
    token_extractor: PhantomData<T>,
}

impl<V, T> ValidationLayer<V, T> {
    pub fn new(validator: V) -> Self {
        ValidationLayer {
            validator,
            token_extractor: PhantomData::<T>,
        }
    }
}

impl<S, V, T> Layer<S> for ValidationLayer<V, T>
where
    V: Clone,
{
    type Service = ResourceGuard<S, V, T>;

    fn layer(&self, service: S) -> Self::Service {
        ResourceGuard::new(service, self.validator.clone())
    }
}
