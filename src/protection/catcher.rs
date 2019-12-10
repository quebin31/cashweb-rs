use super::{GuardError, ProtectedService};

use futures::{
    prelude::*,
    task::{Context, Poll},
};
use http::Request;
use tower_layer::Layer;
use tower_service::Service;

use crate::{tokens::extractors::TokenExtractor, ResponseFuture};

/// A `Service` that catches `GuardError`s emitted by a `ProtectedService`.
pub struct ProtectedCatcher<S, T, V, C> {
    service: ProtectedService<S, T, V>,
    catcher: C,
}

impl<S, T, V, C> ProtectedCatcher<S, T, V, C> {
    pub fn new(service: ProtectedService<S, T, V>, catcher: C) -> Self {
        ProtectedCatcher { service, catcher }
    }
}

impl<S, T, V, C, B> Service<Request<B>> for ProtectedCatcher<S, T, V, C>
where
    B: 'static,
    S: Service<Request<B>> + Clone + 'static,
    V: Service<(Request<B>, String), Response = Request<B>>,
    V::Error: 'static,
    V::Future: 'static,
    C: Service<
            GuardError<S::Error, V::Error>,
            Response = S::Response,
            Error = GuardError<S::Error, V::Error>,
        > + Clone
        + 'static,
    T: TokenExtractor,
{
    type Response = S::Response;
    type Error = GuardError<S::Error, V::Error>;
    type Future = ResponseFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let mut catcher = self.catcher.clone();
        Box::pin(
            self.service
                .call(request)
                .or_else(move |err| catcher.call(err)),
        )
    }
}

/// A `Layer` which wraps a `ProtectedService` in `ProtectedCatcher` middleware.
pub struct ProtectedCatcherLayer<C> {
    catcher: C,
}

impl<S, T, V, C> Layer<ProtectedService<S, T, V>> for ProtectedCatcherLayer<C>
where
    C: Clone,
{
    type Service = ProtectedCatcher<S, T, V, C>;

    fn layer(&self, service: ProtectedService<S, T, V>) -> Self::Service {
        ProtectedCatcher::new(service, self.catcher.clone())
    }
}
