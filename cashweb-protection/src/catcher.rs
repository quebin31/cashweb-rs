use std::{marker::PhantomData, pin::Pin};

use super::{GuardError, ProtectedService};

use futures_core::{
    task::{Context, Poll},
    Future,
};
use futures_util::future::{self, TryFutureExt};
use http::{Request, Response};
use tower_layer::Layer;
use tower_service::Service;

/// A `Service` that catches `GuardError`s emitted by a `ProtectedService`.
pub struct ProtectedCatcher<S, V, C> {
    service: ProtectedService<S, V>,
    catcher: C,
}

impl<S, V, C> ProtectedCatcher<S, V, C> {
    pub fn new(service: ProtectedService<S, V>, catcher: C) -> Self {
        ProtectedCatcher { service, catcher }
    }
}

impl<S, V, C, B> Service<Request<B>> for ProtectedCatcher<S, V, C>
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
{
    type Response = S::Response;
    type Error = GuardError<S::Error, V::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

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

impl<S, V, C> Layer<ProtectedService<S, V>> for ProtectedCatcherLayer<C>
where
    C: Clone,
{
    type Service = ProtectedCatcher<S, V, C>;

    fn layer(&self, service: ProtectedService<S, V>) -> Self::Service {
        ProtectedCatcher::new(service, self.catcher.clone())
    }
}

#[derive(Clone)]
pub struct StaticRedirect<S, V, B> {
    redirect_url: String,
    service_error: PhantomData<S>,
    validation_error: PhantomData<V>,
    body: PhantomData<B>,
}

impl<S, V, B> StaticRedirect<S, V, B> {
    pub fn new(redirect_url: &str) -> Self {
        StaticRedirect {
            redirect_url: redirect_url.to_string(),
            service_error: PhantomData::<S>::default(),
            validation_error: PhantomData::<V>::default(),
            body: PhantomData::<B>::default(),
        }
    }
}

impl<S, V, B> Service<GuardError<S, V>> for StaticRedirect<S, V, B>
where
    B: Default,
    V: 'static,
    B: 'static,
    S: 'static,
{
    type Response = Response<B>;
    type Error = GuardError<S, V>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: GuardError<S, V>) -> Self::Future {
        Box::pin(future::ok(
            Response::builder()
                .header("Location", self.redirect_url.clone())
                .body(B::default())
                .unwrap(),
        ))
    }
}
