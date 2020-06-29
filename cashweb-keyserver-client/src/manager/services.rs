use std::{fmt, pin::Pin};

use futures_core::{
    task::{Context, Poll},
    Future,
};
use futures_util::future::{join, join_all};
use hyper::Uri;
use tower_service::Service;

use super::{KeyserverManager, SampleError, SampleResponse};

pub struct SampleRequest<T, Sampler, Selector> {
    pub request: T,
    pub sampler: Sampler,
    pub selector: Selector,
}

impl<C, T, Sampler, Selector> Service<SampleRequest<T, Sampler, Selector>> for KeyserverManager<C>
where
    T: Send + 'static + Clone,
    C: Send + Clone + 'static,
    C: Service<(Uri, T)>,
    <C as Service<(Uri, T)>>::Error: fmt::Debug + Send,
    <C as Service<(Uri, T)>>::Response: Send + fmt::Debug,
    <C as Service<(Uri, T)>>::Future: Send,
    Sampler: FnOnce(&[Uri]) -> Vec<Uri>,
    Selector: FnOnce(Vec<<C as Service<(Uri, T)>>::Response>) -> <C as Service<(Uri, T)>>::Response
        + Send
        + 'static,
{
    type Response =
        SampleResponse<<C as Service<(Uri, T)>>::Response, <C as Service<(Uri, T)>>::Error>;
    type Error = SampleError<<C as Service<(Uri, T)>>::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(SampleError::Poll)
    }

    fn call(
        &mut self,
        SampleRequest {
            request,
            sampler,
            selector,
        }: SampleRequest<T, Sampler, Selector>,
    ) -> Self::Future {
        let mut inner_client = self.inner_client.clone();
        let sample = sampler(self.uris.as_ref());

        let fut = async move {
            // Collect futures
            let response_futs = sample.into_iter().map(move |uri| {
                let response_fut = inner_client.call((uri.clone(), request.clone()));
                let uri_fut = async move { uri };
                join(uri_fut, response_fut)
            });
            let responses: Vec<(Uri, Result<_, _>)> = join_all(response_futs).await;

            // Seperate successes from errors
            let (oks, errors): (Vec<_>, Vec<_>) =
                responses.into_iter().partition(|(_, res)| res.is_ok());
            let oks: Vec<_> = oks.into_iter().map(|(_, res)| res.unwrap()).collect();
            let errors: Vec<_> = errors
                .into_iter()
                .map(move |(uri, res)| (uri, res.unwrap_err()))
                .collect();

            // If no successes then return all errors
            if oks.is_empty() {
                return Err(SampleError::Sample(errors));
            }

            let response = selector(oks);
            Ok(SampleResponse { response, errors })
        };
        Box::pin(fut)
    }
}
