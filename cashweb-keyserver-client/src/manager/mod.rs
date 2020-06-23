pub mod services;

use std::{fmt, sync::Arc};

use hyper::{client::HttpConnector, http::uri::InvalidUri, Client as HyperClient, Uri};
use rand::seq::SliceRandom;
use tower_service::Service;
use tower_util::ServiceExt;

use crate::client::{services::GetMetadata, KeyserverClient, PairedMetadata};
pub use services::*;

/// KeyserverManager wraps a client and allows sampling and selecting of queries across a set of keyservers.
#[derive(Clone, Debug)]
pub struct KeyserverManager<C> {
    inner_client: C,
    uris: Arc<Vec<Uri>>,
}

/// Error associated with sending sample requests.
#[derive(Debug)]
pub enum SampleError<E> {
    Poll(E),
    Sample(Vec<(Uri, E)>),
}

/// Represents the a response of a sample query.
#[derive(Debug)]
pub struct SampleResponse<R, E> {
    pub response: R,
    pub errors: Vec<(Uri, E)>,
}

impl<C> KeyserverManager<C> {
    /// Creates a new manager from URIs and a client.
    pub fn from_client(inner_client: C, uris: Arc<Vec<Uri>>) -> Self {
        Self { inner_client, uris }
    }
}

impl KeyserverManager<KeyserverClient<HyperClient<HttpConnector>>> {
    /// Create a HTTP manager.
    pub fn new(uris: Vec<String>) -> Result<Self, InvalidUri> {
        let uris: Result<Vec<Uri>, _> = uris.into_iter().map(|uri| uri.parse()).collect();
        let uris = uris?;
        Ok(Self {
            inner_client: KeyserverClient::new(),
            uris: Arc::new(uris),
        })
    }
}

/// Choose from a random subset of URIs.
pub fn uniform_random_sampler(uris: &[Uri], size: usize) -> Vec<Uri> {
    let mut rng = &mut rand::thread_rng();
    uris.choose_multiple(&mut rng, size).cloned().collect()
}

/// Select best authwrapper.
///
/// Panics if empty slice is given.
pub fn select_auth_wrapper(metadatas: Vec<PairedMetadata>) -> PairedMetadata {
    metadatas
        .into_iter()
        .max_by_key(move |pairs| pairs.metadata.timestamp)
        .unwrap()
}

impl<C> KeyserverManager<C>
where
    C: Send + Clone + 'static,
    // GetMetadata service
    C: Service<(Uri, GetMetadata), Response = PairedMetadata>,
    <C as Service<(Uri, GetMetadata)>>::Error: fmt::Debug + Send,
    <C as Service<(Uri, GetMetadata)>>::Response: Send + fmt::Debug,
    <C as Service<(Uri, GetMetadata)>>::Future: Send,
{
    pub async fn sample_metadata(
        &self,
        sample_size: usize,
    ) -> Result<
        SampleResponse<
            <C as Service<(Uri, GetMetadata)>>::Response,
            <C as Service<(Uri, GetMetadata)>>::Error,
        >,
        SampleError<<C as Service<(Uri, GetMetadata)>>::Error>,
    > {
        let sampler = |uris: &[Uri]| uniform_random_sampler(uris, sample_size);
        let sample_request = SampleRequest {
            request: GetMetadata,
            sampler,
            selector: select_auth_wrapper,
        };
        self.clone().oneshot(sample_request).await
    }
}
