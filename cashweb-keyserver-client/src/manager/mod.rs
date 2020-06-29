pub mod services;

use std::{collections::HashSet, fmt, sync::Arc};

use hyper::{client::HttpConnector, http::uri::InvalidUri, Client as HyperClient, Uri};
use rand::seq::SliceRandom;
use tower_service::Service;
use tower_util::ServiceExt;

use crate::{
    client::{
        services::{GetMetadata, GetPeers, PutMetadata},
        KeyserverClient, PairedMetadata,
    },
    models::{AddressMetadata, Peer, Peers},
};
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

/// Aggregate a collection of peers into a single structure.
pub fn aggregate_peers(peers: Vec<Peers>) -> Peers {
    let peers = peers
        .into_iter()
        .map(move |peer| peer.peers)
        .flatten()
        .collect();
    Peers { peers }
}

impl<C> KeyserverManager<C>
where
    C: Send + Clone + 'static,
    // GetMetadata service
    C: Service<(Uri, GetMetadata), Response = PairedMetadata>,
    <C as Service<(Uri, GetMetadata)>>::Error: fmt::Debug + Send,
    <C as Service<(Uri, GetMetadata)>>::Response: Send + fmt::Debug,
    <C as Service<(Uri, GetMetadata)>>::Future: Send,
    // GetPeers service
    C: Service<(Uri, GetPeers), Response = Peers>,
    <C as Service<(Uri, GetPeers)>>::Error: fmt::Debug + Send,
    <C as Service<(Uri, GetPeers)>>::Response: Send + fmt::Debug,
    <C as Service<(Uri, GetPeers)>>::Future: Send,
    // PutMetadata service
    C: Service<(Uri, PutMetadata), Response = ()>,
    <C as Service<(Uri, PutMetadata)>>::Error: fmt::Debug + Send,
    <C as Service<(Uri, PutMetadata)>>::Response: Send + fmt::Debug,
    <C as Service<(Uri, PutMetadata)>>::Future: Send,
{
    /// Perform a uniform sample of metadata over keyservers and select the latest.
    pub async fn uniform_sample_metadata(
        &self,
        sample_size: usize,
    ) -> Result<
        SampleResponse<PairedMetadata, <C as Service<(Uri, GetMetadata)>>::Error>,
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

    /// Collect all peers from keyservers.
    pub async fn collect_peers(
        &self,
    ) -> Result<
        SampleResponse<Peers, <C as Service<(Uri, GetPeers)>>::Error>,
        SampleError<<C as Service<(Uri, GetPeers)>>::Error>,
    > {
        let sampler = |uris: &[Uri]| uris.to_vec();
        let sample_request = SampleRequest {
            request: GetPeers,
            sampler,
            selector: aggregate_peers,
        };
        self.clone().oneshot(sample_request).await
    }

    /// Crawl peers.
    pub async fn crawl_peers(
        &self,
    ) -> Result<
        SampleResponse<Peers, <C as Service<(Uri, GetPeers)>>::Error>,
        SampleError<<C as Service<(Uri, GetPeers)>>::Error>,
    > {
        let mut found_uris: HashSet<_> = self.uris.iter().cloned().collect();
        let mut total: HashSet<_> = self.uris.iter().cloned().collect();
        let mut total_errors = Vec::new();
        while !found_uris.is_empty() {

            // Get sample
            let sampler = |_: &[Uri]| found_uris.drain().collect();
            let sample_request = SampleRequest {
                request: GetPeers,
                sampler,
                selector: aggregate_peers,
            };
            let SampleResponse { response, errors } = self.clone().oneshot(sample_request).await?;

            // Aggregate errors
            total_errors.extend(errors);

            // Aggregate URIs
            let mut found_uris: HashSet<_> = response
                .peers
                .iter()
                .filter_map(|peer| peer.url.parse::<Uri>().ok())
                .collect();
            
            // Only keep new URIs
            found_uris = found_uris.difference(&total).cloned().collect();
            total = total.union(&found_uris).cloned().collect();
        }

        let response = Peers {
            peers: total
                .into_iter()
                .map(|uri| Peer {
                    url: uri.to_string(),
                })
                .collect(),
        };
        Ok(SampleResponse {
            response,
            errors: total_errors,
        })
    }

    /// Perform a uniform broadcast of metadata over keyservers and select the latest.
    pub async fn uniform_broadcast_metadata(
        &self,
        sample_size: usize,
        token: String,
        metadata: AddressMetadata,
    ) -> Result<
        SampleResponse<(), <C as Service<(Uri, PutMetadata)>>::Error>,
        SampleError<<C as Service<(Uri, PutMetadata)>>::Error>,
    > {
        let sampler = |uris: &[Uri]| uniform_random_sampler(uris, sample_size);
        let request = PutMetadata { token, metadata };
        let sample_request = SampleRequest {
            request,
            sampler,
            selector: |_| (),
        };
        self.clone().oneshot(sample_request).await
    }
}
