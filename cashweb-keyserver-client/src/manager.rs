use std::{collections::HashSet, fmt, sync::Arc};

use hyper::{
    client::HttpConnector, http::uri::InvalidUri, Body, Client as HyperClient, Request, Response,
    Uri,
};
use rand::seq::SliceRandom;
use tower_service::Service;
use tower_util::ServiceExt;

use crate::{
    client::{services::*, KeyserverClient, PairedMetadata},
    models::{AddressMetadata, Peer, Peers},
};

/// KeyserverManager wraps a client and allows sampling and selecting of queries across a set of keyservers.
#[derive(Clone, Debug)]
pub struct KeyserverManager<S> {
    inner_client: KeyserverClient<S>,
    uris: Arc<Vec<Uri>>,
}

impl<S> KeyserverManager<S> {
    /// Creates a new manager from URIs and a client.
    pub fn from_service(service: S, uris: Arc<Vec<Uri>>) -> Self {
        Self {
            inner_client: KeyserverClient::from_service(service),
            uris,
        }
    }

    /// Converts the manager into the underlying client.
    pub fn into_client(self) -> KeyserverClient<S> {
        self.inner_client
    }
}

impl KeyserverManager<HyperClient<HttpConnector>> {
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

/// Select best [`AuthWrapper`] from a list.
///
/// Panics if empty slice is given.
pub fn select_auth_wrapper(metadatas: Vec<(Uri, PairedMetadata)>) -> (Uri, PairedMetadata) {
    metadatas
        .into_iter()
        .max_by_key(move |(_, pair)| pair.metadata.timestamp)
        .unwrap()
}

/// Aggregate a collection of [`Peers`] into a single structure.
pub fn aggregate_peers(peers: Vec<(Uri, Peers)>) -> Peers {
    let peers = peers
        .into_iter()
        .map(move |(_, peer)| peer.peers)
        .flatten()
        .collect();
    Peers { peers }
}

/// Response to a sample query.
#[derive(Debug)]
pub struct SampleResponse<R, E> {
    pub uri: Uri,
    pub response: R,
    pub errors: Vec<(Uri, E)>,
}

impl<R, E> SampleResponse<R, E>
where
    R: fmt::Debug,
    E: fmt::Debug,
{
    /// Create a sample response from a list of results.
    pub fn select<F: FnOnce(Vec<(Uri, R)>) -> (Uri, R)>(
        responses: Vec<(Uri, Result<R, E>)>,
        selector: F,
    ) -> Self {
        let (oks, errors): (Vec<_>, Vec<_>) =
            responses.into_iter().partition(|(_, res)| res.is_ok());
        let oks = oks
            .into_iter()
            .map(|(uri, res)| (uri, res.unwrap()))
            .collect();
        let errors = errors
            .into_iter()
            .map(|(uri, res)| (uri, res.unwrap_err()))
            .collect();

        let (uri, response) = selector(oks);

        SampleResponse {
            uri,
            response,
            errors,
        }
    }
}

/// Response to an aggregation query.
#[derive(Debug)]
pub struct AggregateResponse<R, E> {
    pub response: R,
    pub errors: Vec<(Uri, E)>,
}

impl<R, E> AggregateResponse<R, E>
where
    R: fmt::Debug,
    E: fmt::Debug,
{
    /// Create a sample response from a list of results.
    pub fn aggregate<F: FnOnce(Vec<(Uri, R)>) -> R>(
        responses: Vec<(Uri, Result<R, E>)>,
        aggregator: F,
    ) -> Self {
        let (oks, errors): (Vec<_>, Vec<_>) =
            responses.into_iter().partition(|(_, res)| res.is_ok());
        let oks = oks
            .into_iter()
            .map(|(uri, res)| (uri, res.unwrap()))
            .collect();
        let errors = errors
            .into_iter()
            .map(|(uri, res)| (uri, res.unwrap_err()))
            .collect();

        let response = aggregator(oks);

        AggregateResponse { response, errors }
    }
}

impl<S> KeyserverManager<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    S::Future: Send,
    S::Error: fmt::Debug + Send,
{
    /// Perform a uniform sample of metadata over keyservers and select the latest.
    pub async fn uniform_sample_metadata(
        &self,
        sample_size: usize,
    ) -> Result<
        SampleResponse<PairedMetadata, <KeyserverClient<S> as Service<(Uri, GetMetadata)>>::Error>,
        SampleError<<KeyserverClient<S> as Service<(Uri, GetMetadata)>>::Error>,
    > {
        let uris = uniform_random_sampler(&self.uris, sample_size);
        let sample_request = SampleRequest {
            request: GetMetadata,
            uris,
        };

        let responses = self.inner_client.clone().oneshot(sample_request).await?;
        let sample_response = SampleResponse::select(responses, select_auth_wrapper);

        Ok(sample_response)
    }

    /// Collect all peers from keyservers.
    pub async fn collect_peers(
        &self,
    ) -> Result<
        AggregateResponse<Peers, <KeyserverClient<S> as Service<(Uri, GetPeers)>>::Error>,
        SampleError<<KeyserverClient<S> as Service<(Uri, GetPeers)>>::Error>,
    > {
        let sample_request = SampleRequest {
            uris: self.uris.as_ref().clone(),
            request: GetPeers,
        };
        let responses = self.inner_client.clone().oneshot(sample_request).await?;

        let aggregate_response = AggregateResponse::aggregate(responses, aggregate_peers);

        Ok(aggregate_response)
    }

    /// Crawl peers.
    pub async fn crawl_peers(
        &self,
    ) -> Result<
        AggregateResponse<Peers, <KeyserverClient<S> as Service<(Uri, GetPeers)>>::Error>,
        SampleError<<KeyserverClient<S> as Service<(Uri, GetPeers)>>::Error>,
    > {
        let mut found_uris: HashSet<_> = self.uris.iter().cloned().collect();
        let mut total: HashSet<_> = self.uris.iter().cloned().collect();
        let mut total_errors = Vec::new();
        while !found_uris.is_empty() {
            // Get sample
            let uris = found_uris.drain().collect();
            let sample_request = SampleRequest {
                uris,
                request: GetPeers,
            };
            let responses: Vec<_> = self.inner_client.clone().oneshot(sample_request).await?;

            let AggregateResponse { response, errors } =
                AggregateResponse::aggregate(responses, aggregate_peers);

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
        Ok(AggregateResponse {
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
        AggregateResponse<(), <KeyserverClient<S> as Service<(Uri, PutMetadata)>>::Error>,
        SampleError<<KeyserverClient<S> as Service<(Uri, PutMetadata)>>::Error>,
    > {
        let uris = uniform_random_sampler(&self.uris, sample_size);
        let request = PutMetadata { token, metadata };
        let sample_request = SampleRequest { uris, request };
        let responses = self.inner_client.clone().call(sample_request).await?;

        Ok(AggregateResponse::aggregate(responses, |_| ()))
    }
}
