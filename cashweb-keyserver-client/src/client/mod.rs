pub mod services;

use crate::models::*;
pub use services::*;

use hyper::{http::uri::InvalidUri, Body, Client as HyperClient, Request, Response};
use secp256k1::key::PublicKey;
use tower_service::Service;
use tower_util::ServiceExt;

/// Error associated with sending a request to a keyserver.
#[derive(Debug)]
pub enum KeyserverError<E> {
    Uri(InvalidUri),
    Error(E),
}

impl<E> From<E> for KeyserverError<E> {
    fn from(err: E) -> Self {
        Self::Error(err)
    }
}

///
#[derive(Clone, Debug)]
pub struct PairedMetadata {
    pub public_key: PublicKey,
    pub metadata: AddressMetadata,
}

/// KeyserverClient allows queries to specific keyservers.
#[derive(Clone, Debug)]
pub struct KeyserverClient<S> {
    inner_client: S,
}

impl<S> KeyserverClient<S> {
    /// Create a new client from a service.
    pub fn from_service(service: S) -> Self {
        Self {
            inner_client: service,
        }
    }
}

impl KeyserverClient<HyperClient<HttpConnector>> {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        Self {
            inner_client: HyperClient::new(),
        }
    }
}

impl<S> KeyserverClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    /// Get peers from a keyserver.
    pub async fn get_peers(
        &self,
        keyserver_url: &str,
    ) -> Result<Peers, KeyserverError<<Self as Service<(Uri, GetPeers)>>::Error>> {
        // Construct URI
        let full_path = format!("{}/peers", keyserver_url);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = (uri, GetPeers);

        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }

    /// Get metadata from a keyserver.
    pub async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedMetadata, KeyserverError<<Self as Service<(Uri, GetMetadata)>>::Error>> {
        // Construct URI
        let full_path = format!("{}/keys/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = (uri, GetMetadata);

        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }

    /// Put metadata to a keyserver.
    pub async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), KeyserverError<<Self as Service<(Uri, PutMetadata)>>::Error>> {
        // Construct URI
        let full_path = format!("{}/keys/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = (uri, PutMetadata { token, metadata });

        // Get response
        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }
}
