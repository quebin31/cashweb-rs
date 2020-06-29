pub mod services;

use crate::models::*;
pub use services::*;

use async_trait::async_trait;
use hyper::{http::uri::InvalidUri, Client as HyperClient};
use hyper_tls::HttpsConnector;
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

/// The AddressMetadata paired with its PublicKey.
#[derive(Clone, Debug)]
pub struct PairedMetadata {
    pub token: String,
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

impl KeyserverClient<HyperClient<HttpsConnector<HttpConnector>>> {
    /// Create new HTTPS client.
    pub fn new_tls() -> Self {
        let https = HttpsConnector::new();
        Self {
            inner_client: HyperClient::builder().build(https),
        }
    }
}

#[async_trait]
pub trait GetPeersInterface {
    type Error;
    /// Get peers from a keyserver.
    async fn get_peers(&self, keyserver_url: &str) -> Result<Peers, Self::Error>;
}

#[async_trait]
pub trait GetMetadataInterface {
    type Error;

    async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedMetadata, Self::Error>;
}

#[async_trait]
pub trait PutMetadataInterface {
    type Error;

    async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
impl<S> GetPeersInterface for S
where
    S: Service<(Uri, GetPeers), Response = Peers>,
    S: Sync + Clone + Send + 'static,
    S::Future: Send + Sync + 'static,
{
    type Error = KeyserverError<S::Error>;

    async fn get_peers(&self, keyserver_url: &str) -> Result<Peers, Self::Error> {
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
}

#[async_trait]
impl<S> GetMetadataInterface for S
where
    S: Service<(Uri, GetMetadata), Response = PairedMetadata>,
    S: Sync + Clone + Send + 'static,
    S::Future: Send + Sync + 'static,
{
    type Error = KeyserverError<S::Error>;

    /// Get metadata from a keyserver.
    async fn get_metadata(
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
}

#[async_trait]
impl<S> PutMetadataInterface for S
where
    S: Service<(Uri, PutMetadata), Response = ()>,
    S: Sync + Clone + Send + 'static,
    S::Future: Send + Sync + 'static,
{
    type Error = KeyserverError<S::Error>;

    /// Put metadata to a keyserver.
    async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), Self::Error> {
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
