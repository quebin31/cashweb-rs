//!

pub mod services;

use bytes::Bytes;
use hyper::{client::HttpConnector, http::uri::InvalidUri, Client as HyperClient};
use hyper_tls::HttpsConnector;
use secp256k1::key::PublicKey;
use tower_service::Service;
use tower_util::ServiceExt;

use crate::models::*;
use services::*;

/// Error associated with sending a request to a keyserver.
#[derive(Debug)]
pub enum KeyserverError<E> {
    /// Invalid URI.
    Uri(InvalidUri),
    /// Error executing the service method.
    Error(E),
}

impl<E> From<E> for KeyserverError<E> {
    fn from(err: E) -> Self {
        Self::Error(err)
    }
}

/// The [`AddressMetadata`] paired with its [`PublicKey`], the raw [`AuthWrapper`] and a [`POP token`].
///
/// [`POP token`]: https://github.com/cashweb/specifications/blob/master/proof-of-payment-token/specification.mediawiki
#[derive(Clone, Debug)]
pub struct MetadataPackage {
    /// [`POP token`] attached to the response.
    ///
    /// [`POP token`]: https://github.com/cashweb/specifications/blob/master/proof-of-payment-token/specification.mediawiki
    pub token: String,
    /// Public key of the metadata.
    pub public_key: PublicKey,
    /// The address metadata.
    pub metadata: AddressMetadata,
    /// The raw [`AuthWrapper`]
    pub raw_auth_wrapper: Bytes,
}

/// The raw [`AuthWrapper`] paired with a [`POP token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawAuthWrapperPackage {
    /// [`POP token`] attached to the response.
    ///
    /// [`POP token`]: https://github.com/cashweb/specifications/blob/master/proof-of-payment-token/specification.mediawiki
    pub token: String,
    /// The raw [`AuthWrapper`].
    pub raw_auth_wrapper: Bytes,
}

/// `KeyserverClient` allows queries to specific keyservers.
#[derive(Clone, Debug)]
pub struct KeyserverClient<S> {
    inner_client: S,
}

impl<S> KeyserverClient<S> {
    /// Create a new client from a [`Service`].
    ///
    /// [`Service`]: tower_service::Service
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

impl<S> KeyserverClient<S>
where
    Self: Service<(Uri, GetPeers), Response = Peers>,
    Self: Sync + Clone + Send + 'static,
    <Self as Service<(Uri, GetPeers)>>::Future: Send + Sync + 'static,
{
    /// Get [`Peers`] from a keyserver.
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
}

impl<S> KeyserverClient<S>
where
    Self: Service<(Uri, GetMetadata), Response = MetadataPackage>,
    Self: Sync + Clone + Send + 'static,
    <Self as Service<(Uri, GetMetadata)>>::Future: Send + Sync + 'static,
{
    /// Get [`AddressMetadata`] from a server. The result is wrapped in [`MetadataPackage`].
    pub async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<MetadataPackage, KeyserverError<<Self as Service<(Uri, GetMetadata)>>::Error>> {
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

impl<S> KeyserverClient<S>
where
    Self: Service<(Uri, PutMetadata), Response = ()>,
    Self: Sync + Clone + Send + 'static,
    <Self as Service<(Uri, PutMetadata)>>::Future: Send + Sync + 'static,
{
    /// Put [`AddressMetadata`] to a keyserver.
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
