#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-relay-client` is a library providing [`RelayClient`] which allows
//! interaction with specific relay server.

pub mod services;

pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use hyper::{http::uri::InvalidUri, Client as HyperClient};
use secp256k1::key::PublicKey;
use tower_service::Service;
use tower_util::ServiceExt;

use relay::Profile;
use services::*;

/// RelayClient allows queries to specific relay servers.
#[derive(Clone, Debug)]
pub struct RelayClient<S> {
    inner_client: S,
}

impl<S> RelayClient<S> {
    /// Create a new client from a service.
    pub fn from_service(service: S) -> Self {
        Self {
            inner_client: service,
        }
    }
}

impl RelayClient<HyperClient<HttpConnector>> {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        Self {
            inner_client: HyperClient::new(),
        }
    }
}

/// Error associated with sending a request to a relay server.
#[derive(Debug)]
pub enum RelayError<E> {
    /// Invalid URI.
    Uri(InvalidUri),
    /// Error executing the service method.
    Error(E),
}

impl<E> From<E> for RelayError<E> {
    fn from(err: E) -> Self {
        Self::Error(err)
    }
}

/// A [`Profile`] paired with its [`PublicKey`].
#[derive(Clone, Debug)]
pub struct ProfilePackage {
    /// Public key of the metadata.
    pub public_key: PublicKey,
    /// The profile.
    pub profile: Profile,
}

impl<S> RelayClient<S>
where
    Self: Service<(Uri, GetProfile), Response = ProfilePackage>,
    Self: Sync + Clone + Send + 'static,
    <Self as Service<(Uri, GetProfile)>>::Future: Send + Sync + 'static,
{
    /// Get [`Profile`] from a server. The result is wrapped in [`ProfilePackage`].
    pub async fn get_profile(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<ProfilePackage, RelayError<<Self as Service<(Uri, GetProfile)>>::Error>> {
        // Construct URI
        let full_path = format!("{}/profiles/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(RelayError::Uri)?;

        // Construct request
        let request = (uri, GetProfile);

        self.clone()
            .oneshot(request)
            .await
            .map_err(RelayError::Error)
    }
}

impl<S> RelayClient<S>
where
    Self: Service<(Uri, PutProfile), Response = ()>,
    Self: Sync + Clone + Send + 'static,
    <Self as Service<(Uri, PutProfile)>>::Future: Send + Sync + 'static,
{
    /// Put a [`Profile`] to a relay server.
    pub async fn put_profile(
        &self,
        relay_url: &str,
        address: &str,
        profile: Profile,
        token: String,
    ) -> Result<(), RelayError<<Self as Service<(Uri, PutProfile)>>::Error>> {
        // Construct URI
        let full_path = format!("{}/profiles/{}", relay_url, address);
        let uri: Uri = full_path.parse().map_err(RelayError::Uri)?;

        // Construct request
        let request = (uri, PutProfile { token, profile });

        // Get response
        self.clone()
            .oneshot(request)
            .await
            .map_err(RelayError::Error)
    }
}
