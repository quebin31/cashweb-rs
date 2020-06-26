pub mod services;

use async_trait::async_trait;
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

/// Error associated with sending a request to a relay server.
#[derive(Debug)]
pub enum RelayError<E> {
    Uri(InvalidUri),
    Error(E),
}

impl<E> From<E> for RelayError<E> {
    fn from(err: E) -> Self {
        Self::Error(err)
    }
}

/// A profile paired with its public key.
#[derive(Clone, Debug)]
pub struct PairedProfile {
    pub public_key: PublicKey,
    pub profile: Profile,
}

#[async_trait]
pub trait GetProfileInterface {
    type Error;

    async fn get_profile(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedProfile, Self::Error>;
}

#[async_trait]
pub trait PutProfileInterface {
    type Error;

    async fn put_profile(
        &self,
        keyserver_url: &str,
        address: &str,
        profile: Profile,
        token: String,
    ) -> Result<(), Self::Error>;
}

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

#[async_trait]
impl<S> GetProfileInterface for S
where
    S: Service<(Uri, GetProfile), Response = PairedProfile>,
    S: Sync + Clone + Send + 'static,
    S::Future: Send + Sync + 'static,
{
    type Error = RelayError<S::Error>;

    async fn get_profile(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedProfile, Self::Error> {
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

#[async_trait]
impl<S> PutProfileInterface for S
where
    S: Service<(Uri, PutProfile), Response = ()>,
    S: Sync + Clone + Send + 'static,
    S::Future: Send + Sync + 'static,
{
    type Error = RelayError<S::Error>;

    /// Put metadata to a keyserver.
    async fn put_profile(
        &self,
        relay_url: &str,
        address: &str,
        profile: Profile,
        token: String,
    ) -> Result<(), Self::Error> {
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
