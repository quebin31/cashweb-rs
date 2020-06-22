use std::pin::Pin;

use async_trait::async_trait;
use futures_core::{
    task::{Context, Poll},
    Future,
};
use hyper::{
    body::aggregate, http::uri::InvalidUri, Client as HyperClient, Error as HyperError, StatusCode,
};
pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use prost::{DecodeError, Message as _};
use tower_service::Service;
use tower_util::ServiceExt;

mod models {
    include!(concat!(env!("OUT_DIR"), "/keyserver.rs"));
    pub use ::auth_wrapper::*;
}

pub use models::*;

#[derive(Clone, Debug)]
pub struct Client<C> {
    inner_client: HyperClient<C>,
}

impl Client<HttpConnector> {
    /// Creates a new client.
    pub fn new() -> Self {
        Self {
            inner_client: HyperClient::new(),
        }
    }
}

/// Represents a request for the Peers object.
pub struct GetPeers(Uri);

/// The error associated with getting Peers from a keyserver.
#[derive(Debug)]
pub enum GetPeersError {
    /// Error while processing the body.
    Body(HyperError),
    /// A connection error occured.
    Connection(HyperError),
    /// Error while decoding the body.
    Decode(DecodeError),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
    /// Peering is disabled on the
    PeeringDisabled,
}

impl<C> Service<GetPeers> for Client<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = Peers;
    type Error = GetPeersError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, GetPeers(uri): GetPeers) -> Self::Future {
        let client = self.inner_client.clone();
        let fut = async move {
            let response = client.get(uri).await.map_err(Self::Error::Connection)?;
            match response.status() {
                StatusCode::OK => (),
                StatusCode::NOT_IMPLEMENTED => return Err(Self::Error::PeeringDisabled),
                code => return Err(Self::Error::UnexpectedStatusCode(code.as_u16())),
            }
            let body = response.into_body();
            let buf = aggregate(body).await.map_err(Self::Error::Body)?;
            let peers = Peers::decode(buf).map_err(Self::Error::Decode)?;
            Ok(peers)
        };
        Box::pin(fut)
    }
}

/// Represents a request for the Metadata object.
pub struct GetMetadata(Uri);

/// The error associated with getting Metadata from a keyserver.
#[derive(Debug)]
pub enum GetMetadataError {
    /// Error while decoding the AddressMetadata.
    AddressMetadata(ValidateDecodeError<DecodeError>),
    /// Error while decoding the AuthWrapper.
    AuthWrapperDecode(DecodeError),
    /// Error while processing the body.
    Body(HyperError),
    /// A connection error occured.
    Connection(HyperError),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
    /// Peering is disabled on the keyserver.
    PeeringDisabled,
}

pub type WrappedMetadata = ParsedAuthWrapper<AddressMetadata>;

impl<C> Service<GetMetadata> for Client<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = WrappedMetadata;
    type Error = GetMetadataError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, GetMetadata(uri): GetMetadata) -> Self::Future {
        let client = self.inner_client.clone();
        let fut = async move {
            let response = client.get(uri).await.map_err(Self::Error::Connection)?;
            match response.status() {
                StatusCode::OK => (),
                StatusCode::NOT_IMPLEMENTED => return Err(Self::Error::PeeringDisabled),
                code => return Err(Self::Error::UnexpectedStatusCode(code.as_u16())),
            }
            let body = response.into_body();
            let buf = aggregate(body).await.map_err(Self::Error::Body)?;
            let auth_wrapper = AuthWrapper::decode(buf).map_err(Self::Error::AuthWrapperDecode)?;
            let wrapped_metadata = auth_wrapper
                .decode_validate(|x| AddressMetadata::decode(&mut x.as_slice()))
                .map_err(Self::Error::AddressMetadata)?;
            Ok(wrapped_metadata)
        };
        Box::pin(fut)
    }
}

pub enum KeyserverError<E> {
    Uri(InvalidUri),
    Error(E),
}

impl<E> From<E> for KeyserverError<E> {
    fn from(err: E) -> Self {
        Self::Error(err)
    }
}

#[async_trait]
pub trait KeyserverClient {
    async fn get_peers(
        &self,
        keyserver_url: &str,
    ) -> Result<Peers, KeyserverError<GetPeersError>>;

    async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<WrappedMetadata, KeyserverError<GetMetadataError>> ;
}

#[async_trait]
impl<S> KeyserverClient for S
where
    S: Sync + 'static + Send + Clone,
    // GetPeers service
    S: Service<GetPeers, Response = Peers, Error = GetPeersError>,
    <S as Service<GetPeers>>::Future: Send,
    // GetMetadata service
    S: Service<GetMetadata, Response = WrappedMetadata, Error = GetMetadataError>,
    <S as Service<GetMetadata>>::Future: Send,
{
    async fn get_peers(
        &self,
        keyserver_url: &str,
    ) -> Result<Peers, KeyserverError<GetPeersError>> {
        let full_path = format!("{}/peers", keyserver_url);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;
        let get_peers = GetPeers(uri);

        let peers = self
            .clone()
            .oneshot(get_peers)
            .await
            .map_err(KeyserverError::Error)?;
        Ok(peers)
    }

    async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<WrappedMetadata, KeyserverError<GetMetadataError>> {
        let full_path = format!("{}/keys/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;
        let get_metadata = GetMetadata(uri);

        let wrapped_metadata = self
            .clone()
            .oneshot(get_metadata)
            .await
            .map_err(KeyserverError::Error)?;
        Ok(wrapped_metadata)
    }
}
