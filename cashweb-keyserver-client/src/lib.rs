pub mod models;
pub mod services;

pub use services::*;

use async_trait::async_trait;

use hyper::http::uri::InvalidUri;

use tower_service::Service;
use tower_util::ServiceExt;

pub use models::*;

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
    async fn get_peers(&self, keyserver_url: &str) -> Result<Peers, KeyserverError<GetPeersError>>;

    async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedMetadata, KeyserverError<GetMetadataError>>;

    async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), KeyserverError<PutMetadataError>>;
}

#[async_trait]
impl<S> KeyserverClient for S
where
    S: Sync + 'static + Send + Clone,
    // GetPeers service
    S: Service<GetPeers, Response = Peers, Error = GetPeersError>,
    <S as Service<GetPeers>>::Future: Send,
    // GetMetadata service
    S: Service<GetMetadata, Response = PairedMetadata, Error = GetMetadataError>,
    <S as Service<GetMetadata>>::Future: Send,
    // PutMetadata service
    S: Service<PutMetadata, Response = (), Error = PutMetadataError>,
    <S as Service<PutMetadata>>::Future: Send,
{
    async fn get_peers(&self, keyserver_url: &str) -> Result<Peers, KeyserverError<GetPeersError>> {
        // Construct URI
        let full_path = format!("{}/peers", keyserver_url);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = GetPeers(uri);

        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }

    async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedMetadata, KeyserverError<GetMetadataError>> {
        // Construct URI
        let full_path = format!("{}/keys/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = GetMetadata(uri);

        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }

    async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), KeyserverError<PutMetadataError>> {
        // Construct URI
        let full_path = format!("{}/keys/{}", keyserver_url, address);
        let uri: Uri = full_path.parse().map_err(KeyserverError::Uri)?;

        // Construct request
        let request = PutMetadata {
            uri,
            token,
            metadata,
        };

        // Get response
        self.clone()
            .oneshot(request)
            .await
            .map_err(KeyserverError::Error)
    }
}
