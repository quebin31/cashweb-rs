pub mod models;
pub mod services;

pub use services::*;

use hyper::{http::uri::InvalidUri, Body, Request, Response};

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

impl<S> Client<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    pub async fn get_peers(
        &self,
        keyserver_url: &str,
    ) -> Result<Peers, KeyserverError<<Self as Service<GetPeers>>::Error>> {
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

    pub async fn get_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
    ) -> Result<PairedMetadata, KeyserverError<<Self as Service<GetMetadata>>::Error>> {
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

    pub async fn put_metadata(
        &self,
        keyserver_url: &str,
        address: &str,
        metadata: AddressMetadata,
        token: String,
    ) -> Result<(), KeyserverError<<Self as Service<PutMetadata>>::Error>> {
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
