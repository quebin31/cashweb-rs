use std::pin::Pin;

use futures_core::{
    task::{Context, Poll},
    Future,
};
use hyper::{
    body::aggregate, http::header::AUTHORIZATION, Body, Client as HyperClient, Error as HyperError,
    Request, StatusCode,
};
pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use prost::{DecodeError, Message as _};
use secp256k1::key::PublicKey;
use tower_service::Service;

use crate::models::*;

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
pub struct GetPeers(pub Uri);

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
pub struct GetMetadata(pub Uri);

/// The error associated with getting Metadata from a keyserver.
#[derive(Debug)]
pub enum GetMetadataError {
    // Error while decoding the [AddressMetadata](struct.AddressMetadata.html)
    MetadataDecode(DecodeError),
    /// Error while decoding the [AuthWrapper](struct.AuthWrapper.html).
    AuthWrapperDecode(DecodeError),
    /// Error while parsing the [AuthWrapper](struct.AuthWrapper.html).
    AuthWrapperParse(ParseError),
    /// Error while parsing the [AuthWrapper](struct.AuthWrapper.html).
    AuthWrapperVerify(VerifyError),
    /// Error while processing the body.
    Body(HyperError),
    /// A connection error occured.
    Connection(HyperError),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
    /// Peering is disabled on the keyserver.
    PeeringDisabled,
}

#[derive(Debug)]
pub struct PairedMetadata {
    pub public_key: PublicKey,
    pub metadata: AddressMetadata,
}

impl<C> Service<GetMetadata> for Client<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = PairedMetadata;
    type Error = GetMetadataError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, GetMetadata(uri): GetMetadata) -> Self::Future {
        let client = self.inner_client.clone();
        let fut = async move {
            // Get response
            let response = client.get(uri).await.map_err(Self::Error::Connection)?;

            // Check status code
            // TODO: Fix this
            match response.status() {
                StatusCode::OK => (),
                StatusCode::NOT_IMPLEMENTED => return Err(Self::Error::PeeringDisabled),
                code => return Err(Self::Error::UnexpectedStatusCode(code.as_u16())),
            }

            // Deserialize and decode body
            let body = response.into_body();
            let buf = aggregate(body).await.map_err(Self::Error::Body)?;
            let auth_wrapper = AuthWrapper::decode(buf).map_err(Self::Error::AuthWrapperDecode)?;

            // Parse auth wrapper
            let parsed_auth_wrapper = auth_wrapper
                .parse()
                .map_err(Self::Error::AuthWrapperParse)?;

            // Verify signature
            parsed_auth_wrapper
                .verify()
                .map_err(Self::Error::AuthWrapperVerify)?;

            // Decode metadata
            let metadata = AddressMetadata::decode(&mut parsed_auth_wrapper.payload.as_slice())
                .map_err(Self::Error::MetadataDecode)?;

            Ok(PairedMetadata {
                public_key: parsed_auth_wrapper.public_key,
                metadata,
            })
        };
        Box::pin(fut)
    }
}

#[derive(Debug)]
pub enum PutMetadataError {
    /// A connection error occured.
    Connection(HyperError),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
}

pub struct PutMetadata {
    pub uri: Uri,
    pub token: String,
    pub metadata: AddressMetadata,
}

impl<C> Service<PutMetadata> for Client<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = PutMetadataError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: PutMetadata) -> Self::Future {
        let client = self.inner_client.clone();

        // Construct body
        let mut body = Vec::with_capacity(request.metadata.encoded_len());
        request.metadata.encode(&mut body).unwrap();

        let http_request = Request::builder()
            .uri(request.uri)
            .header(AUTHORIZATION, request.token)
            .body(Body::from(body))
            .unwrap(); // This is safe

        let fut = async move {
            // Get response
            let response = client
                .request(http_request)
                .await
                .map_err(Self::Error::Connection)?;

            // Check status code
            // TODO: Fix this
            match response.status() {
                StatusCode::OK => (),
                code => return Err(Self::Error::UnexpectedStatusCode(code.as_u16())),
            }

            Ok(())
        };
        Box::pin(fut)
    }
}
