use std::pin::Pin;

use futures_core::{
    task::{Context, Poll},
    Future,
};
use hyper::{
    body::aggregate, http::header::AUTHORIZATION, Body, Error as HyperError, Request, Response,
    StatusCode,
};
pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use prost::{DecodeError, Message as _};
use secp256k1::key::PublicKey;
use tower_service::Service;

use super::Client;
use crate::models::*;

/// Represents a request for the Peers object.
pub struct GetPeers;

/// The error associated with getting Peers from a keyserver.
#[derive(Debug)]
pub enum GetPeersError<E> {
    /// Error while processing the body.
    Body(HyperError),
    /// A connection error occured.
    Service(E),
    /// Error while decoding the body.
    Decode(DecodeError),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
    /// Peering is disabled on the
    PeeringDisabled,
}

impl<S> Service<(Uri, GetPeers)> for Client<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = Peers;
    type Error = GetPeersError<S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(GetPeersError::Service)
    }

    fn call(&mut self, (uri, _): (Uri, GetPeers)) -> Self::Future {
        let mut client = self.inner_client.clone();
        let http_request = Request::builder().uri(uri).body(Body::empty()).unwrap(); // This is safe

        let fut = async move {
            let response = client
                .call(http_request)
                .await
                .map_err(Self::Error::Service)?;
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
pub struct GetMetadata;

/// The error associated with getting Metadata from a keyserver.
#[derive(Debug)]
pub enum GetMetadataError<E> {
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
    Service(E),
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

impl<S> Service<(Uri, GetMetadata)> for Client<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = PairedMetadata;
    type Error = GetMetadataError<S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(GetMetadataError::Service)
    }

    fn call(&mut self, (uri, _): (Uri, GetMetadata)) -> Self::Future {
        let mut client = self.inner_client.clone();
        let http_request = Request::builder().uri(uri).body(Body::empty()).unwrap(); // This is safe
        let fut = async move {
            // Get response
            let response = client
                .call(http_request)
                .await
                .map_err(Self::Error::Service)?;

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
pub enum PutMetadataError<E> {
    /// A connection error occured.
    Service(E),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
}

pub struct PutMetadata {
    pub token: String,
    pub metadata: AddressMetadata,
}

impl<S> Service<(Uri, PutMetadata)> for Client<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = ();
    type Error = PutMetadataError<S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(PutMetadataError::Service)
    }

    fn call(&mut self, (uri, request): (Uri, PutMetadata)) -> Self::Future {
        let mut client = self.inner_client.clone();

        // Construct body
        let mut body = Vec::with_capacity(request.metadata.encoded_len());
        request.metadata.encode(&mut body).unwrap();

        let http_request = Request::builder()
            .uri(uri)
            .header(AUTHORIZATION, request.token)
            .body(Body::from(body))
            .unwrap(); // This is safe

        let fut = async move {
            // Get response
            let response = client
                .call(http_request)
                .await
                .map_err(Self::Error::Service)?;

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
