//! This module contains lower-level primitives for working with the [`KeyserverClient`].

use std::{fmt, pin::Pin};

use futures_core::{
    task::{Context, Poll},
    Future,
};
use futures_util::future::{join, join_all};
use hyper::{
    body::aggregate, http::header::AUTHORIZATION, http::Method, Body, Error as HyperError, Request,
    Response, StatusCode,
};
pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use prost::{DecodeError, Message as _};
use tower_service::Service;

use super::{KeyserverClient, MetadataPackage};
use crate::models::*;

type FutResponse<Response, Error> =
    Pin<Box<dyn Future<Output = Result<Response, Error>> + 'static + Send>>;

/// Represents a request for the Peers object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPeers;

/// Error associated with getting Peers from a keyserver.
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

impl<S> Service<(Uri, GetPeers)> for KeyserverClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = Peers;
    type Error = GetPeersError<S::Error>;
    type Future = FutResponse<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(GetPeersError::Service)
    }

    fn call(&mut self, (uri, _): (Uri, GetPeers)) -> Self::Future {
        let mut client = self.inner_client.clone();
        let http_request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap(); // This is safe

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetMetadata;

/// Error associated with getting Metadata from a keyserver.
#[derive(Debug)]
pub enum GetMetadataError<E> {
    /// Error while decoding the [`AddressMetadata`]
    MetadataDecode(DecodeError),
    /// Error while decoding the [`AuthWrapper`].
    AuthWrapperDecode(DecodeError),
    /// Error while parsing the [`AuthWrapper`].
    AuthWrapperParse(ParseError),
    /// Error while parsing the [`AuthWrapper`].
    AuthWrapperVerify(VerifyError),
    /// Error while processing the body.
    Body(HyperError),
    /// A connection error occured.
    Service(E),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
    /// Peering is disabled on the keyserver.
    PeeringDisabled,
    /// POP token missing from headers.
    MissingToken,
}

impl<S> Service<(Uri, GetMetadata)> for KeyserverClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = MetadataPackage;
    type Error = GetMetadataError<S::Error>;
    type Future = FutResponse<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(GetMetadataError::Service)
    }

    fn call(&mut self, (uri, _): (Uri, GetMetadata)) -> Self::Future {
        let mut client = self.inner_client.clone();
        let http_request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
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
                StatusCode::NOT_IMPLEMENTED => return Err(Self::Error::PeeringDisabled),
                code => return Err(Self::Error::UnexpectedStatusCode(code.as_u16())),
            }

            let token = response
                .headers()
                .into_iter()
                .find(|(name, value)| {
                    *name == AUTHORIZATION && value.as_bytes()[..4] == b"POP "[..]
                })
                .ok_or(Self::Error::MissingToken)?
                .0
                .to_string();

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

            Ok(MetadataPackage {
                token,
                public_key: parsed_auth_wrapper.public_key,
                metadata,
            })
        };
        Box::pin(fut)
    }
}

/// Error associated with putting [`AddressMetadata`] to the keyserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutMetadataError<E> {
    /// A connection error occured.
    Service(E),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
}

/// Request for putting [`AddressMetadata`] to the keyserver.
#[derive(Debug, Clone, PartialEq)]
pub struct PutMetadata {
    /// POP authorization token.
    pub token: String,
    /// The [`AddressMetadata`] to be put to the keyserver.
    pub metadata: AddressMetadata,
}

impl<S> Service<(Uri, PutMetadata)> for KeyserverClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = ();
    type Error = PutMetadataError<S::Error>;
    type Future = FutResponse<Self::Response, Self::Error>;

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
            .method(Method::PUT)
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

/// Request for performing multiple requests to a range of keyservers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRequest<T> {
    /// The [`Uri`]s of the targetted keyservers.
    pub uris: Vec<Uri>,
    /// The request to be broadcast.
    pub request: T,
}

/// Error associated with sending sample requests.
#[derive(Debug)]
pub enum SampleError<E> {
    /// Error while polling service.
    Poll(E),
    /// Sample totally failed. Contains errors paired with the [`Uri`] of the keyserver they originated at.
    Sample(Vec<(Uri, E)>),
}

impl<S, T> Service<SampleRequest<T>> for KeyserverClient<S>
where
    T: Send + 'static + Clone + Sized,
    S: Send + Clone + 'static,
    Self: Service<(Uri, T)>,
    <Self as Service<(Uri, T)>>::Response: Send + fmt::Debug,
    <Self as Service<(Uri, T)>>::Error: fmt::Debug + Send,
    <Self as Service<(Uri, T)>>::Future: Send,
{
    type Response = Vec<(
        Uri,
        Result<<Self as Service<(Uri, T)>>::Response, <Self as Service<(Uri, T)>>::Error>,
    )>;
    type Error = SampleError<<Self as Service<(Uri, T)>>::Error>;
    type Future = FutResponse<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(context).map_err(SampleError::Poll)
    }

    fn call(&mut self, SampleRequest { uris, request }: SampleRequest<T>) -> Self::Future {
        let mut inner_client = self.clone();

        let fut = async move {
            // Collect futures
            let response_futs = uris.into_iter().map(move |uri| {
                let response_fut = inner_client.call((uri.clone(), request.clone()));
                let uri_fut = async move { uri };
                join(uri_fut, response_fut)
            });
            let responses: Vec<(Uri, Result<_, _>)> = join_all(response_futs).await;

            // If no successes then return all errors
            if responses.iter().any(|(_, res)| res.is_ok()) {
                let errors = responses
                    .into_iter()
                    .map(|(uri, result)| (uri, result.err().unwrap()))
                    .collect();
                return Err(SampleError::Sample(errors));
            }

            Ok(responses)
        };
        Box::pin(fut)
    }
}
