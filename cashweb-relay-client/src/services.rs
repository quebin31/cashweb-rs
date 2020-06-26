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
use tower_service::Service;

use super::{PairedProfile, RelayClient};
use ::auth_wrapper::*;
use relay::Profile;

/// Represents a request for the Profile object.
#[derive(Clone, Debug)]
pub struct GetProfile;

/// The error associated with getting a Profile from a relay server.
#[derive(Debug)]
pub enum GetProfileError<E> {
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
}

impl<S> Service<(Uri, GetProfile)> for RelayClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = PairedProfile;
    type Error = GetProfileError<S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(GetProfileError::Service)
    }

    fn call(&mut self, (uri, _): (Uri, GetProfile)) -> Self::Future {
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
            let profile = Profile::decode(&mut parsed_auth_wrapper.payload.as_slice())
                .map_err(Self::Error::MetadataDecode)?;

            Ok(PairedProfile {
                public_key: parsed_auth_wrapper.public_key,
                profile,
            })
        };
        Box::pin(fut)
    }
}

/// Error associated with putting a Profile to the relay server.
#[derive(Clone, Debug)]
pub enum PutProfileError<E> {
    /// A connection error occured.
    Service(E),
    /// Unexpected status code.
    UnexpectedStatusCode(u16),
}

#[derive(Clone, Debug)]
pub struct PutProfile {
    pub token: String,
    pub profile: Profile,
}

impl<S> Service<(Uri, PutProfile)> for RelayClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S: Send + Clone + 'static,
    <S as Service<Request<Body>>>::Future: Send,
{
    type Response = ();
    type Error = PutProfileError<S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_client
            .poll_ready(context)
            .map_err(PutProfileError::Service)
    }

    fn call(&mut self, (uri, request): (Uri, PutProfile)) -> Self::Future {
        let mut client = self.inner_client.clone();

        // Construct body
        let mut body = Vec::with_capacity(request.profile.encoded_len());
        request.profile.encode(&mut body).unwrap();

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
