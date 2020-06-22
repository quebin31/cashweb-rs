use std::pin::Pin;

use futures_core::{
    task::{Context, Poll},
    Future,
};
use hyper::{body::aggregate, Client as HyperClient, Error as HyperError, StatusCode};
pub use hyper::{
    client::{connect::Connect, HttpConnector},
    Uri,
};
use prost::{DecodeError, Message as _};
use tower_service::Service;

mod models {
    include!(concat!(env!("OUT_DIR"), "/keyserver.rs"));
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

pub enum GetPeerError {
    /// A connection error occured.
    Connection(HyperError),
    Body(HyperError),
    PeeringDisabled,
    UnexpectedStatusCode(u16),
    Decode(DecodeError),
}

pub struct GetPeer(Uri);

impl<C> Service<GetPeer> for Client<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Response = Peers;
    type Error = GetPeerError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, GetPeer(uri): GetPeer) -> Self::Future {
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
