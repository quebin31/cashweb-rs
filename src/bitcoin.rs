use async_json_rpc::prelude::{Error as ClientError, *};
use futures::{
    prelude::*,
    task::{Context, Poll},
};
use hyper::{Body, Error as HyperError, Request as HttpRequest, Response as HttpResponse};
use tower_service::Service;

use crate::ResponseFuture;

/// The error type for Bitcoin RPC.
pub enum BitcoinError {
    /// A connection error occured.
    Client(ClientError<HyperError>),
    /// Bitcoind produced an JSONRPC error.
    Rpc(RpcError),
    /// An error occured while trying to deserialize the response JSON.
    Json(JsonError),
    /// Bitcoind produced an empty JSON.
    EmptyJson,
}

/// A `Service` that sends raw transactions to Bitcoind.
pub struct TransactionBroadcaster<C> {
    json_client: HttpClient<C>,
}

impl TransactionBroadcaster<HttpsTransport> {
    /// Creates a new TLS client.
    pub fn new_tls(url: String, user: Option<String>, password: Option<String>) -> Self {
        TransactionBroadcaster {
            json_client: HttpClient::new_tls(url, user, password),
        }
    }
}

impl TransactionBroadcaster<HttpTransport> {
    /// Creates a new client.
    pub fn new(url: String, user: Option<String>, password: Option<String>) -> Self {
        TransactionBroadcaster {
            json_client: HttpClient::new(url, user, password),
        }
    }
}

impl<C> Service<&[u8]> for TransactionBroadcaster<C>
where
    C: Service<HttpRequest<Body>, Response = HttpResponse<Body>, Error = HyperError>,
    C::Future: 'static,
{
    type Response = String;
    type Error = BitcoinError;
    type Future = ResponseFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.json_client
            .poll_ready(ctx)
            .map_err(BitcoinError::Client)
    }

    fn call(&mut self, raw_tx: &[u8]) -> Self::Future {
        let req = self
            .json_client
            .build_request()
            .method("sendrawtransaction")
            .params(hex::encode(raw_tx))
            .finish()
            .unwrap();

        let fut = self.json_client.call(req).map(|res| match res {
            Ok(response) => response
                .result()
                .map(|res| res.map_err(BitcoinError::Json))
                .unwrap_or(Err(response
                    .error()
                    .map(BitcoinError::Rpc)
                    .unwrap_or(BitcoinError::EmptyJson))),
            Err(err) => Err(BitcoinError::Client(err)),
        });

        Box::pin(fut)
    }
}
