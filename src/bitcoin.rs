use async_json_rpc::prelude::{Error as ClientError, *};
use futures::{
    prelude::*,
    task::{Context, Poll},
};
use hyper::{Body, Error as HyperError, Request as HttpRequest, Response as HttpResponse};
use tower_service::Service;

use crate::ResponseFuture;

pub enum BitcoinError {
    Client(ClientError<HyperError>),
    Transaction,
    Json(serde_json::Error),
}

pub struct TransactionAcceptor<C> {
    json_client: HttpClient<C>,
}

impl TransactionAcceptor<HttpsTransport> {
    /// Creates a new TLS client.
    pub fn new_tls(url: String, user: Option<String>, password: Option<String>) -> Self {
        TransactionAcceptor {
            json_client: HttpClient::new_tls(url, user, password),
        }
    }
}

impl TransactionAcceptor<HttpTransport> {
    /// Creates a new client.
    pub fn new(url: String, user: Option<String>, password: Option<String>) -> Self {
        TransactionAcceptor {
            json_client: HttpClient::new(url, user, password),
        }
    }
}

impl<C> Service<&[u8]> for TransactionAcceptor<C>
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
                .unwrap_or(Err(BitcoinError::Transaction)),
            Err(err) => Err(BitcoinError::Client(err)),
        });

        Box::pin(fut)
    }
}
