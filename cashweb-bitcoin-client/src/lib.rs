#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-bitcoin-client` is a library providing a [`BitcoinClient`] with
//! basic asynchronous methods for interacting with bitcoind.

use std::fmt;

use hex::FromHexError;
use hyper::{
    client::HttpConnector, Body, Client as HyperClient, Error as HyperError,
    Request as HttpRequest, Response as HttpResponse,
};
use hyper_tls::HttpsConnector;
use json_rpc::{
    clients::{
        http::{Client as JsonClient, ConnectionError},
        Error,
    },
    prelude::{JsonError, RequestFactory, RpcError},
};
use serde_json::Value;
use tower_service::Service;

/// Standard HTTP client.
pub type HttpClient = HyperClient<HttpConnector>;

/// Standard HTTPs client.
pub type HttpsClient = HyperClient<HttpsConnector<HttpConnector>>;

/// Standard HTTP error.
pub type HttpError = NodeError<HyperError>;

/// Basic Bitcoin JSON-RPC client.
#[derive(Clone, Debug)]
pub struct BitcoinClient<S>(JsonClient<S>);

impl<S> BitcoinClient<S> {
    /// Create a new [`BitcoinClient`] using a user-defined client service.
    pub fn from_service(service: S, endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(JsonClient::from_service(
            service,
            endpoint,
            Some(username),
            Some(password),
        ))
    }
}

impl BitcoinClient<HyperClient<HttpConnector>> {
    /// Create a new HTTP [`BitcoinClient`].
    pub fn new(endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(JsonClient::new(endpoint, Some(username), Some(password)))
    }
}

impl BitcoinClient<HyperClient<HttpsConnector<HttpConnector>>> {
    /// Create a new HTTPS [`BitcoinClient`].
    pub fn new_tls(endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(JsonClient::new_tls(
            endpoint,
            Some(username),
            Some(password),
        ))
    }
}

impl<C> std::ops::Deref for BitcoinClient<C> {
    type Target = JsonClient<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error associated with the Bitcoin RPC.
#[derive(Debug)]
pub enum NodeError<E> {
    /// Error connecting to bitcoind.
    Http(Error<ConnectionError<E>>),
    /// bitcoind responded with an JSON-RPC error.
    Rpc(RpcError),
    /// Failed to deserialize response JSON.
    Json(JsonError),
    /// The response JSON was empty.
    EmptyResponse,
    /// Failed to decode hexidecimal response.
    HexDecode(FromHexError),
}

impl<E> From<FromHexError> for NodeError<E> {
    fn from(err: FromHexError) -> Self {
        Self::HexDecode(err)
    }
}

impl<E: fmt::Display> fmt::Display for NodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(err) => err.fmt(f),
            Self::Json(err) => err.fmt(f),
            Self::Rpc(err) => f.write_str(&format!("{:#?}", err)),
            Self::EmptyResponse => f.write_str("empty response"),
            Self::HexDecode(err) => err.fmt(f),
        }
    }
}

impl<S> BitcoinClient<S>
where
    S: Service<HttpRequest<Body>, Response = HttpResponse<Body>> + Clone,
    S::Error: 'static,
    S::Future: Send + 'static,
{
    /// Calls the `getnewaddress` method.
    pub async fn get_new_addr(&self) -> Result<String, NodeError<S::Error>> {
        let request = self
            .build_request()
            .method("getnewaddress")
            .finish()
            .unwrap();
        let response = self.send(request).await.map_err(NodeError::Http)?;
        if response.is_error() {
            return Err(NodeError::Rpc(response.error().unwrap()));
        }
        response
            .into_result()
            .ok_or(NodeError::EmptyResponse)?
            .map_err(NodeError::Json)
    }

    /// Calls the `sendrawtransaction` method.
    pub async fn send_tx(&self, raw_tx: &[u8]) -> Result<String, NodeError<S::Error>> {
        let request = self
            .build_request()
            .method("sendrawtransaction")
            .params(vec![Value::String(hex::encode(raw_tx))])
            .finish()
            .unwrap();
        let response = self.send(request).await.map_err(NodeError::Http)?;
        if response.is_error() {
            let err = response.error().unwrap();
            return Err(NodeError::Rpc(err));
        }
        response
            .into_result()
            .ok_or(NodeError::EmptyResponse)?
            .map_err(NodeError::Json)
    }

    /// Calls the `getrawtransaction` method.
    pub async fn get_raw_transaction(&self, tx_id: &[u8]) -> Result<Vec<u8>, NodeError<S::Error>> {
        let request = self
            .build_request()
            .method("getrawtransaction")
            .params(vec![Value::String(hex::encode(tx_id))])
            .finish()
            .unwrap();
        let response = self.send(request).await.map_err(NodeError::Http)?;
        if response.is_error() {
            return Err(NodeError::Rpc(response.error().unwrap()));
        }
        let tx_hex: String = response
            .into_result()
            .ok_or(NodeError::EmptyResponse)?
            .map_err(NodeError::Json)?;
        hex::decode(tx_hex).map_err(Into::into)
    }
}
