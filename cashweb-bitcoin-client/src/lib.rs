#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(elided_lifetimes_in_paths)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! `cashweb-bitcoin-client` is a library providing a [`BitcoinClient`] with
//! basic asynchronous methods for interacting with bitcoind.

use std::fmt;

use hex::FromHexError;
use json_rpc::prelude::*;
pub use json_rpc::{clients::http::{HttpConnector, HttpsConnector}, prelude::Connect};
use serde_json::Value;

/// Basic Bitcoin JSON-RPC client.
#[derive(Clone, Debug)]
pub struct BitcoinClient<C>(HttpClient<C>);

impl BitcoinClient<HttpConnector> {
    /// Construct a new `BitcoinClient` using a HTTP connector.
    pub fn new(endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(HttpClient::new(endpoint, Some(username), Some(password)))
    }
}

impl BitcoinClient<HttpsConnector<HttpConnector>> {
    /// Construct a new `BitcoinClient` using a HTTPS connector.
    pub fn new_tls(endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(HttpClient::new_tls(endpoint, Some(username), Some(password)))
    }
}

impl<C> std::ops::Deref for BitcoinClient<C> {
    type Target = HttpClient<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The error type associated with the Bitcoin RPC.
#[derive(Debug)]
pub enum NodeError {
    /// Error connecting to bitcoind.
    Http(HttpError),
    /// bitcoind responded with an JSON-RPC error.
    Rpc(RpcError),
    /// Failed to deserialize response JSON.
    Json(JsonError),
    /// The response JSON was empty.
    EmptyResponse,
    /// Failed to decode hexidecimal response.
    HexDecode(FromHexError),
}

impl From<FromHexError> for NodeError {
    fn from(err: FromHexError) -> Self {
        Self::HexDecode(err)
    }
}

impl fmt::Display for NodeError {
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

impl<C> BitcoinClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Calls the `getnewaddress` method.
    pub async fn get_new_addr(&self) -> Result<String, NodeError> {
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
    pub async fn send_tx(&self, raw_tx: &[u8]) -> Result<String, NodeError> {
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
    pub async fn get_raw_transaction(&self, tx_id: &[u8]) -> Result<Vec<u8>, NodeError> {
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
