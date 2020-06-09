use std::fmt;

use hex::FromHexError;
pub use json_rpc::clients::http::HttpConnector;
use json_rpc::prelude::*;
use serde_json::Value;

/// Basic bitcoin JSON-RPC client.
#[derive(Clone, Debug)]
pub struct BitcoinClient<C>(HttpClient<C>);

impl BitcoinClient<HttpConnector> {
    /// Construct a new `BitcoinClient` using a HTTP connector.
    pub fn new(endpoint: String, username: String, password: String) -> Self {
        BitcoinClient(HttpClient::new(endpoint, Some(username), Some(password)))
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
    Http(HttpError),
    Rpc(RpcError),
    Json(JsonError),
    EmptyResponse,
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
