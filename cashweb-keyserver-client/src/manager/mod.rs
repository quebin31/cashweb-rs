use std::sync::Arc;

use hyper::Uri;

#[derive(Debug)]
pub struct Manager<C> {
    inner_client: C,
    uris: Arc<Vec<Uri>>,
}

impl<C> Manager<C> {
    /// Create a new manager from URIs and a client.
    pub fn from_client(inner_client: C, uris: Arc<Vec<Uri>>) -> Self {
        Self { inner_client, uris }
    }
}
