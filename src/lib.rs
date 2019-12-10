pub mod models {
    include!(concat!(env!("OUT_DIR"), "/models.rs"));
}

pub mod bitcoin;
pub mod payment_processor;
pub mod resource_guard;
pub mod tokens;

use futures::Future;
use std::pin::Pin;

#[doc(hidden)]
pub type ResponseFuture<Response, Error> = Pin<Box<dyn Future<Output = Result<Response, Error>>>>;
