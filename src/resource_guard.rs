use std::pin::Pin;

use futures::{
    future,
    prelude::*,
    task::{Context, Poll},
};
use http::{header::HeaderValue, header::AUTHORIZATION, Request};
use tower_service::Service;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<V, S> {
    NoAuthData,
    TokenValidate(V),
    Service(S),
}

/// Extract POP token string from http header value
fn extract_pop_header(value: &HeaderValue) -> Option<&str> {
    if let Ok(header_str) = value.to_str() {
        if &header_str[..4] == "POP " {
            Some(&header_str[4..])
        } else {
            None
        }
    } else {
        None
    }
}

/// Extract POP token string from query string item
fn extract_pop_query(value: &str) -> Option<&str> {
    if &value[..5] == "code=" {
        Some(&value[5..])
    } else {
        None
    }
}

#[derive(Clone)]
pub struct ResourceGuard<S, V> {
    service: S,
    validation_service: V,
}

impl<S, V, B> Service<Request<B>> for ResourceGuard<S, V>
where
    B: 'static,
    S: Service<Request<B>> + 'static,
    S::Future: 'static,
    S::Response: 'static,
    S::Error: 'static,
    V: Service<(Request<B>, String), Response = Request<B>> + 'static,
    V::Future: 'static,
    V::Response: 'static,
    V::Error: 'static,
{
    type Response = S::Response;
    type Error = GuardError<V::Error, S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Poll::Ready(ready) = self.service.poll_ready(cx) {
            if let Err(err) = ready {
                Poll::Ready(Err(GuardError::Service(err)))
            } else {
                Poll::Ready(Ok(()))
            }
        } else {
            Poll::Pending
        }
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let token_str = if let Some(token_str) = request
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .find_map(extract_pop_header)
        {
            // Found token string in authorization header
            token_str
        } else if let Some(query_str) = request.uri().query() {
            if let Some(token_str) = query_str.split('&').find_map(extract_pop_query) {
                // Found token in query string
                token_str
            } else {
                return Box::pin(future::err(GuardError::NoAuthData));
            }
        } else {
            return Box::pin(future::err(GuardError::NoAuthData));
        };

        let fut = self
            .validation_service
            .call((request, token_str.to_string()))
            .map_err(GuardError::TokenValidate)
            .and_then(|request| self.service.call(request).map_err(GuardError::Service));

        Box::pin(fut)
    }
}

// #[async_trait]
// pub trait ResourceGuardExt: ResourceGuard
// where
//     Self::Body: Sync,
//     Self::Context: Sync + Send,
// {
//     /// Proof-of-Payment guard surounding protected resource
//     #[inline]
//     async fn guard<'a>(
//         &mut self,
//         req: &'a Request<Self::Body>,
//         context: &mut Self::Context,
//     ) -> Result<(Self::ValidationResult, &'a str), GuardError<Self::ValidationError>> {
//         // Search for POP token
//         let token_str = if let Some(token_str) = req
//             .headers()
//             .get_all(AUTHORIZATION)
//             .iter()
//             .find_map(extract_pop_header)
//         {
//             // Found token string in authorization header
//             token_str
//         } else if let Some(query_str) = req.uri().query() {
//             if let Some(token_str) = query_str.split('&').find_map(extract_pop_query) {
//                 // Found token in query string
//                 token_str
//             } else {
//                 return Err(GuardError::NoAuthData);
//             }
//         } else {
//             return Err(GuardError::NoAuthData);
//         };
//         let result = self.validate_token(token_str, context).await?;
//         Ok((result, token_str))
//     }
// }
