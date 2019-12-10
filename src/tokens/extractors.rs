use http::{header::HeaderValue, header::AUTHORIZATION, Request};

/// Extract token from `Authorization` header.
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

/// Extract token from query string.
fn extract_pop_query(value: &str) -> Option<&str> {
    if &value[..5] == "code=" {
        Some(&value[5..])
    } else {
        None
    }
}

/// Represents the method of extracting a token from a HTTP request using either of two extractors.
#[allow(dead_code)]
pub struct EitherExtractor<A, B> {
    extractor_a: A,
    extractor_b: B,
}

impl<A, B> EitherExtractor<A, B> {
    pub fn either(extractor_a: A, extractor_b: B) -> Self {
        EitherExtractor {
            extractor_a,
            extractor_b,
        }
    }
}

/// Represents a method of extracting a token from a HTTP Request.
pub trait TokenExtractor {
    /// Extract a token from a request.
    fn extract<B>(request: &Request<B>) -> Option<&str>;
}

impl<X, Y> TokenExtractor for EitherExtractor<X, Y>
where
    X: TokenExtractor,
    Y: TokenExtractor,
{
    #[allow(clippy::or_fun_call)]
    fn extract<B>(request: &Request<B>) -> Option<&str> {
        X::extract(request).or(Y::extract(request))
    }
}

/// The method of extracting the token from a requests `Authorization` header.
pub struct AuthTokenExtractor;

impl TokenExtractor for AuthTokenExtractor {
    fn extract<B>(request: &Request<B>) -> Option<&str> {
        request
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .find_map(extract_pop_header)
    }
}

/// The method of extracting the token from a requests query string.
pub struct QueryStringTokenExtractor;

impl TokenExtractor for QueryStringTokenExtractor {
    fn extract<B>(request: &Request<B>) -> Option<&str> {
        if let Some(query_str) = request.uri().query() {
            query_str.split('&').find_map(extract_pop_query)
        } else {
            None
        }
    }
}
