use http::{header::HeaderValue, header::AUTHORIZATION, Request};

/// Extract POP token string from http header value
pub fn extract_pop_header(value: &HeaderValue) -> Option<&str> {
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
pub fn extract_pop_query(value: &str) -> Option<&str> {
    if &value[..5] == "code=" {
        Some(&value[5..])
    } else {
        None
    }
}

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

pub trait TokenExtractor {
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
