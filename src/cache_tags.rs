//! The `Cache-Tag` response header.

use std::convert::Infallible;

use axum::response::{IntoResponseParts, ResponseParts};
use http::HeaderValue;
use http::header::HeaderName;

use crate::core::{tags_header_len, valid_tag};

/// The header name.
const CACHE_TAG: HeaderName = HeaderName::from_static("cache-tag");

/// An error in a cache tag list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacheTagError {
    /// The tag is not 1 to 1,024 bytes of printable ASCII, or it has a
    /// space or a comma.
    #[error("invalid cache tag `{0}`")]
    InvalidTag(String),
    /// The header value is longer than 16 KB.
    #[error("the Cache-Tag header value is longer than 16 KB")]
    TooLong,
}

/// Cache tags for a response. Use it as a response part. Cloudflare
/// removes the header before it sends the response to the visitor.
///
/// ```rust
/// use autumn_plugin_cloudflare::CacheTags;
/// use axum::response::IntoResponse;
///
/// let tags = CacheTags::new(["post:1", "posts"]).expect("valid tags");
/// let response = (tags, "hello").into_response();
/// assert_eq!(response.headers()["cache-tag"], "post:1,posts");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheTags {
    value: String,
}

impl CacheTags {
    /// Make a tag list. An empty list adds no header.
    ///
    /// # Errors
    ///
    /// Returns an error for a tag that breaks the Cloudflare rules, or
    /// when the header value is too long.
    pub fn new<I, S>(tags: I) -> Result<Self, CacheTagError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list: Vec<String> = Vec::new();
        for tag in tags {
            let tag = tag.as_ref();
            if !valid_tag(tag.as_bytes()) {
                return Err(CacheTagError::InvalidTag(tag.to_owned()));
            }
            list.push(tag.to_owned());
        }
        let lens: Vec<usize> = list.iter().map(String::len).collect();
        tags_header_len(&lens).ok_or(CacheTagError::TooLong)?;
        Ok(Self {
            value: list.join(","),
        })
    }

    /// The header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl IntoResponseParts for CacheTags {
    type Error = Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        // `new` allows only printable ASCII, so the value is always valid.
        if let Ok(value) = HeaderValue::from_str(&self.value)
            && !self.value.is_empty()
        {
            res.headers_mut().append(CACHE_TAG, value);
        }
        Ok(res)
    }
}
