//! The `Cache-Tag` response header.

/// An error in a cache tag list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacheTagError {
    /// The tag is not valid.
    #[error("invalid cache tag `{0}`")]
    InvalidTag(String),
    /// The header value is too long.
    #[error("the Cache-Tag header value is too long")]
    TooLong,
}

/// Cache tags for a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheTags {
    value: String,
}

impl CacheTags {
    /// Make a tag list.
    ///
    /// # Errors
    ///
    /// Returns an error for a tag that breaks the Cloudflare rules.
    pub fn new<I, S>(_tags: I) -> Result<Self, CacheTagError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// The header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl axum::response::IntoResponseParts for CacheTags {
    type Error = std::convert::Infallible;

    fn into_response_parts(
        self,
        _res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        todo!()
    }
}
