//! Cloudflare cache purge client.

use std::fmt;
use std::time::Duration;

/// A Cloudflare API token.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl ApiToken {
    /// Make a token.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty token or a token with characters
    /// that are not allowed in a header.
    pub fn new(_token: impl Into<String>) -> Result<Self, PurgeError> {
        todo!()
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

/// One error or message from the Cloudflare API.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ApiMessage {
    /// The Cloudflare code.
    #[serde(default)]
    pub code: i64,
    /// The text.
    #[serde(default)]
    pub message: String,
}

/// The result of a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// The number of API requests.
    pub requests: usize,
    /// The number of purged items.
    pub items: usize,
}

/// A purge error.
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// The input is not valid.
    #[error("invalid purge input: {0}")]
    InvalidInput(String),
    /// An environment variable is missing.
    #[error("environment variable `{0}` is not set")]
    MissingEnv(&'static str),
    /// The API rate limit was reached.
    #[error("the Cloudflare API rate limit was reached after {purged} items")]
    RateLimited {
        /// The `Retry-After` time.
        retry_after: Option<Duration>,
        /// The number of items that were purged before the error.
        purged: usize,
    },
    /// The API returned an error.
    #[error("the Cloudflare API returned status {status} after {purged} items")]
    Api {
        /// The HTTP status.
        status: u16,
        /// The API errors.
        errors: Vec<ApiMessage>,
        /// The number of items that were purged before the error.
        purged: usize,
    },
    /// The request failed.
    #[error("the request to the Cloudflare API failed after {purged} items: {message}")]
    Transport {
        /// The error text.
        message: String,
        /// The number of items that were purged before the error.
        purged: usize,
    },
}

impl PurgeError {
    /// The number of items that were purged before the error.
    #[must_use]
    pub const fn purged(&self) -> usize {
        todo!()
    }
}

/// A client for the Cloudflare cache purge API.
#[derive(Clone, Debug)]
pub struct CloudflareCache {
    _private: (),
}

impl CloudflareCache {
    /// Make a client for one zone.
    ///
    /// # Errors
    ///
    /// Returns an error for a zone ID that is not ASCII letters and digits.
    pub fn new(_zone_id: impl Into<String>, _token: ApiToken) -> Result<Self, PurgeError> {
        todo!()
    }

    /// Make a client from `CLOUDFLARE_ZONE_ID` and `CLOUDFLARE_API_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns an error when a variable is missing or not valid.
    pub fn from_env() -> Result<Self, PurgeError> {
        todo!()
    }

    /// Set the API base URL.
    #[must_use]
    pub fn api_base(self, _url: impl Into<String>) -> Self {
        todo!()
    }

    /// Set the batch size (1 to 100).
    #[must_use]
    pub fn batch_size(self, _size: usize) -> Self {
        todo!()
    }

    /// Purge URLs.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_urls<I, S>(&self, _urls: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// Purge cache tags.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_tags<I, S>(&self, _tags: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// Purge URL prefixes.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_prefixes<I, S>(&self, _prefixes: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// Purge hosts.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_hosts<I, S>(&self, _hosts: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// Purge all files in the zone.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_everything(&self) -> Result<PurgeReport, PurgeError> {
        todo!()
    }
}

/// Make a client from a variable lookup. `from_env` uses `std::env::var`.
///
/// # Errors
///
/// Returns an error when a variable is missing or not valid.
pub fn cache_from_lookup<F>(_lookup: F) -> Result<CloudflareCache, PurgeError>
where
    F: Fn(&str) -> Option<String>,
{
    todo!()
}

impl axum::extract::FromRequestParts<autumn_web::AppState> for CloudflareCache {
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(
        _parts: &mut http::request::Parts,
        _state: &autumn_web::AppState,
    ) -> Result<Self, Self::Rejection> {
        todo!()
    }
}
