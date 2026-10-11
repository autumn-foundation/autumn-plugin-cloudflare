//! Cloudflare cache purge client.

use std::fmt;
use std::future::{Future, ready};
use std::time::Duration;

use autumn_web::AppState;
use autumn_web::http::Client;
use axum::extract::FromRequestParts;
use http::StatusCode;
use http::request::Parts;

use crate::core::{MAX_BATCH, batch_count, valid_tag};

/// A Cloudflare API token with the "Cache Purge" permission. `Debug`
/// output hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl ApiToken {
    /// Make a token.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty token, or a token with characters
    /// other than printable ASCII.
    pub fn new(token: impl Into<String>) -> Result<Self, PurgeError> {
        let token = token.into();
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(PurgeError::InvalidInput(
                "the API token must be printable ASCII with no spaces".to_owned(),
            ));
        }
        Ok(Self(token))
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken(***)")
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
        match self {
            Self::InvalidInput(_) | Self::MissingEnv(_) => 0,
            Self::RateLimited { purged, .. }
            | Self::Api { purged, .. }
            | Self::Transport { purged, .. } => *purged,
        }
    }
}

/// The default API base URL.
const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The time limit for one purge request.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A client for the Cloudflare cache purge API.
///
/// The client sends batches of 100 items or less. It does not retry. On
/// an error, it stops and tells how many items it purged.
///
/// ```rust,no_run
/// # async fn run() -> Result<(), autumn_plugin_cloudflare::PurgeError> {
/// use autumn_plugin_cloudflare::{ApiToken, CloudflareCache};
///
/// let cache = CloudflareCache::new("023e105f4ecef8ad9ca31a8372d0c353", ApiToken::new("token")?)?;
/// cache.purge_tags(["post:1"]).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CloudflareCache {
    client: Client,
    api_base: String,
    zone_id: String,
    token: ApiToken,
    batch_size: usize,
}

impl fmt::Debug for CloudflareCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareCache")
            .field("api_base", &self.api_base)
            .field("zone_id", &self.zone_id)
            .field("token", &self.token)
            .field("batch_size", &self.batch_size)
            .finish_non_exhaustive()
    }
}

#[derive(serde::Deserialize)]
struct ApiResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
}

impl CloudflareCache {
    /// Make a client for one zone.
    ///
    /// # Errors
    ///
    /// Returns an error for a zone ID that is not 1 to 64 ASCII letters and
    /// digits.
    pub fn new(zone_id: impl Into<String>, token: ApiToken) -> Result<Self, PurgeError> {
        let zone_id = zone_id.into();
        if zone_id.is_empty()
            || zone_id.len() > 64
            || !zone_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(PurgeError::InvalidInput(
                "the zone ID must be 1 to 64 ASCII letters and digits".to_owned(),
            ));
        }
        Ok(Self {
            client: Client::with_timeout(TIMEOUT),
            api_base: DEFAULT_API_BASE.to_owned(),
            zone_id,
            token,
            batch_size: MAX_BATCH,
        })
    }

    /// Make a client from `CLOUDFLARE_ZONE_ID` and `CLOUDFLARE_API_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns an error when a variable is missing or not valid.
    pub fn from_env() -> Result<Self, PurgeError> {
        cache_from_lookup(|name| std::env::var(name).ok())
    }

    /// Set the API base URL. The default is
    /// `https://api.cloudflare.com/client/v4`.
    #[must_use]
    pub fn api_base(mut self, url: impl Into<String>) -> Self {
        url.into()
            .trim_end_matches('/')
            .clone_into(&mut self.api_base);
        self
    }

    /// Set the number of items in one request. The client uses 1 to 100.
    /// The default is 100.
    #[must_use]
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.clamp(1, MAX_BATCH);
        self
    }

    /// Purge URLs. Each URL starts with `http://` or `https://`.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_urls<I, S>(&self, urls: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.purge_items("files", collect(urls, valid_url, "URL")?)
            .await
    }

    /// Purge cache tags. See [`CacheTags`](crate::CacheTags).
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_tags<I, S>(&self, tags: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.purge_items("tags", collect(tags, |t| valid_tag(t.as_bytes()), "tag")?)
            .await
    }

    /// Purge URL prefixes, for example `www.example.com/blog/`. A prefix
    /// has no scheme.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_prefixes<I, S>(&self, prefixes: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.purge_items("prefixes", collect(prefixes, valid_prefix, "prefix")?)
            .await
    }

    /// Purge hosts, for example `img.example.com`.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_hosts<I, S>(&self, hosts: I) -> Result<PurgeReport, PurgeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.purge_items("hosts", collect(hosts, valid_host, "host")?)
            .await
    }

    /// Purge all files in the zone.
    ///
    /// # Errors
    ///
    /// See [`PurgeError`].
    pub async fn purge_everything(&self) -> Result<PurgeReport, PurgeError> {
        self.send(&serde_json::json!({ "purge_everything": true }), 0)
            .await?;
        Ok(PurgeReport {
            requests: 1,
            items: 0,
        })
    }

    async fn purge_items(
        &self,
        key: &'static str,
        items: Vec<String>,
    ) -> Result<PurgeReport, PurgeError> {
        let mut report = PurgeReport {
            requests: 0,
            items: 0,
        };
        for batch in items.chunks(self.batch_size) {
            let body = serde_json::json!({ key: batch });
            self.send(&body, report.items).await?;
            report.requests += 1;
            report.items += batch.len();
        }
        debug_assert_eq!(report.requests, batch_count(items.len(), self.batch_size));
        Ok(report)
    }

    async fn send(&self, body: &serde_json::Value, purged: usize) -> Result<(), PurgeError> {
        let url = format!("{}/zones/{}/purge_cache", self.api_base, self.zone_id);
        let response = self
            .client
            .post(url)
            .header("authorization", format!("Bearer {}", self.token.0))
            .json(body)
            .no_retry()
            .no_redirect()
            .send()
            .await
            .map_err(|e| PurgeError::Transport {
                message: e.to_string(),
                purged,
            })?;
        let status = response.status().as_u16();
        if status == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(PurgeError::RateLimited {
                retry_after,
                purged,
            });
        }
        let success = response.is_success();
        match response.json::<ApiResponse>() {
            Ok(api) if success && api.success => Ok(()),
            Ok(api) => Err(PurgeError::Api {
                status,
                errors: api.errors,
                purged,
            }),
            Err(_) => Err(PurgeError::Api {
                status,
                errors: Vec::new(),
                purged,
            }),
        }
    }
}

/// Check and collect the items. The first bad item stops the purge.
fn collect<I, S>(items: I, valid: fn(&str) -> bool, kind: &str) -> Result<Vec<String>, PurgeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    items
        .into_iter()
        .map(|item| {
            let item = item.as_ref();
            if valid(item) {
                Ok(item.to_owned())
            } else {
                Err(PurgeError::InvalidInput(format!("invalid {kind} `{item}`")))
            }
        })
        .collect()
}

fn printable(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

fn valid_url(url: &str) -> bool {
    let lower = url
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let rest = if lower.starts_with("https://") {
        url.get(8..)
    } else if lower.starts_with("http://") {
        url.get(7..)
    } else {
        None
    };
    printable(url) && rest.is_some_and(|r| !r.is_empty() && !r.starts_with('/'))
}

fn valid_prefix(prefix: &str) -> bool {
    printable(prefix) && !prefix.contains("://")
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl FromRequestParts<AppState> for CloudflareCache {
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        _parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(
            state
                .extension::<Self>()
                .map(|cache| (*cache).clone())
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the Cloudflare cache client is not configured",
                )),
        )
    }
}

/// Make a client from a variable lookup. `from_env` uses `std::env::var`.
///
/// # Errors
///
/// Returns an error when a variable is missing or not valid.
pub fn cache_from_lookup<F>(lookup: F) -> Result<CloudflareCache, PurgeError>
where
    F: Fn(&str) -> Option<String>,
{
    let zone = lookup("CLOUDFLARE_ZONE_ID").ok_or(PurgeError::MissingEnv("CLOUDFLARE_ZONE_ID"))?;
    let token =
        lookup("CLOUDFLARE_API_TOKEN").ok_or(PurgeError::MissingEnv("CLOUDFLARE_API_TOKEN"))?;
    CloudflareCache::new(zone, ApiToken::new(token)?)
}
