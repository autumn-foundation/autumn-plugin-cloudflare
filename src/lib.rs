//! Run an [Autumn](https://autumn-web.app) application behind Cloudflare.
//!
//! Add the plugin. You do not need other changes:
//!
//! ```rust,no_run
//! use autumn_plugin_cloudflare::CloudflarePlugin;
//! use autumn_web::prelude::*;
//!
//! #[get("/")]
//! async fn index() -> &'static str {
//!     "hello"
//! }
//!
//! #[autumn_web::main]
//! async fn main() {
//!     autumn_web::app()
//!         .plugin(CloudflarePlugin::new())
//!         .routes(routes![index])
//!         .run()
//!         .await;
//! }
//! ```
//!
//! The plugin checks each request:
//!
//! - **Verified (from an edge):** `ClientAddr` and the Autumn rate limits
//!   use the visitor IP from `CF-Connecting-IP`. Handlers can read
//!   [`CloudflareRequest`].
//! - **Direct (from another peer):** the plugin removes all `cf-*`
//!   headers. With [`CloudflarePlugin::lock_origin`], it returns
//!   `403 Forbidden`.
//!
//! [`CacheTags`] adds a `Cache-Tag` header. [`CloudflareCache`] purges
//! the Cloudflare cache. See the
//! [design record](https://github.com/autumn-foundation/autumn-plugin-cloudflare/blob/main/docs/adr/0001-identity-layer.md).

mod cache_tags;
mod core;
mod headers;
mod layer;
mod plugin;
mod purge;
mod ranges;
mod refresh;
mod request;

pub use cache_tags::{CacheTagError, CacheTags};
pub use http::HeaderName;
pub use layer::{CloudflareLayer, CloudflareService};
pub use plugin::{CloudflarePlugin, PeerSource};
pub use purge::{ApiMessage, ApiToken, CloudflareCache, PurgeError, PurgeReport};
pub use ranges::{CloudflareRanges, IpRange, RangeError};
pub use request::CloudflareRequest;

/// Internal items for the tests of this crate.
///
/// This module is not part of the public API. It can change in any release.
#[doc(hidden)]
pub mod __private {
    pub use crate::core::{
        ClientIpSource, Decision, MAX_BATCH, MAX_HEADER_LEN, MAX_RANGES, MAX_TAG_LEN,
        MAX_V4_COVERAGE, MAX_V6_COVERAGE, MIN_V4_PREFIX, MIN_V6_PREFIX, batch_count,
        choose_client_ip, constant_time_eq, coverage_within, decide, is_pseudo_ipv4,
        prefix_match_v4, prefix_match_v6, range_is_safe, tags_header_len, valid_tag,
    };
    pub use crate::headers::{header_ip, strip_cloudflare_headers, visitor_scheme};
    pub use crate::purge::cache_from_lookup;
    pub use crate::refresh::{refresh_once, secure_url, spawn_refresh};
}

/// Compiles the README examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
