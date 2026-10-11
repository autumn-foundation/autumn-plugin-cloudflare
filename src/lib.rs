//! Run an [Autumn](https://autumn-web.app) application behind Cloudflare.

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
        ClientIpSource, Decision, MAX_BATCH, MAX_HEADER_LEN, MAX_TAG_LEN, MIN_V4_PREFIX,
        MIN_V6_PREFIX, batch_count, choose_client_ip, constant_time_eq, decide, prefix_match_v4,
        prefix_match_v6, range_is_safe, tags_header_len, valid_tag,
    };
    pub use crate::headers::{header_ip, strip_cloudflare_headers, visitor_scheme};
    pub use crate::purge::cache_from_lookup;
    pub use crate::refresh::{refresh_once, spawn_refresh};
}
