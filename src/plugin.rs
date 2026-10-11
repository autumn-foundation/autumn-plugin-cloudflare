//! `CloudflarePlugin`: options and wiring.

use std::time::Duration;

use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use http::HeaderName;

use crate::layer::CloudflareLayer;
use crate::purge::CloudflareCache;
use crate::ranges::{CloudflareRanges, IpRange};

/// The IP that the plugin checks against the Cloudflare ranges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerSource {
    /// The TCP peer. Use this when Cloudflare connects to Autumn directly.
    #[default]
    Socket,
    /// The client IP that Autumn resolved from `[security.trusted_proxies]`.
    /// Use this when a load balancer is between Cloudflare and Autumn.
    Resolved,
}

/// The Cloudflare plugin.
#[derive(Debug, Default)]
pub struct CloudflarePlugin {
    _private: (),
}

impl CloudflarePlugin {
    /// Make a plugin with the default options.
    #[must_use]
    pub fn new() -> Self {
        todo!()
    }

    /// Use these ranges instead of the built-in list.
    #[must_use]
    pub fn ranges(self, _ranges: CloudflareRanges) -> Self {
        todo!()
    }

    /// Set the peer source.
    #[must_use]
    pub fn peer_source(self, _source: PeerSource) -> Self {
        todo!()
    }

    /// Return `403` to peers that are not Cloudflare and not allowed.
    #[must_use]
    pub fn lock_origin(self, _lock: bool) -> Self {
        todo!()
    }

    /// Let peers in this range pass the origin lock.
    #[must_use]
    pub fn allow(self, _range: IpRange) -> Self {
        todo!()
    }

    /// Require a shared-secret header from Cloudflare.
    #[must_use]
    pub fn require_header(self, _name: HeaderName, _value: impl Into<String>) -> Self {
        todo!()
    }

    /// Get the range list from the Cloudflare API at startup and at each
    /// interval.
    #[must_use]
    pub fn refresh_ranges(self, _interval: Duration) -> Self {
        todo!()
    }

    /// Set the URL of the range API.
    #[must_use]
    pub fn ranges_url(self, _url: impl Into<String>) -> Self {
        todo!()
    }

    /// Put a purge client in the app state.
    #[must_use]
    pub fn cache(self, _cache: CloudflareCache) -> Self {
        todo!()
    }

    /// The Tower layer for these options.
    #[must_use]
    pub fn layer(&self) -> CloudflareLayer {
        todo!()
    }
}

impl Plugin for CloudflarePlugin {
    fn build(self, _app: AppBuilder) -> AppBuilder {
        todo!()
    }
}
