//! `CloudflarePlugin`: options and wiring.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use autumn_web::plugin_contract::PluginContract;
use http::HeaderName;

use crate::layer::{CloudflareLayer, Secret, Settings};
use crate::purge::CloudflareCache;
use crate::ranges::{CloudflareRanges, IpRange};
use crate::refresh::spawn_refresh;

/// The default range API.
const DEFAULT_RANGES_URL: &str = "https://api.cloudflare.com/client/v4/ips";

/// The shortest refresh interval.
const MIN_REFRESH: Duration = Duration::from_secs(60);

/// The IP that the plugin checks against the Cloudflare ranges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerSource {
    /// The TCP peer. Use this when Cloudflare connects to Autumn directly.
    #[default]
    Socket,
    /// The client IP that Autumn resolved from `[security.trusted_proxies]`.
    /// Use this when a load balancer is between Cloudflare and Autumn.
    /// Configure the load balancer as a trusted proxy.
    Resolved,
}

/// Run an Autumn app behind Cloudflare.
///
/// The plugin adds one layer. For a request from a Cloudflare edge, the
/// layer sets the client IP and scheme from the Cloudflare headers. For
/// other requests, it removes the Cloudflare headers.
///
/// ```rust,no_run
/// use autumn_plugin_cloudflare::CloudflarePlugin;
/// use autumn_web::prelude::*;
///
/// #[get("/")]
/// async fn index() -> &'static str {
///     "hello"
/// }
///
/// #[autumn_web::main]
/// async fn main() {
///     autumn_web::app()
///         .plugin(CloudflarePlugin::new())
///         .routes(routes![index])
///         .run()
///         .await;
/// }
/// ```
pub struct CloudflarePlugin {
    ranges: CloudflareRanges,
    peer_source: PeerSource,
    lock: bool,
    allow: Vec<IpRange>,
    secret: Option<(HeaderName, String)>,
    refresh: Option<Duration>,
    ranges_url: String,
    cache: Option<CloudflareCache>,
}

impl fmt::Debug for CloudflarePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflarePlugin")
            .field("ranges", &self.ranges.ranges().len())
            .field("peer_source", &self.peer_source)
            .field("lock", &self.lock)
            .field("allow", &self.allow)
            .field("secret_header", &self.secret.as_ref().map(|(name, _)| name))
            .field("refresh", &self.refresh)
            .field("ranges_url", &self.ranges_url)
            .field("cache", &self.cache)
            .finish()
    }
}

impl Default for CloudflarePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflarePlugin {
    /// Make a plugin with the default options: the built-in ranges, the
    /// socket peer, no origin lock, no secret, and no refresh.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ranges: CloudflareRanges::builtin(),
            peer_source: PeerSource::Socket,
            lock: false,
            allow: Vec::new(),
            secret: None,
            refresh: None,
            ranges_url: DEFAULT_RANGES_URL.to_owned(),
            cache: None,
        }
    }

    /// Use these ranges instead of the built-in list.
    #[must_use]
    pub fn ranges(mut self, ranges: CloudflareRanges) -> Self {
        self.ranges = ranges;
        self
    }

    /// Set the IP that the plugin checks. The default is
    /// [`PeerSource::Socket`].
    #[must_use]
    pub const fn peer_source(mut self, source: PeerSource) -> Self {
        self.peer_source = source;
        self
    }

    /// When `true`, return `403 Forbidden` to peers that are not Cloudflare
    /// and not in an [`allow`](Self::allow) range. The default is `false`.
    #[must_use]
    pub const fn lock_origin(mut self, lock: bool) -> Self {
        self.lock = lock;
        self
    }

    /// Let peers in this range pass the origin lock, for example health
    /// checks. The plugin removes their Cloudflare headers.
    #[must_use]
    pub fn allow(mut self, range: IpRange) -> Self {
        self.allow.push(range);
        self
    }

    /// Require the header `name` with the value `value` from Cloudflare.
    /// Add the header with a Cloudflare Transform Rule.
    ///
    /// A request without the correct value is not from Cloudflare. The
    /// plugin removes the header before the handler. An empty value never
    /// matches.
    #[must_use]
    pub fn require_header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        self.secret = Some((name, value.into()));
        self
    }

    /// Get the range list from the Cloudflare API at startup and then at
    /// each interval. The plugin uses 60 seconds or more. If a refresh
    /// fails, the plugin logs a warning and keeps the last good list.
    #[must_use]
    pub fn refresh_ranges(mut self, interval: Duration) -> Self {
        self.refresh = Some(interval.max(MIN_REFRESH));
        self
    }

    /// Set the URL of the range API. The default is
    /// `https://api.cloudflare.com/client/v4/ips`.
    #[must_use]
    pub fn ranges_url(mut self, url: impl Into<String>) -> Self {
        self.ranges_url = url.into();
        self
    }

    /// Put a purge client in the app state. Handlers can then use
    /// [`CloudflareCache`] as an extractor.
    #[must_use]
    pub fn cache(mut self, cache: CloudflareCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Make the Tower layer for these options. Each call makes a new
    /// layer with its own range list.
    #[must_use]
    pub fn layer(&self) -> CloudflareLayer {
        if self.secret.as_ref().is_some_and(|(_, v)| v.is_empty()) {
            tracing::error!(
                "cloudflare: the required header value is empty, so no request is verified"
            );
        }
        CloudflareLayer::new(Settings {
            ranges: RwLock::new(Arc::new(self.ranges.clone())),
            peer_source: self.peer_source,
            lock: self.lock,
            allow: self.allow.clone(),
            secret: self.secret.as_ref().map(|(name, value)| Secret {
                name: name.clone(),
                value: value.as_bytes().to_vec(),
            }),
        })
    }
}

impl Plugin for CloudflarePlugin {
    fn build(self, app: AppBuilder) -> AppBuilder {
        let layer = self.layer();
        let mut app = app.layer(layer.clone());
        if let Some(cache) = self.cache {
            app = app.state_initializer(move |state| state.insert_extension(cache));
        }
        if let Some(interval) = self.refresh {
            let task = Arc::new(Mutex::new(None));
            let start = Arc::clone(&task);
            let url = self.ranges_url;
            app = app
                .on_startup(move |_state| {
                    let handle = spawn_refresh(layer.clone(), url.clone(), interval);
                    let old = start
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .replace(handle);
                    if let Some(old) = old {
                        old.abort();
                    }
                    async { Ok(()) }
                })
                .on_shutdown(move || {
                    let handle = task.lock().unwrap_or_else(PoisonError::into_inner).take();
                    if let Some(handle) = handle {
                        handle.abort();
                    }
                    async {}
                });
        }
        app
    }

    fn contract(&self) -> Option<PluginContract> {
        Some(
            PluginContract::new(env!("CARGO_PKG_NAME"))
                .plugin_version(env!("CARGO_PKG_VERSION"))
                .autumn_web("0.8"),
        )
    }
}
