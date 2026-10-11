//! The Tower layer that checks the edge and sets the client identity.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};

use autumn_web::security::ResolvedClientIdentity;
use axum::extract::ConnectInfo;
use axum::response::{IntoResponse, Response};
use http::header::{HOST, HeaderName};
use http::{HeaderMap, HeaderValue, Request, StatusCode};
use tower::{Layer, Service};

use crate::core::{Decision, choose_client_ip, constant_time_eq, decide};
use crate::headers::{
    CONNECTING_IP, CONNECTING_IPV6, RAY, WORKER, country, header_ip, strip_cloudflare_headers,
    text, visitor_scheme,
};
use crate::plugin::PeerSource;
use crate::ranges::{CloudflareRanges, IpRange, any_contains};
use crate::request::CloudflareRequest;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

/// A shared-secret header. `Debug` hides the value.
pub(crate) struct Secret {
    pub(crate) name: HeaderName,
    pub(crate) value: Vec<u8>,
}

impl Secret {
    /// Returns true when the request has exactly one matching value. An
    /// empty secret never matches.
    fn matches(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(&self.name).iter();
        match (values.next(), values.next()) {
            (Some(value), None) => {
                !self.value.is_empty() && constant_time_eq(value.as_bytes(), &self.value)
            }
            _ => false,
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("value", &"***")
            .finish()
    }
}

/// The layer options.
#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) ranges: RwLock<Arc<CloudflareRanges>>,
    pub(crate) peer_source: PeerSource,
    pub(crate) lock: bool,
    pub(crate) allow: Vec<IpRange>,
    pub(crate) secret: Option<Secret>,
    /// Set after the first warning about a missing resolved IP.
    pub(crate) warned_no_identity: AtomicBool,
}

/// Tower layer from [`CloudflarePlugin::layer`](crate::CloudflarePlugin::layer).
///
/// The plugin adds this layer for you. Use it directly only with a plain
/// `axum` router. Clones share one range list. This layer does not refresh
/// its ranges. Only the plugin starts a refresh task.
#[derive(Clone, Debug)]
pub struct CloudflareLayer {
    settings: Arc<Settings>,
}

impl CloudflareLayer {
    pub(crate) fn new(settings: Settings) -> Self {
        Self {
            settings: Arc::new(settings),
        }
    }

    /// The current range list.
    #[must_use]
    pub fn current_ranges(&self) -> Arc<CloudflareRanges> {
        let guard = self
            .settings
            .ranges
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Replaces the range list.
    pub(crate) fn set_ranges(&self, ranges: CloudflareRanges) {
        let mut guard = self
            .settings
            .ranges
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *guard = Arc::new(ranges);
    }

    /// The IP to check against the ranges.
    fn peer<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        let ip = match self.settings.peer_source {
            PeerSource::Socket => req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
            PeerSource::Resolved => {
                let ip = req
                    .extensions()
                    .get::<ResolvedClientIdentity>()
                    .and_then(|id| id.addr);
                if ip.is_none()
                    && !self
                        .settings
                        .warned_no_identity
                        .swap(true, Ordering::Relaxed)
                {
                    tracing::warn!(
                        "cloudflare: PeerSource::Resolved found no client IP from Autumn; \
                         check [security.trusted_proxies]"
                    );
                }
                ip
            }
        };
        ip.map(|ip| ip.to_canonical())
    }

    /// Checks the request and changes it for the decision.
    fn handle<B>(&self, req: &mut Request<B>) -> Decision {
        let settings = &self.settings;
        let peer = self.peer(req);
        let secret_ok = settings
            .secret
            .as_ref()
            .is_none_or(|s| s.matches(req.headers()));
        if let Some(secret) = &settings.secret {
            req.headers_mut().remove(&secret.name);
        }
        let ranges = self.current_ranges();
        let is_edge = peer.is_some_and(|ip| ranges.contains(ip));
        let allowed = peer.is_some_and(|ip| any_contains(&settings.allow, ip));
        let decision = decide(is_edge, secret_ok, allowed, settings.lock);
        match (decision, peer) {
            (Decision::Verified, Some(edge)) => apply_verified(req, edge),
            (Decision::Reject, _) => {
                tracing::debug!(peer = ?peer, "cloudflare: origin lock rejected a request");
            }
            _ => strip_cloudflare_headers(req.headers_mut()),
        }
        decision
    }
}

/// Sets the client identity from the Cloudflare headers.
///
/// Autumn reads the client IP from `ResolvedClientIdentity`, `ConnectInfo`,
/// or `X-Forwarded-For`. The function sets each one to the visitor IP.
/// The host comes from `Host`, because a client can send
/// `X-Forwarded-Host` through Cloudflare.
fn apply_verified<B>(req: &mut Request<B>, edge: IpAddr) {
    let headers = req.headers();
    let (client, _) = choose_client_ip(
        header_ip(headers, CONNECTING_IPV6),
        header_ip(headers, CONNECTING_IP),
        edge,
    );
    let client = client.to_canonical();
    let scheme = visitor_scheme(headers);
    let info = CloudflareRequest {
        client_ip: client,
        edge_ip: edge,
        ray: text(headers, RAY),
        country: country(headers),
        scheme,
        worker: text(headers, WORKER),
    };
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_owned());

    let extensions = req.extensions_mut();
    if let Some(id) = extensions.get_mut::<ResolvedClientIdentity>() {
        id.addr = Some(client);
        id.host = host;
        if let Some(scheme) = scheme {
            id.scheme = Some(scheme.to_owned());
        }
    } else {
        extensions.insert(ResolvedClientIdentity {
            addr: Some(client),
            host,
            scheme: scheme.map(str::to_owned),
        });
    }
    let port = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(0, |c| c.0.port());
    extensions.insert(ConnectInfo(SocketAddr::new(client, port)));
    extensions.insert(info);

    let headers = req.headers_mut();
    headers.remove(X_REAL_IP);
    headers.remove(X_FORWARDED_HOST);
    headers.remove(FORWARDED);
    if let Ok(value) = HeaderValue::from_str(&client.to_string()) {
        headers.insert(X_FORWARDED_FOR, value);
    }
    if let Some(scheme) = scheme {
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(scheme));
    }
}

impl<S> Layer<S> for CloudflareLayer {
    type Service = CloudflareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CloudflareService {
            inner,
            layer: self.clone(),
        }
    }
}

/// Tower service from [`CloudflareLayer`].
#[derive(Clone, Debug)]
pub struct CloudflareService<S> {
    inner: S,
    layer: CloudflareLayer,
}

impl<S, B> Service<Request<B>> for CloudflareService<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if self.layer.handle(&mut req) == Decision::Reject {
            return Box::pin(async { Ok((StatusCode::FORBIDDEN, "forbidden").into_response()) });
        }
        // Use the service that `poll_ready` made ready. Keep a clone.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(inner.call(req))
    }
}
