//! The `CloudflareRequest` extractor.

use std::convert::Infallible;
use std::future::{Future, ready};
use std::net::IpAddr;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::StatusCode;
use http::request::Parts;

/// Cloudflare data for a request that came from Cloudflare.
///
/// The plugin adds it only to verified requests. Use
/// `Option<CloudflareRequest>` for routes that also get direct requests.
/// Without the data, the extractor returns `403 Forbidden`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRequest {
    pub(crate) client_ip: IpAddr,
    pub(crate) edge_ip: IpAddr,
    pub(crate) ray: Option<String>,
    pub(crate) country: Option<String>,
    pub(crate) scheme: Option<&'static str>,
    pub(crate) worker: Option<String>,
}

impl CloudflareRequest {
    /// The visitor IP.
    #[must_use]
    pub const fn client_ip(&self) -> IpAddr {
        self.client_ip
    }

    /// The IP of the Cloudflare edge.
    #[must_use]
    pub const fn edge_ip(&self) -> IpAddr {
        self.edge_ip
    }

    /// The Ray ID (`CF-Ray`).
    #[must_use]
    pub fn ray(&self) -> Option<&str> {
        self.ray.as_deref()
    }

    /// The two-letter visitor country (`CF-IPCountry`). Cloudflare uses
    /// `XX` for "unknown" and `T1` for Tor.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// The visitor scheme: `http` or `https`.
    #[must_use]
    pub const fn scheme(&self) -> Option<&'static str> {
        self.scheme
    }

    /// The zone of the Worker that sent the request (`CF-Worker`).
    #[must_use]
    pub fn worker(&self) -> Option<&str> {
        self.worker.as_deref()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CloudflareRequest {
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(parts.extensions.get::<Self>().cloned().ok_or((
            StatusCode::FORBIDDEN,
            "the request did not come through Cloudflare",
        )))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for CloudflareRequest {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        ready(Ok(parts.extensions.get::<Self>().cloned()))
    }
}
