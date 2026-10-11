//! The `CloudflareRequest` extractor.

use std::net::IpAddr;

/// Cloudflare data for a request that came from Cloudflare.
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

    /// The visitor country (`CF-IPCountry`).
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

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CloudflareRequest {
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(
        _parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        todo!()
    }
}

impl<S: Send + Sync> axum::extract::OptionalFromRequestParts<S> for CloudflareRequest {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        _parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        todo!()
    }
}
