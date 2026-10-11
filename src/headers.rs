//! Cloudflare request headers.

use std::net::IpAddr;

use http::HeaderMap;

/// Parse one IP from the header `name`.
#[must_use]
pub fn header_ip(_headers: &HeaderMap, _name: &str) -> Option<IpAddr> {
    todo!()
}

/// The visitor scheme from `CF-Visitor`, then `X-Forwarded-Proto`.
#[must_use]
pub fn visitor_scheme(_headers: &HeaderMap) -> Option<&'static str> {
    todo!()
}

/// Remove all `cf-*` headers and `true-client-ip`.
pub fn strip_cloudflare_headers(_headers: &mut HeaderMap) {
    todo!()
}
