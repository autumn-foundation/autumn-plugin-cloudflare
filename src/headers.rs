//! Cloudflare request headers.

use std::net::IpAddr;

use http::HeaderMap;

/// Visitor IP (one value).
pub(crate) const CONNECTING_IP: &str = "cf-connecting-ip";
/// Real IPv6 visitor IP when Pseudo IPv4 overwrites `CF-Connecting-IP`.
pub(crate) const CONNECTING_IPV6: &str = "cf-connecting-ipv6";
/// Ray ID.
pub(crate) const RAY: &str = "cf-ray";
/// Visitor country.
pub(crate) const COUNTRY: &str = "cf-ipcountry";
/// Visitor scheme, as JSON.
pub(crate) const VISITOR: &str = "cf-visitor";
/// Zone of the Worker that sent the request.
pub(crate) const WORKER: &str = "cf-worker";

/// The longest header value that the extractor keeps.
const MAX_VALUE_LEN: usize = 256;

/// The value of `name` when there is exactly one, as text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// Parses one IP from the header `name`. Returns `None` when the header is
/// missing, repeated, or not one valid IP.
#[must_use]
pub fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    single(headers, name)?.trim().parse().ok()
}

/// Returns the visitor scheme from `CF-Visitor`. If that header is not
/// valid, uses `X-Forwarded-Proto`. Returns only `http` or `https`.
#[must_use]
pub fn visitor_scheme(headers: &HeaderMap) -> Option<&'static str> {
    #[derive(serde::Deserialize)]
    struct Visitor {
        scheme: String,
    }
    let from_visitor = single(headers, VISITOR)
        .and_then(|v| serde_json::from_str::<Visitor>(v).ok())
        .map(|v| v.scheme);
    let from_proto = || {
        single(headers, "x-forwarded-proto")
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_owned())
    };
    let scheme = from_visitor.or_else(from_proto)?;
    if scheme.eq_ignore_ascii_case("https") {
        Some("https")
    } else if scheme.eq_ignore_ascii_case("http") {
        Some("http")
    } else {
        None
    }
}

/// Removes all `cf-*` headers and `true-client-ip`.
pub fn strip_cloudflare_headers(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .keys()
        .filter(|n| n.as_str().starts_with("cf-") || n.as_str() == "true-client-ip")
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

/// A short printable text value of `name`.
pub(crate) fn text(headers: &HeaderMap, name: &str) -> Option<String> {
    single(headers, name)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= MAX_VALUE_LEN)
        .filter(|v| v.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
        .map(str::to_owned)
}

/// The two-letter country code from `CF-IPCountry`.
pub(crate) fn country(headers: &HeaderMap) -> Option<String> {
    single(headers, COUNTRY)
        .map(str::trim)
        .filter(|v| v.len() == 2 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_owned)
}
