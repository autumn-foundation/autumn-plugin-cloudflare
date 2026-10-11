//! Pure core. Each function has a Verus twin in `verification/core.rs`.

use std::net::IpAddr;

/// The broadest IPv4 prefix that a range list can have.
pub const MIN_V4_PREFIX: u8 = 8;
/// The broadest IPv6 prefix that a range list can have.
pub const MIN_V6_PREFIX: u8 = 16;
/// The longest tag that the purge API accepts, in bytes.
pub const MAX_TAG_LEN: usize = 1024;
/// The longest `Cache-Tag` header value, in bytes.
pub const MAX_HEADER_LEN: usize = 16384;
/// The largest number of items in one purge request.
pub const MAX_BATCH: usize = 100;

/// The result of the edge check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request came from Cloudflare.
    Verified,
    /// The request did not come from Cloudflare. It can continue.
    Direct,
    /// The origin lock stops the request.
    Reject,
}

/// The source of the client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpSource {
    /// `CF-Connecting-IPv6`.
    ConnectingIpv6,
    /// `CF-Connecting-IP`.
    ConnectingIp,
    /// The peer IP.
    Peer,
}

/// Twin of `prefix_match_v4`.
#[must_use]
pub const fn prefix_match_v4(_network: u32, _prefix: u8, _addr: u32) -> bool {
    todo!()
}

/// Twin of `prefix_match_v6`.
#[must_use]
pub const fn prefix_match_v6(_network: u128, _prefix: u8, _addr: u128) -> bool {
    todo!()
}

/// Twin of `range_is_safe`.
#[must_use]
pub const fn range_is_safe(_is_v4: bool, _prefix: u8) -> bool {
    todo!()
}

/// Twin of `decide`.
#[must_use]
pub const fn decide(_is_edge: bool, _secret_ok: bool, _allowed: bool, _lock: bool) -> Decision {
    todo!()
}

/// Twin of `choose_client_ip`.
#[must_use]
pub fn choose_client_ip(
    _v6_header: Option<IpAddr>,
    _ip_header: Option<IpAddr>,
    _peer: IpAddr,
) -> (IpAddr, ClientIpSource) {
    todo!()
}

/// Twin of `constant_time_eq`.
#[must_use]
pub fn constant_time_eq(_a: &[u8], _b: &[u8]) -> bool {
    todo!()
}

/// Twin of `valid_tag`.
#[must_use]
pub fn valid_tag(_t: &[u8]) -> bool {
    todo!()
}

/// Twin of `tags_header_len`.
#[must_use]
pub fn tags_header_len(_lens: &[usize]) -> Option<usize> {
    todo!()
}

/// Twin of `batch_count`.
#[must_use]
pub const fn batch_count(_n: usize, _size: usize) -> usize {
    todo!()
}
