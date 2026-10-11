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

/// True when the top `prefix` bits of `addr` and `network` are equal.
/// A prefix above 32 never matches.
#[must_use]
pub const fn prefix_match_v4(network: u32, prefix: u8, addr: u32) -> bool {
    if prefix == 0 {
        true
    } else if prefix > 32 {
        false
    } else {
        let shift = 32 - prefix as u32;
        (network >> shift) == (addr >> shift)
    }
}

/// The IPv6 version of [`prefix_match_v4`]. A prefix above 128 never
/// matches.
#[must_use]
pub const fn prefix_match_v6(network: u128, prefix: u8, addr: u128) -> bool {
    if prefix == 0 {
        true
    } else if prefix > 128 {
        false
    } else {
        let shift = 128 - prefix as u32;
        (network >> shift) == (addr >> shift)
    }
}

/// True when a range is narrow enough for a Cloudflare list.
#[must_use]
pub const fn range_is_safe(is_v4: bool, prefix: u8) -> bool {
    if is_v4 {
        MIN_V4_PREFIX <= prefix && prefix <= 32
    } else {
        MIN_V6_PREFIX <= prefix && prefix <= 128
    }
}

/// The edge check. Only a Cloudflare peer with the correct secret is
/// verified. The lock rejects all other peers that are not allowed.
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "the four inputs are the Verus model inputs"
)]
#[must_use]
pub const fn decide(is_edge: bool, secret_ok: bool, allowed: bool, lock: bool) -> Decision {
    if is_edge && secret_ok {
        Decision::Verified
    } else if lock && !allowed {
        Decision::Reject
    } else {
        Decision::Direct
    }
}

/// The client IP: an IPv6 value from `CF-Connecting-IPv6`, then
/// `CF-Connecting-IP`, then the peer.
#[must_use]
pub const fn choose_client_ip(
    v6_header: Option<IpAddr>,
    ip_header: Option<IpAddr>,
    peer: IpAddr,
) -> (IpAddr, ClientIpSource) {
    match v6_header {
        Some(ip @ IpAddr::V6(_)) => (ip, ClientIpSource::ConnectingIpv6),
        _ => match ip_header {
            Some(ip) => (ip, ClientIpSource::ConnectingIp),
            None => (peer, ClientIpSource::Peer),
        },
    }
}

/// Compare two byte strings. The time does not depend on the position of
/// the first difference.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// True when `t` is a valid cache tag: 1 to 1,024 bytes of printable
/// ASCII, with no space and no comma.
#[must_use]
pub fn valid_tag(t: &[u8]) -> bool {
    if t.is_empty() || t.len() > MAX_TAG_LEN {
        return false;
    }
    t.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b',')
}

/// The length of the tags joined with commas. `None` when the value is
/// longer than [`MAX_HEADER_LEN`].
#[must_use]
pub fn tags_header_len(lens: &[usize]) -> Option<usize> {
    let mut total: usize = 0;
    for (i, &len) in lens.iter().enumerate() {
        let sep = usize::from(i != 0);
        if total + sep > MAX_HEADER_LEN || len > MAX_HEADER_LEN - total - sep {
            return None;
        }
        total = total + sep + len;
    }
    Some(total)
}

/// The number of batches of `size` items for `n` items. `size` must be 1
/// or more.
#[must_use]
pub const fn batch_count(n: usize, size: usize) -> usize {
    let q = n / size;
    if n.is_multiple_of(size) { q } else { q + 1 }
}
