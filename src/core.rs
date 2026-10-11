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
/// The largest number of ranges in a list.
pub const MAX_RANGES: usize = 1024;
/// The largest number of IPv4 addresses that a list can cover (one `/8`).
pub const MAX_V4_COVERAGE: u128 = 1 << 24;
/// The largest number of IPv6 addresses that a list can cover (one `/16`).
pub const MAX_V6_COVERAGE: u128 = 1 << 112;

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

/// Returns true when the top `prefix` bits of `addr` and `network` are equal.
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

/// Returns true when a range is narrow enough for a Cloudflare list.
#[must_use]
pub const fn range_is_safe(is_v4: bool, prefix: u8) -> bool {
    if is_v4 {
        MIN_V4_PREFIX <= prefix && prefix <= 32
    } else {
        MIN_V6_PREFIX <= prefix && prefix <= 128
    }
}

/// Decides the result of the edge check. The function verifies only an
/// edge with the correct secret. With the lock on, it rejects all other
/// peers that are not allowed.
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

/// Returns true when `a` is a Pseudo IPv4 address (Class E, `240.0.0.0/4`).
#[must_use]
pub const fn is_pseudo_ipv4(a: u32) -> bool {
    (a >> 28) == 0xf
}

/// The visitor IP. The function uses `CF-Connecting-IPv6` only when
/// `CF-Connecting-IP` is a Pseudo IPv4 address. If not, it uses
/// `CF-Connecting-IP`. If that header is missing, it uses the peer.
#[must_use]
pub fn choose_client_ip(
    v6_header: Option<IpAddr>,
    ip_header: Option<IpAddr>,
    peer: IpAddr,
) -> (IpAddr, ClientIpSource) {
    match (v6_header, ip_header) {
        (Some(v6 @ IpAddr::V6(_)), Some(IpAddr::V4(a))) if is_pseudo_ipv4(a.into()) => {
            (v6, ClientIpSource::ConnectingIpv6)
        }
        (_, Some(ip)) => (ip, ClientIpSource::ConnectingIp),
        (_, None) => (peer, ClientIpSource::Peer),
    }
}

/// Compares `input` with `secret`. The loop reads `secret.len()` bytes.
/// The time does not depend on the input length or on the first
/// difference.
#[must_use]
pub fn constant_time_eq(input: &[u8], secret: &[u8]) -> bool {
    let mut diff = u8::from(input.len() != secret.len());
    for (i, s) in secret.iter().enumerate() {
        let x = input.get(i).copied().unwrap_or(0);
        diff |= x ^ s;
    }
    std::hint::black_box(diff) == 0
}

/// Returns true when `t` is a valid cache tag: 1 to 1,024 bytes of printable
/// ASCII, with no space and no comma.
#[must_use]
pub fn valid_tag(t: &[u8]) -> bool {
    if t.is_empty() || t.len() > MAX_TAG_LEN {
        return false;
    }
    t.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b',')
}

/// Returns the length of the tags joined with commas. `None` when the value is
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

/// Returns the number of batches of `size` items for `n` items. `size` must be 1
/// or more.
#[must_use]
pub const fn batch_count(n: usize, size: usize) -> usize {
    let q = n / size;
    if n.is_multiple_of(size) { q } else { q + 1 }
}
