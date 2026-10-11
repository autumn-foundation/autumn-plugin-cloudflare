//! Verus model of the pure core in `src/`.
//!
//! Each `exec` function here has the same logic as its runtime twin.
//! Tests in `tests/spec_conformance.rs` check that the twins agree.
//!
//! Run: `verification/verify.sh`.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Range match (twin: `src/core.rs::prefix_match_v4` and `prefix_match_v6`)
// ---------------------------------------------------------------------------

/// Spec: `addr` is in `network/prefix`. The top `prefix` bits are equal.
pub open spec fn spec_match_v4(network: u32, prefix: u8, addr: u32) -> bool {
    if prefix == 0 {
        true
    } else if prefix > 32 {
        false
    } else {
        (network >> ((32 - prefix) as u32)) == (addr >> ((32 - prefix) as u32))
    }
}

/// Twin of `prefix_match_v4`.
pub fn prefix_match_v4(network: u32, prefix: u8, addr: u32) -> (r: bool)
    ensures
        r == spec_match_v4(network, prefix, addr),
        // A bad prefix never matches.
        prefix > 32 ==> !r,
        // A network address is in its own range.
        prefix <= 32 && addr == network ==> r,
        // A `/32` range has one address.
        prefix == 32 ==> (r <==> addr == network),
{
    if prefix == 0 {
        true
    } else if prefix > 32 {
        false
    } else {
        let shift: u32 = (32 - prefix) as u32;
        if prefix == 32 {
            assert(shift == 0);
            assert((network >> 0u32) == network && (addr >> 0u32) == addr) by (bit_vector);
        }
        (network >> shift) == (addr >> shift)
    }
}

/// A shorter prefix keeps a match. So the range check is monotonic.
pub proof fn lemma_match_v4_monotonic(network: u32, p: u8, q: u8, addr: u32)
    requires
        spec_match_v4(network, p, addr),
        q <= p,
        p <= 32,
    ensures
        spec_match_v4(network, q, addr),
{
    if q != 0 {
        let s1: u32 = (32 - p) as u32;
        let s2: u32 = (32 - q) as u32;
        assert(s1 <= s2 && s2 < 32);
        assert((network >> s1) == (addr >> s1) && s1 <= s2 && s2 < 32 ==> (network >> s2) == (
        addr >> s2)) by (bit_vector);
    }
}

/// Spec for IPv6.
pub open spec fn spec_match_v6(network: u128, prefix: u8, addr: u128) -> bool {
    if prefix == 0 {
        true
    } else if prefix > 128 {
        false
    } else {
        (network >> ((128 - prefix) as u128)) == (addr >> ((128 - prefix) as u128))
    }
}

/// Twin of `prefix_match_v6`.
pub fn prefix_match_v6(network: u128, prefix: u8, addr: u128) -> (r: bool)
    ensures
        r == spec_match_v6(network, prefix, addr),
        prefix > 128 ==> !r,
        prefix <= 128 && addr == network ==> r,
        prefix == 128 ==> (r <==> addr == network),
{
    if prefix == 0 {
        true
    } else if prefix > 128 {
        false
    } else {
        let shift: u128 = (128 - prefix) as u128;
        if prefix == 128 {
            assert(shift == 0);
            assert((network >> 0u128) == network && (addr >> 0u128) == addr) by (bit_vector);
        }
        (network >> shift) == (addr >> shift)
    }
}

// ---------------------------------------------------------------------------
// Range list safety (twin: `src/core.rs::range_is_safe`)
// ---------------------------------------------------------------------------

/// The broadest IPv4 prefix that a range list can have.
pub const MIN_V4_PREFIX: u8 = 8;

/// The broadest IPv6 prefix that a range list can have.
pub const MIN_V6_PREFIX: u8 = 16;

/// Spec: a range is narrow enough and has a valid prefix.
pub open spec fn spec_range_is_safe(is_v4: bool, prefix: u8) -> bool {
    if is_v4 {
        MIN_V4_PREFIX <= prefix && prefix <= 32
    } else {
        MIN_V6_PREFIX <= prefix && prefix <= 128
    }
}

/// Twin of `range_is_safe`.
pub fn range_is_safe(is_v4: bool, prefix: u8) -> (r: bool)
    ensures
        r == spec_range_is_safe(is_v4, prefix),
        // A safe range never matches all addresses.
        r ==> prefix != 0,
{
    if is_v4 {
        MIN_V4_PREFIX <= prefix && prefix <= 32
    } else {
        MIN_V6_PREFIX <= prefix && prefix <= 128
    }
}

// ---------------------------------------------------------------------------
// Decision (twin: `src/core.rs::decide`)
// ---------------------------------------------------------------------------

/// Model of `Decision`.
pub enum Decision {
    Verified,
    Direct,
    Reject,
}

/// Spec: the result of the edge check.
pub open spec fn spec_decide(is_edge: bool, secret_ok: bool, allowed: bool, lock: bool) -> Decision {
    if is_edge && secret_ok {
        Decision::Verified
    } else if lock && !allowed {
        Decision::Reject
    } else {
        Decision::Direct
    }
}

/// Twin of `decide`.
pub fn decide(is_edge: bool, secret_ok: bool, allowed: bool, lock: bool) -> (r: Decision)
    ensures
        r == spec_decide(is_edge, secret_ok, allowed, lock),
        // Only a Cloudflare peer with the correct secret is verified.
        r is Verified <==> (is_edge && secret_ok),
        // With the lock off, the plugin never rejects.
        !lock ==> !(r is Reject),
        // An allowed peer is never rejected.
        allowed ==> !(r is Reject),
        // With the lock on, a peer that is not verified and not allowed is rejected.
        lock && !allowed && !(is_edge && secret_ok) ==> r is Reject,
{
    if is_edge && secret_ok {
        Decision::Verified
    } else if lock && !allowed {
        Decision::Reject
    } else {
        Decision::Direct
    }
}

// ---------------------------------------------------------------------------
// Client IP choice (twin: `src/core.rs::choose_client_ip`)
// ---------------------------------------------------------------------------

/// Model of `IpAddr`.
pub enum Ip {
    V4(u32),
    V6(u128),
}

/// Model of the source of the client IP.
pub enum Source {
    ConnectingIpv6,
    ConnectingIp,
    Peer,
}

/// Spec: a Pseudo IPv4 address is in the Class E range `240.0.0.0/4`.
pub open spec fn spec_is_pseudo_ipv4(a: u32) -> bool {
    (a >> 28u32) == 0xfu32
}

/// Spec: use `CF-Connecting-IPv6` only when Pseudo IPv4 overwrote
/// `CF-Connecting-IP`. Then use `CF-Connecting-IP`. Then use the peer.
pub open spec fn spec_choose(v6_header: Option<Ip>, ip_header: Option<Ip>) -> Source {
    match (v6_header, ip_header) {
        (Some(Ip::V6(_)), Some(Ip::V4(a))) if spec_is_pseudo_ipv4(a) => Source::ConnectingIpv6,
        (_, Some(_)) => Source::ConnectingIp,
        (_, None) => Source::Peer,
    }
}

/// Twin of `choose_client_ip`.
pub fn choose_client_ip(v6_header: Option<Ip>, ip_header: Option<Ip>, peer: Ip) -> (r: (Ip, Source))
    ensures
        r.1 == spec_choose(v6_header, ip_header),
        r.1 is ConnectingIpv6 ==> v6_header == Some(r.0) && r.0 is V6,
        r.1 is ConnectingIp ==> ip_header == Some(r.0),
        r.1 is Peer ==> r.0 == peer,
        // Without a Pseudo IPv4 value, `CF-Connecting-IPv6` never wins.
        (forall|a: u32| ip_header == Some(Ip::V4(a)) ==> !spec_is_pseudo_ipv4(a))
            ==> !(r.1 is ConnectingIpv6),
        // The peer is used only when `CF-Connecting-IP` is missing.
        r.1 is Peer <==> ip_header is None,
{
    match (v6_header, ip_header) {
        (Some(Ip::V6(b)), Some(Ip::V4(a))) if (a >> 28u32) == 0xfu32 => (
            Ip::V6(b),
            Source::ConnectingIpv6,
        ),
        (_, Some(ip)) => (ip, Source::ConnectingIp),
        (_, None) => (peer, Source::Peer),
    }
}

// ---------------------------------------------------------------------------
// Constant-time compare (twin: `src/core.rs::constant_time_eq`)
// ---------------------------------------------------------------------------

proof fn lemma_xor_or(diff: u8, x: u8, y: u8)
    ensures
        ((diff | (x ^ y)) == 0) <==> (diff == 0 && x == y),
{
    assert(((diff | (x ^ y)) == 0) <==> (diff == 0 && x == y)) by (bit_vector);
}

/// Twin of `constant_time_eq`. The loop reads `secret.len()` bytes. The
/// time does not depend on the input length or on the first difference.
pub fn constant_time_eq(input: &[u8], secret: &[u8]) -> (r: bool)
    ensures
        r <==> input@ == secret@,
{
    let mut diff: u8 = if input.len() == secret.len() { 0 } else { 1 };
    let mut i: usize = 0;
    while i < secret.len()
        invariant
            i <= secret.len(),
            diff == 0 <==> (input.len() == secret.len() && forall|j: int|
                0 <= j < i ==> input@[j] == secret@[j]),
        decreases secret.len() - i,
    {
        let x: u8 = if i < input.len() { input[i] } else { 0 };
        proof {
            lemma_xor_or(diff, x, secret@[i as int]);
        }
        diff = diff | (x ^ secret[i]);
        i = i + 1;
    }
    proof {
        if diff == 0 {
            assert(input@ =~= secret@);
        }
        if input@ == secret@ {
            assert(input.len() == secret.len());
        }
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Cache tags (twin: `src/core.rs::valid_tag` and `tags_header_len`)
// ---------------------------------------------------------------------------

/// The longest tag that the purge API accepts, in bytes.
pub const MAX_TAG_LEN: usize = 1024;

/// The longest `Cache-Tag` header value, in bytes.
pub const MAX_HEADER_LEN: usize = 16384;

/// Spec: printable ASCII, not a space, not a comma.
pub open spec fn spec_tag_byte(b: u8) -> bool {
    0x21 <= b && b <= 0x7e && b != 0x2c
}

/// Spec: a valid tag.
pub open spec fn spec_valid_tag(t: Seq<u8>) -> bool {
    1 <= t.len() <= MAX_TAG_LEN && forall|j: int| #![auto] 0 <= j < t.len() ==> spec_tag_byte(t[j])
}

/// Twin of `valid_tag`.
pub fn valid_tag(t: &[u8]) -> (r: bool)
    ensures
        r == spec_valid_tag(t@),
{
    if t.len() == 0 || t.len() > MAX_TAG_LEN {
        return false;
    }
    let mut i: usize = 0;
    while i < t.len()
        invariant
            1 <= t.len() <= MAX_TAG_LEN,
            i <= t.len(),
            forall|j: int| #![auto] 0 <= j < i ==> spec_tag_byte(t@[j]),
        decreases t.len() - i,
    {
        let b = t[i];
        if !(0x21 <= b && b <= 0x7e && b != 0x2c) {
            return false;
        }
        i = i + 1;
    }
    true
}

/// Spec: the header value length for tags with lengths `lens`. Commas
/// join the tags.
pub open spec fn spec_header_len(lens: Seq<usize>) -> int
    decreases lens.len(),
{
    if lens.len() == 0 {
        0
    } else if lens.len() == 1 {
        lens[0] as int
    } else {
        spec_header_len(lens.drop_last()) + 1 + lens.last() as int
    }
}

proof fn lemma_header_len_grows(lens: Seq<usize>)
    ensures
        spec_header_len(lens) >= 0,
    decreases lens.len(),
{
    if lens.len() > 1 {
        lemma_header_len_grows(lens.drop_last());
    }
}

/// Twin of `tags_header_len`. Returns `None` when the value is too long.
pub fn tags_header_len(lens: &[usize]) -> (r: Option<usize>)
    ensures
        r matches Some(n) ==> n as int == spec_header_len(lens@) && n <= MAX_HEADER_LEN,
        r is None ==> spec_header_len(lens@) > MAX_HEADER_LEN,
{
    let mut total: usize = 0;
    let mut i: usize = 0;
    while i < lens.len()
        invariant
            i <= lens.len(),
            total as int == spec_header_len(lens@.subrange(0, i as int)),
            total <= MAX_HEADER_LEN,
        decreases lens.len() - i,
    {
        let sep: usize = if i == 0 { 0 } else { 1 };
        assert(lens@.subrange(0, i as int + 1).drop_last() =~= lens@.subrange(0, i as int));
        if total + sep > MAX_HEADER_LEN || lens[i] > MAX_HEADER_LEN - total - sep {
            proof {
                lemma_prefix_bound(lens@, i as int + 1);
            }
            return None;
        }
        total = total + sep + lens[i];
        i = i + 1;
    }
    assert(lens@.subrange(0, lens.len() as int) =~= lens@);
    Some(total)
}

/// A longer list never has a shorter header value.
proof fn lemma_prefix_bound(lens: Seq<usize>, k: int)
    requires
        0 <= k <= lens.len(),
    ensures
        spec_header_len(lens) >= spec_header_len(lens.subrange(0, k)),
    decreases lens.len() - k,
{
    if k < lens.len() {
        lemma_prefix_bound(lens, k + 1);
        let longer = lens.subrange(0, k + 1);
        assert(longer.drop_last() =~= lens.subrange(0, k));
        lemma_header_len_grows(longer.drop_last());
    } else {
        assert(lens.subrange(0, k) =~= lens);
    }
}

// ---------------------------------------------------------------------------
// Purge batches (twin: `src/core.rs::batch_count`)
// ---------------------------------------------------------------------------

/// The largest number of items in one purge request.
pub const MAX_BATCH: usize = 100;

/// Twin of `batch_count`. `slice::chunks(size)` gives this many chunks.
pub fn batch_count(n: usize, size: usize) -> (r: usize)
    requires
        1 <= size,
    ensures
        // The batches hold all items.
        (r as int) * (size as int) >= (n as int),
        // No batch is empty.
        n > 0 ==> ((r as int - 1) * (size as int)) < (n as int),
        n == 0 ==> r == 0,
{
    let q = n / size;
    let rem = n % size;
    proof {
        assert(q as int * size as int + rem as int == n as int && rem < size) by (nonlinear_arith)
            requires
                q == n / size,
                rem == n % size,
                size >= 1,
        ;
    }
    if rem == 0 {
        proof {
            assert(n > 0 ==> ((q as int - 1) * (size as int)) < (n as int)) by (nonlinear_arith)
                requires
                    q as int * size as int == n as int,
                    size >= 1,
            ;
        }
        q
    } else {
        proof {
            assert(q as int * 2 <= n as int) by (nonlinear_arith)
                requires
                    q as int * size as int + rem as int == n as int,
                    rem > 0,
                    rem < size,
            ;
            assert((q as int + 1) * (size as int) >= (n as int)) by (nonlinear_arith)
                requires
                    q as int * size as int + rem as int == n as int,
                    rem < size,
            ;
        }
        q + 1
    }
}

fn main() {
}

} // verus!
