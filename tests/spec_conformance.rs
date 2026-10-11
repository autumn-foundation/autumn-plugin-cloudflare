//! Property tests: the runtime code agrees with the Verus spec in
//! `verification/core.rs`. Proofs cover the model. These tests connect
//! the model to the real code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use autumn_plugin_cloudflare::__private::{
    ClientIpSource, Decision, MAX_BATCH, MAX_HEADER_LEN, MAX_RANGES, MAX_TAG_LEN, MAX_V4_COVERAGE,
    MAX_V6_COVERAGE, MIN_V4_PREFIX, MIN_V6_PREFIX, batch_count, choose_client_ip, constant_time_eq,
    coverage_within, decide, is_pseudo_ipv4, prefix_match_v4, prefix_match_v6, range_is_safe,
    tags_header_len, valid_tag,
};
use autumn_plugin_cloudflare::{CloudflareRanges, IpRange, RangeError};
use proptest::prelude::*;

/// IPs with many Pseudo IPv4 (Class E) values.
fn ip_strategy() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<IpAddr>(),
        (0xf000_0000u32..=u32::MAX).prop_map(|a| IpAddr::V4(Ipv4Addr::from(a))),
    ]
}

/// Bit by bit: the top `prefix` bits are equal.
fn naive_match(network: u128, addr: u128, prefix: u32, width: u32) -> bool {
    if prefix > width {
        return false;
    }
    (0..prefix).all(|i| {
        let bit = width - 1 - i;
        (network >> bit) & 1 == (addr >> bit) & 1
    })
}

proptest! {
    #[test]
    fn v4_match_agrees_with_bits(n: u32, a: u32, p in 0u8..=40) {
        prop_assert_eq!(
            prefix_match_v4(n, p, a),
            naive_match(u128::from(n), u128::from(a), u32::from(p), 32)
        );
    }

    #[test]
    fn v4_match_near_network(n: u32, flip in 0u32..32, p in 0u8..=32) {
        // Flip one bit. The match fails only when the bit is in the prefix.
        let a = n ^ (1 << flip);
        let in_prefix = 31 - flip < u32::from(p);
        prop_assert_eq!(prefix_match_v4(n, p, a), !in_prefix);
    }

    #[test]
    fn v6_match_agrees_with_bits(n: u128, a: u128, p in 0u8..=140) {
        prop_assert_eq!(
            prefix_match_v6(n, p, a),
            naive_match(n, a, u32::from(p), 128)
        );
    }

    #[test]
    fn ip_range_agrees_with_bits(n: u32, a: u32, p in 0u8..=32) {
        let range: IpRange = format!("{}/{p}", Ipv4Addr::from(n)).parse().expect("range");
        prop_assert_eq!(
            range.contains(IpAddr::V4(Ipv4Addr::from(a))),
            naive_match(u128::from(n), u128::from(a), u32::from(p), 32)
        );
    }

    #[test]
    fn ip_range_v6_agrees_with_bits(n: u128, a: u128, p in 0u8..=128) {
        let range: IpRange = format!("{}/{p}", Ipv6Addr::from(n)).parse().expect("range");
        prop_assert_eq!(
            range.contains(IpAddr::V6(Ipv6Addr::from(a))),
            naive_match(n, a, u32::from(p), 128)
        );
    }

    #[test]
    fn v6_match_near_network(n: u128, flip in 0u32..128, p in prop_oneof![Just(0u8), Just(1), Just(64), Just(127), Just(128), 0u8..=128]) {
        let a = n ^ (1u128 << flip);
        let in_prefix = 127 - flip < u32::from(p);
        prop_assert_eq!(prefix_match_v6(n, p, a), !in_prefix);
        prop_assert_eq!(prefix_match_v6(n, p, n), true);
    }

    #[test]
    fn safe_ranges_never_match_everything(n: u32, n6: u128, p: u8) {
        // Property: a safe range leaves out the address with the top bit
        // flipped. An unsafe prefix is 0, too broad, or too long.
        if range_is_safe(true, p) {
            prop_assert!(!prefix_match_v4(n, p, n ^ 0x8000_0000));
        } else {
            prop_assert!(!(MIN_V4_PREFIX..=32).contains(&p));
        }
        if range_is_safe(false, p) {
            prop_assert!(!prefix_match_v6(n6, p, n6 ^ (1 << 127)));
        } else {
            prop_assert!(!(MIN_V6_PREFIX..=128).contains(&p));
        }
    }

    #[test]
    fn choose_agrees_with_spec(v6 in proptest::option::of(any::<IpAddr>()), ip in proptest::option::of(ip_strategy()), peer: IpAddr) {
        let (got, source) = choose_client_ip(v6, ip, peer);
        // Properties, not a copy of the code:
        // - the result is the value of the source that it names;
        // - the peer only when `CF-Connecting-IP` is missing;
        // - the IPv6 header only over a Class E value, and only as IPv6.
        match source {
            ClientIpSource::Peer => prop_assert!(ip.is_none() && got == peer),
            ClientIpSource::ConnectingIp => prop_assert_eq!(Some(got), ip),
            ClientIpSource::ConnectingIpv6 => {
                prop_assert_eq!(Some(got), v6);
                prop_assert!(got.is_ipv6());
                let class_e = matches!(ip, Some(IpAddr::V4(a)) if a.octets()[0] >= 240);
                prop_assert!(class_e);
            }
        }
        if ip.is_some() {
            prop_assert!(source != ClientIpSource::Peer);
        }
        if let (Some(IpAddr::V6(_)), Some(IpAddr::V4(a))) = (v6, ip)
            && a.octets()[0] >= 240
        {
            prop_assert_eq!(source, ClientIpSource::ConnectingIpv6);
        }
    }

    #[test]
    fn pseudo_ipv4_is_class_e(a: u32) {
        prop_assert_eq!(is_pseudo_ipv4(a), Ipv4Addr::from(a).octets()[0] >= 240);
    }

    #[test]
    fn constant_time_eq_is_eq(a in proptest::collection::vec(any::<u8>(), 0..40), b in proptest::collection::vec(any::<u8>(), 0..40)) {
        prop_assert_eq!(constant_time_eq(&a, &b), a == b);
        prop_assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn constant_time_eq_handles_prefixes(a in proptest::collection::vec(any::<u8>(), 0..40), extra in proptest::collection::vec(any::<u8>(), 1..5)) {
        let mut longer = a.clone();
        longer.extend(&extra);
        prop_assert!(!constant_time_eq(&a, &longer));
        prop_assert!(!constant_time_eq(&longer, &a));
    }

    #[test]
    fn coverage_limit_agrees_with_spec(prefixes in proptest::collection::vec(8u8..=32, 1..20)) {
        let ranges: Vec<String> = prefixes
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{}.0.0.0/{p}", 11 + i))
            .collect();
        let total: u128 = prefixes.iter().map(|p| 1u128 << (32 - u32::from(*p))).sum();
        let result = CloudflareRanges::parse(&ranges);
        if total <= MAX_V4_COVERAGE {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(result, Err(RangeError::TooLarge));
        }
    }

    #[test]
    fn valid_tag_agrees_with_spec(t in proptest::collection::vec(any::<u8>(), 0..1100)) {
        let spec = (1..=MAX_TAG_LEN).contains(&t.len())
            && t.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b',');
        prop_assert_eq!(valid_tag(&t), spec);
    }

    #[test]
    fn printable_tags_are_valid(t in "[!-+\\--~]{1,64}") {
        prop_assert!(valid_tag(t.as_bytes()));
    }

    #[test]
    fn constant_time_eq_finds_one_changed_byte(a in proptest::collection::vec(any::<u8>(), 1..40), index: proptest::sample::Index, flip in 1u8..=255) {
        let mut b = a.clone();
        let i = index.index(b.len());
        b[i] ^= flip;
        prop_assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn header_len_at_the_limit(k in 1usize..20, zeros in 0usize..3, delta in prop_oneof![Just(-1i64), Just(0), Just(1)]) {
        // Lengths that sum (with commas) to MAX - 1, MAX, or MAX + 1.
        let mut lens = vec![0usize; zeros];
        lens.extend(vec![1usize; k - 1]);
        let commas = lens.len() + 1 - 1;
        let used: usize = lens.iter().sum::<usize>() + commas;
        let target = i64::try_from(MAX_HEADER_LEN).expect("fits") + delta;
        let last = usize::try_from(target - i64::try_from(used).expect("fits")).expect("non-negative");
        lens.push(last);
        let spec: usize = lens.iter().sum::<usize>() + lens.len() - 1;
        prop_assert_eq!(i64::try_from(spec).expect("fits"), target);
        let got = tags_header_len(&lens);
        if delta <= 0 {
            prop_assert_eq!(got, Some(spec));
        } else {
            prop_assert_eq!(got, None);
        }
    }

    #[test]
    fn coverage_within_agrees_with_spec(sizes in proptest::collection::vec(prop_oneof![0u128..10, any::<u128>()], 0..8), max: u128) {
        let spec = sizes.iter().try_fold(0u128, |acc, s| acc.checked_add(*s)).is_some_and(|t| t <= max);
        prop_assert_eq!(coverage_within(&sizes, max), spec);
    }

    #[test]
    fn header_len_agrees_with_spec(lens in proptest::collection::vec(prop_oneof![Just(0usize), 0usize..3000], 0..30)) {
        let spec: usize = lens.iter().sum::<usize>() + lens.len().saturating_sub(1);
        let got = tags_header_len(&lens);
        if spec <= MAX_HEADER_LEN {
            prop_assert_eq!(got, Some(spec));
        } else {
            prop_assert_eq!(got, None);
        }
    }

    #[test]
    fn batch_count_matches_chunks(n in 0usize..1000, size in 1usize..=150) {
        let items = vec![0u8; n];
        let chunks: Vec<_> = items.chunks(size).collect();
        prop_assert_eq!(batch_count(n, size), chunks.len());
        prop_assert!(chunks.iter().all(|c| !c.is_empty() && c.len() <= size));
    }
}

#[test]
fn decide_has_the_proved_properties_for_all_inputs() {
    for bits in 0..16u8 {
        let (edge, secret, allowed, lock) =
            (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
        let d = decide(edge, secret, allowed, lock);
        // The same properties as the Verus `ensures` clauses.
        assert_eq!(d == Decision::Verified, edge && secret, "{bits:04b}");
        if !lock || allowed {
            assert_ne!(d, Decision::Reject, "{bits:04b}");
        }
        if lock && !allowed && !(edge && secret) {
            assert_eq!(d, Decision::Reject, "{bits:04b}");
        }
    }
}

#[test]
fn limits_match_the_model() {
    assert_eq!(MIN_V4_PREFIX, 8);
    assert_eq!(MIN_V6_PREFIX, 16);
    assert_eq!(MAX_TAG_LEN, 1024);
    assert_eq!(MAX_HEADER_LEN, 16384);
    assert_eq!(MAX_BATCH, 100);
    assert_eq!(MAX_RANGES, 1024);
    assert_eq!(MAX_V4_COVERAGE, 1 << 24);
    assert_eq!(MAX_V6_COVERAGE, 1 << 112);
    assert_eq!(batch_count(0, 1), 0);
    assert_eq!(batch_count(usize::MAX, 1), usize::MAX);
    assert_eq!(batch_count(usize::MAX, 2), usize::MAX / 2 + 1);
}
