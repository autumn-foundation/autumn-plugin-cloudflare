//! Property tests: the runtime code agrees with the Verus spec in
//! `verification/core.rs`. Proofs cover the model. These tests connect
//! the model to the real code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use autumn_plugin_cloudflare::__private::{
    ClientIpSource, Decision, MAX_BATCH, MAX_HEADER_LEN, MAX_RANGES, MAX_TAG_LEN, MAX_V4_COVERAGE,
    MAX_V6_COVERAGE, MIN_V4_PREFIX, MIN_V6_PREFIX, batch_count, choose_client_ip, constant_time_eq,
    decide, is_pseudo_ipv4, prefix_match_v4, prefix_match_v6, range_is_safe, tags_header_len,
    valid_tag,
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
    fn ip_range_uses_the_twin(n: u32, a: u32, p in 0u8..=32) {
        let range: IpRange = format!("{}/{p}", Ipv4Addr::from(n)).parse().expect("range");
        prop_assert_eq!(range.contains(IpAddr::V4(Ipv4Addr::from(a))), prefix_match_v4(n, p, a));
    }

    #[test]
    fn ip_range_v6_uses_the_twin(n: u128, a: u128, p in 0u8..=128) {
        let range: IpRange = format!("{}/{p}", Ipv6Addr::from(n)).parse().expect("range");
        prop_assert_eq!(range.contains(IpAddr::V6(Ipv6Addr::from(a))), prefix_match_v6(n, p, a));
    }

    #[test]
    fn range_safety_agrees_with_spec(is_v4: bool, p: u8) {
        let spec = if is_v4 {
            (MIN_V4_PREFIX..=32).contains(&p)
        } else {
            (MIN_V6_PREFIX..=128).contains(&p)
        };
        prop_assert_eq!(range_is_safe(is_v4, p), spec);
    }

    #[test]
    fn choose_agrees_with_spec(v6 in proptest::option::of(any::<IpAddr>()), ip in proptest::option::of(ip_strategy()), peer: IpAddr) {
        let (got, source) = choose_client_ip(v6, ip, peer);
        let pseudo = matches!(ip, Some(IpAddr::V4(a)) if u32::from(a) >= 0xf000_0000);
        match (v6, ip) {
            (Some(a @ IpAddr::V6(_)), Some(_)) if pseudo => prop_assert_eq!((got, source), (a, ClientIpSource::ConnectingIpv6)),
            (_, Some(b)) => prop_assert_eq!((got, source), (b, ClientIpSource::ConnectingIp)),
            (_, None) => prop_assert_eq!((got, source), (peer, ClientIpSource::Peer)),
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
    fn header_len_agrees_with_spec(lens in proptest::collection::vec(0usize..3000, 0..30)) {
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
fn decide_agrees_with_spec_for_all_inputs() {
    for bits in 0..16u8 {
        let (edge, secret, allowed, lock) =
            (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
        let spec = if edge && secret {
            Decision::Verified
        } else if lock && !allowed {
            Decision::Reject
        } else {
            Decision::Direct
        };
        assert_eq!(decide(edge, secret, allowed, lock), spec, "{bits:04b}");
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
