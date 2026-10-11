//! Ranges, header helpers, cache tags, and the extractor.

use std::net::IpAddr;

use autumn_plugin_cloudflare::__private::{header_ip, strip_cloudflare_headers, visitor_scheme};
use autumn_plugin_cloudflare::{CacheTagError, CacheTags, CloudflareRanges, IpRange, RangeError};
use axum::extract::FromRequestParts;
use axum::response::IntoResponse;
use http::{HeaderMap, HeaderValue};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

// --- AC2: ranges ------------------------------------------------------------

#[test]
fn builtin_list_is_the_published_snapshot() {
    let ranges = CloudflareRanges::builtin();
    let v4 = ranges
        .ranges()
        .iter()
        .filter(|r| r.network().is_ipv4())
        .count();
    let v6 = ranges.ranges().len() - v4;
    assert_eq!((v4, v6), (15, 7));
    for edge in [
        "173.245.48.1",
        "104.16.0.1",
        "104.23.255.255",
        "172.71.255.1",
        "131.0.72.9",
        "2400:cb00::1",
        "2a06:98c7:ffff::1",
        "2c0f:f248::9",
    ] {
        assert!(ranges.contains(ip(edge)), "{edge}");
    }
    for other in [
        "8.8.8.8",
        "104.32.0.1",
        "127.0.0.1",
        "1.1.1.1",
        "2a06:98c8::1",
        "::1",
    ] {
        assert!(!ranges.contains(ip(other)), "{other}");
    }
}

#[test]
fn ipv4_mapped_addresses_match_ipv4_ranges() {
    assert!(CloudflareRanges::builtin().contains(ip("::ffff:162.158.1.1")));
    assert!(!CloudflareRanges::builtin().contains(ip("::ffff:8.8.8.8")));
}

#[test]
fn ip_range_parses_and_displays() {
    let r: IpRange = "104.16.0.0/13".parse().expect("range");
    assert_eq!(r.prefix(), 13);
    assert_eq!(r.network(), ip("104.16.0.0"));
    assert_eq!(r.to_string(), "104.16.0.0/13");
    let single: IpRange = " 10.0.0.1 ".parse().expect("range");
    assert_eq!(single.prefix(), 32);
    assert!(single.contains(ip("10.0.0.1")));
    assert!(!single.contains(ip("10.0.0.2")));
    let v6: IpRange = "2001:db8::/32".parse().expect("range");
    assert!(v6.contains(ip("2001:db8:1::1")));
    assert!(!v6.contains(ip("10.0.0.1")));
    assert!(!r.contains(ip("2001:db8::1")));
    let all: IpRange = "0.0.0.0/0".parse().expect("range");
    assert!(all.contains(ip("8.8.8.8")));
    assert!(!all.contains(ip("::1")));
}

#[test]
fn bad_ranges_are_errors() {
    for bad in [
        "",
        "10.0.0.0/33",
        "::/129",
        "10.0.0/8",
        "abc",
        "10.0.0.0/x",
        "/8",
    ] {
        assert!(
            matches!(bad.parse::<IpRange>(), Err(RangeError::Invalid(_))),
            "{bad}"
        );
    }
}

#[test]
fn range_lists_must_be_safe() {
    assert_eq!(
        CloudflareRanges::parse(Vec::<&str>::new()),
        Err(RangeError::Empty)
    );
    assert!(matches!(
        CloudflareRanges::parse(["0.0.0.0/0"]),
        Err(RangeError::TooBroad(_))
    ));
    assert!(matches!(
        CloudflareRanges::parse(["104.16.0.0/13", "2000::/3"]),
        Err(RangeError::TooBroad(_))
    ));
    assert!(matches!(
        CloudflareRanges::parse(["104.16.0.0/13", "nope"]),
        Err(RangeError::Invalid(_))
    ));
    let ok = CloudflareRanges::parse(["10.0.0.0/8", "2001:db8::/16"]).expect("ok");
    assert_eq!(ok.ranges().len(), 2);
}

#[test]
fn api_json_is_parsed_and_checked() {
    let body = br#"{"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"],"etag":"x"},"success":true,"errors":[],"messages":[]}"#;
    let ranges = CloudflareRanges::from_api_json(body).expect("ranges");
    assert_eq!(ranges.ranges().len(), 2);

    let failed = br#"{"result":null,"success":false,"errors":[{"code":1,"message":"x"}]}"#;
    assert!(matches!(
        CloudflareRanges::from_api_json(failed),
        Err(RangeError::Api(_))
    ));
    assert!(matches!(
        CloudflareRanges::from_api_json(b"not json"),
        Err(RangeError::Api(_))
    ));
    let broad = br#"{"result":{"ipv4_cidrs":["0.0.0.0/1"],"ipv6_cidrs":[]},"success":true}"#;
    assert!(matches!(
        CloudflareRanges::from_api_json(broad),
        Err(RangeError::TooBroad(_))
    ));
    let empty = br#"{"result":{"ipv4_cidrs":[],"ipv6_cidrs":[]},"success":true}"#;
    assert_eq!(
        CloudflareRanges::from_api_json(empty),
        Err(RangeError::Empty)
    );
}

#[test]
fn range_errors_have_text() {
    assert!(
        RangeError::TooBroad("0.0.0.0/0".into())
            .to_string()
            .contains("0.0.0.0/0")
    );
    assert!(!RangeError::Empty.to_string().is_empty());
}

// --- Header helpers ---------------------------------------------------------

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(
            http::HeaderName::from_bytes(k.as_bytes()).expect("name"),
            HeaderValue::from_str(v).expect("value"),
        );
    }
    map
}

#[test]
fn header_ip_reads_one_valid_ip() {
    let h = headers(&[("cf-connecting-ip", " 203.0.113.7 ")]);
    assert_eq!(header_ip(&h, "cf-connecting-ip"), Some(ip("203.0.113.7")));
    let h = headers(&[
        ("cf-connecting-ip", "1.2.3.4"),
        ("cf-connecting-ip", "5.6.7.8"),
    ]);
    assert_eq!(header_ip(&h, "cf-connecting-ip"), None);
    let h = headers(&[("cf-connecting-ip", "1.2.3.4, 5.6.7.8")]);
    assert_eq!(header_ip(&h, "cf-connecting-ip"), None);
    assert_eq!(header_ip(&HeaderMap::new(), "cf-connecting-ip"), None);
    let mut h = HeaderMap::new();
    h.insert(
        "cf-connecting-ip",
        HeaderValue::from_bytes(b"1.2.3.\xff").expect("value"),
    );
    assert_eq!(header_ip(&h, "cf-connecting-ip"), None);
}

#[test]
fn visitor_scheme_reads_cf_visitor_then_x_forwarded_proto() {
    assert_eq!(
        visitor_scheme(&headers(&[("cf-visitor", r#"{"scheme":"https"}"#)])),
        Some("https")
    );
    assert_eq!(
        visitor_scheme(&headers(&[("cf-visitor", r#"{ "scheme" : "HTTP" }"#)])),
        Some("http")
    );
    assert_eq!(
        visitor_scheme(&headers(&[
            ("cf-visitor", "garbage"),
            ("x-forwarded-proto", "https")
        ])),
        Some("https")
    );
    assert_eq!(
        visitor_scheme(&headers(&[("x-forwarded-proto", "https, http")])),
        Some("https")
    );
    assert_eq!(
        visitor_scheme(&headers(&[("cf-visitor", r#"{"scheme":"ws"}"#)])),
        None
    );
    assert_eq!(visitor_scheme(&HeaderMap::new()), None);
}

#[test]
fn strip_removes_only_cloudflare_headers() {
    let mut h = headers(&[
        ("cf-ray", "x"),
        ("CF-Connecting-IP", "1.2.3.4"),
        ("cf-new-header", "y"),
        ("true-client-ip", "1.2.3.4"),
        ("x-forwarded-for", "1.2.3.4"),
        ("cfx", "kept"),
        ("accept", "*/*"),
    ]);
    strip_cloudflare_headers(&mut h);
    let mut names: Vec<_> = h.keys().map(http::HeaderName::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["accept", "cfx", "x-forwarded-for"]);
}

// --- AC9: cache tags --------------------------------------------------------

#[test]
fn cache_tags_join_valid_tags() {
    let tags = CacheTags::new(["post:1", "posts", "user-7"]).expect("tags");
    assert_eq!(tags.as_str(), "post:1,posts,user-7");
    let res = (tags, "ok").into_response();
    assert_eq!(
        res.headers().get("cache-tag").and_then(|v| v.to_str().ok()),
        Some("post:1,posts,user-7")
    );
}

#[test]
fn empty_cache_tags_add_no_header() {
    let tags = CacheTags::new(Vec::<String>::new()).expect("tags");
    assert_eq!(tags.as_str(), "");
    let res = (tags, "ok").into_response();
    assert!(res.headers().get("cache-tag").is_none());
}

#[test]
fn bad_cache_tags_are_errors() {
    let long = "a".repeat(1025);
    for bad in ["", "a b", "a,b", "café", "tab\t", long.as_str()] {
        assert!(
            matches!(CacheTags::new([bad]), Err(CacheTagError::InvalidTag(_))),
            "{bad:?}"
        );
    }
    assert!(CacheTags::new(["a".repeat(1024)]).is_ok());
}

#[test]
fn cache_tag_header_has_a_size_limit() {
    // 16 tags of 1024 bytes and 15 commas: 16399 bytes.
    let tags = vec!["a".repeat(1024); 16];
    assert_eq!(CacheTags::new(&tags), Err(CacheTagError::TooLong));
    // 15 tags of 1024 bytes and 14 commas, then one more of 999: 16384.
    let mut tags = vec!["a".repeat(1024); 15];
    tags.push("b".repeat(16384 - 15 * 1024 - 15));
    assert!(CacheTags::new(&tags).is_ok());
    assert!(!CacheTagError::TooLong.to_string().is_empty());
}

// --- AC5: extractor ---------------------------------------------------------

#[tokio::test]
async fn extractor_rejects_requests_without_cloudflare_data() {
    use autumn_plugin_cloudflare::CloudflareRequest;
    let (mut parts, ()) = http::Request::new(()).into_parts();
    let err = CloudflareRequest::from_request_parts(&mut parts, &())
        .await
        .expect_err("no data");
    assert_eq!(err.into_response().status(), 403);
    let opt =
        <CloudflareRequest as axum::extract::OptionalFromRequestParts<()>>::from_request_parts(
            &mut parts,
            &(),
        )
        .await
        .expect("infallible");
    assert!(opt.is_none());
}
