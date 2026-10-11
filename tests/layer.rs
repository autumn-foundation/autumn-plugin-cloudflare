//! The layer: edge check, identity, anti-spoofing, origin lock, secret.

mod common;

use autumn_plugin_cloudflare::{CloudflarePlugin, CloudflareRanges, PeerSource};
use autumn_web::security::ResolvedClientIdentity;
use axum::body::Body;
use common::{EDGE, OTHER, VISITOR, call, request};
use http::{HeaderName, Request};

fn layer() -> autumn_plugin_cloudflare::CloudflareLayer {
    CloudflarePlugin::new().layer()
}

fn secret_layer(lock: bool) -> autumn_plugin_cloudflare::CloudflareLayer {
    CloudflarePlugin::new()
        .require_header(HeaderName::from_static("x-origin-auth"), "s3cret")
        .lock_origin(lock)
        .layer()
}

// --- AC3: real identity -----------------------------------------------------

#[tokio::test]
async fn verified_request_uses_cf_connecting_ip() {
    let (status, seen) = call(&layer(), request(EDGE, &[("cf-connecting-ip", VISITOR)])).await;
    let seen = seen.expect("200");
    assert_eq!(status, 200);
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert_eq!(seen.cf_client_ip.as_deref(), Some(VISITOR));
    assert_eq!(seen.cf_edge_ip.as_deref(), Some(EDGE));
    assert_eq!(seen.host.as_deref(), Some("example.com"));
}

#[tokio::test]
async fn verified_request_sets_peer_and_forwarded_headers_for_autumn() {
    // Autumn rate limits resolve the IP again from the peer and
    // `X-Forwarded-For`. Both must give the visitor IP.
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[
                ("cf-connecting-ip", VISITOR),
                ("x-forwarded-for", "6.6.6.6, 203.0.113.7"),
                ("x-real-ip", "6.6.6.6"),
                ("cf-visitor", r#"{"scheme":"https"}"#),
                ("x-forwarded-proto", "http"),
            ],
        ),
    )
    .await;
    let seen = seen.expect("200");
    assert_eq!(seen.connect_ip.as_deref(), Some(VISITOR));
    assert_eq!(seen.forwarded_for.as_deref(), Some(VISITOR));
    assert_eq!(seen.forwarded_proto.as_deref(), Some("https"));
    assert!(!seen.headers.iter().any(|h| h == "x-real-ip"));
}

#[tokio::test]
async fn verified_request_uses_the_host_header() {
    let mut req = request(
        EDGE,
        &[
            ("cf-connecting-ip", VISITOR),
            ("x-forwarded-host", "evil.example"),
            ("forwarded", "host=evil.example"),
        ],
    );
    req.extensions_mut()
        .get_mut::<ResolvedClientIdentity>()
        .expect("identity")
        .host = Some("evil.example".to_owned());
    let (_, seen) = call(&layer(), req).await;
    let seen = seen.expect("200");
    assert_eq!(seen.host.as_deref(), Some("example.com"));
    assert!(
        !seen
            .headers
            .iter()
            .any(|h| h == "x-forwarded-host" || h == "forwarded")
    );
}

#[tokio::test]
async fn resolved_source_without_identity_is_direct() {
    let layer = CloudflarePlugin::new()
        .peer_source(PeerSource::Resolved)
        .layer();
    for _ in 0..2 {
        let mut req = request(EDGE, &[("cf-connecting-ip", VISITOR)]);
        req.extensions_mut().remove::<ResolvedClientIdentity>();
        let (_, seen) = call(&layer, req).await;
        assert_eq!(seen.expect("200").cf_client_ip, None);
    }
}

#[tokio::test]
async fn direct_request_keeps_peer_and_forwarded_headers() {
    let (_, seen) = call(&layer(), request(OTHER, &[("x-forwarded-for", "6.6.6.6")])).await;
    let seen = seen.expect("200");
    assert_eq!(seen.connect_ip.as_deref(), Some(OTHER));
    assert_eq!(seen.forwarded_for.as_deref(), Some("6.6.6.6"));
}

#[tokio::test]
async fn ipv6_header_wins_only_over_a_pseudo_ipv4_value() {
    // Pseudo IPv4 "Overwrite Headers": `CF-Connecting-IP` is Class E.
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[
                ("cf-connecting-ip", "240.16.0.1"),
                ("cf-connecting-ipv6", "2001:db8::1"),
            ],
        ),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some("2001:db8::1"));

    // Without Pseudo IPv4, a Worker can set `CF-Connecting-IPv6`. The
    // plugin ignores it.
    for ip in [VISITOR, "2a06:98c0:3600::103"] {
        let (_, seen) = call(
            &layer(),
            request(
                EDGE,
                &[
                    ("cf-connecting-ip", ip),
                    ("cf-connecting-ipv6", "2001:db8::66"),
                ],
            ),
        )
        .await;
        assert_eq!(seen.expect("200").addr.as_deref(), Some(ip));
    }

    // No `CF-Connecting-IP`: the plugin uses the edge IP.
    let (_, seen) = call(
        &layer(),
        request(EDGE, &[("cf-connecting-ipv6", "2001:db8::66")]),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(EDGE));
}

#[tokio::test]
async fn ipv4_value_in_ipv6_header_is_ignored() {
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[
                ("cf-connecting-ip", VISITOR),
                ("cf-connecting-ipv6", "198.51.100.1"),
            ],
        ),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(VISITOR));
}

#[tokio::test]
async fn ipv4_mapped_visitor_ip_is_ipv4() {
    let (_, seen) = call(
        &layer(),
        request(EDGE, &[("cf-connecting-ip", "::ffff:203.0.113.7")]),
    )
    .await;
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert_eq!(seen.forwarded_for.as_deref(), Some(VISITOR));
    assert_eq!(seen.connect_ip.as_deref(), Some(VISITOR));
}

#[tokio::test]
async fn bad_or_missing_header_falls_back_to_the_peer() {
    for headers in [&[("cf-connecting-ip", "not-an-ip")][..], &[][..]] {
        let (_, seen) = call(&layer(), request(EDGE, headers)).await;
        let seen = seen.expect("200");
        assert_eq!(seen.addr.as_deref(), Some(EDGE));
        assert_eq!(seen.cf_client_ip.as_deref(), Some(EDGE));
    }
}

#[tokio::test]
async fn repeated_connecting_ip_header_is_ignored() {
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[("cf-connecting-ip", VISITOR), ("cf-connecting-ip", OTHER)],
        ),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(EDGE));
}

#[tokio::test]
async fn scheme_comes_from_cf_visitor_then_x_forwarded_proto() {
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[
                ("cf-visitor", r#"{"scheme":"https"}"#),
                ("x-forwarded-proto", "http"),
            ],
        ),
    )
    .await;
    let seen = seen.expect("200");
    assert_eq!(seen.scheme.as_deref(), Some("https"));
    assert_eq!(seen.cf_scheme.as_deref(), Some("https"));

    let (_, seen) = call(&layer(), request(EDGE, &[("x-forwarded-proto", "HTTP")])).await;
    assert_eq!(seen.expect("200").scheme.as_deref(), Some("http"));

    let (_, seen) = call(&layer(), request(EDGE, &[("x-forwarded-proto", "gopher")])).await;
    let seen = seen.expect("200");
    assert_eq!(seen.scheme, None);
    assert_eq!(seen.cf_scheme, None);
}

// --- AC5: extractor data ----------------------------------------------------

#[tokio::test]
async fn verified_request_has_cloudflare_data() {
    let (_, seen) = call(
        &layer(),
        request(
            EDGE,
            &[
                ("cf-connecting-ip", VISITOR),
                ("cf-ray", "230b030023ae2822-SJC"),
                ("cf-ipcountry", "US"),
                ("cf-worker", "example.com"),
            ],
        ),
    )
    .await;
    let seen = seen.expect("200");
    assert_eq!(seen.cf_ray.as_deref(), Some("230b030023ae2822-SJC"));
    assert_eq!(seen.cf_country.as_deref(), Some("US"));
    assert_eq!(seen.cf_worker.as_deref(), Some("example.com"));
    // Cloudflare headers stay for a verified request.
    assert!(seen.headers.iter().any(|h| h == "cf-ray"));
}

#[tokio::test]
async fn bad_country_is_ignored() {
    for bad in ["U", "USA", "u$"] {
        let (_, seen) = call(&layer(), request(EDGE, &[("cf-ipcountry", bad)])).await;
        assert_eq!(seen.expect("200").cf_country, None, "{bad}");
    }
}

// --- AC4: anti-spoofing -----------------------------------------------------

#[tokio::test]
async fn direct_request_loses_spoofed_headers_and_keeps_identity() {
    let (status, seen) = call(
        &layer(),
        request(
            OTHER,
            &[
                ("cf-connecting-ip", VISITOR),
                ("CF-Connecting-IPv6", "2001:db8::1"),
                ("cf-ray", "x"),
                ("cf-ipcountry", "US"),
                ("cf-visitor", r#"{"scheme":"https"}"#),
                ("true-client-ip", VISITOR),
                ("x-custom", "kept"),
            ],
        ),
    )
    .await;
    assert_eq!(status, 200);
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(OTHER));
    assert_eq!(seen.scheme, None);
    assert_eq!(seen.cf_client_ip, None);
    assert!(
        seen.headers
            .iter()
            .all(|h| !h.starts_with("cf-") && h != "true-client-ip"),
        "{:?}",
        seen.headers
    );
    assert!(seen.headers.iter().any(|h| h == "x-custom"));
}

// --- AC2: edge check --------------------------------------------------------

#[tokio::test]
async fn ipv4_mapped_peer_is_an_edge() {
    let (_, seen) = call(
        &layer(),
        request("::ffff:104.16.0.1", &[("cf-connecting-ip", VISITOR)]),
    )
    .await;
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert_eq!(seen.cf_edge_ip.as_deref(), Some(EDGE));
}

#[tokio::test]
async fn ipv6_edge_is_an_edge() {
    let (_, seen) = call(
        &layer(),
        request("2606:4700::1", &[("cf-connecting-ip", VISITOR)]),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(VISITOR));
}

#[tokio::test]
async fn custom_ranges_replace_the_builtin_list() {
    let layer = CloudflarePlugin::new()
        .ranges(CloudflareRanges::parse(["198.51.100.0/24"]).expect("ranges"))
        .layer();
    let (_, seen) = call(&layer, request(OTHER, &[("cf-connecting-ip", VISITOR)])).await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(VISITOR));
    let (_, seen) = call(&layer, request(EDGE, &[("cf-connecting-ip", VISITOR)])).await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(EDGE));
}

#[tokio::test]
async fn resolved_peer_source_checks_the_autumn_identity() {
    let layer = CloudflarePlugin::new()
        .peer_source(PeerSource::Resolved)
        .layer();
    // The socket peer is a load balancer. Autumn resolved the edge IP.
    let mut req = request("10.0.0.5", &[("cf-connecting-ip", VISITOR)]);
    req.extensions_mut()
        .get_mut::<ResolvedClientIdentity>()
        .expect("identity")
        .addr = Some(EDGE.parse().expect("ip"));
    let (_, seen) = call(&layer, req).await;
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert_eq!(seen.cf_edge_ip.as_deref(), Some(EDGE));

    // With the socket source, the load balancer is not an edge.
    let mut req = request("10.0.0.5", &[("cf-connecting-ip", VISITOR)]);
    req.extensions_mut()
        .get_mut::<ResolvedClientIdentity>()
        .expect("identity")
        .addr = Some(EDGE.parse().expect("ip"));
    let (_, seen) = call(&CloudflarePlugin::new().layer(), req).await;
    assert_eq!(seen.expect("200").cf_client_ip, None);
}

#[tokio::test]
async fn no_peer_means_direct() {
    let req = Request::builder()
        .uri("/")
        .header("cf-connecting-ip", VISITOR)
        .body(Body::empty())
        .expect("request");
    let (status, seen) = call(&layer(), req).await;
    assert_eq!(status, 200);
    let seen = seen.expect("200");
    assert_eq!(seen.cf_client_ip, None);
    assert!(!seen.headers.iter().any(|h| h == "cf-connecting-ip"));

    let locked = CloudflarePlugin::new().lock_origin(true).layer();
    let req = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("request");
    assert_eq!(call(&locked, req).await.0, 403);
}

#[tokio::test]
async fn verified_request_without_autumn_identity_gets_one() {
    let mut req = request(EDGE, &[("cf-connecting-ip", VISITOR)]);
    req.extensions_mut().remove::<ResolvedClientIdentity>();
    let (_, seen) = call(&layer(), req).await;
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert_eq!(seen.host.as_deref(), Some("example.com"));
}

// --- AC6: origin lock -------------------------------------------------------

#[tokio::test]
async fn origin_lock_rejects_other_peers() {
    let locked = CloudflarePlugin::new().lock_origin(true).layer();
    assert_eq!(call(&locked, request(OTHER, &[])).await.0, 403);
    assert_eq!(call(&locked, request(EDGE, &[])).await.0, 200);
}

#[tokio::test]
async fn origin_lock_lets_allowed_peers_pass_without_cf_headers() {
    let locked = CloudflarePlugin::new()
        .lock_origin(true)
        .allow("10.0.0.0/8".parse().expect("range"))
        .layer();
    let (status, seen) = call(
        &locked,
        request("10.1.2.3", &[("cf-connecting-ip", VISITOR)]),
    )
    .await;
    assert_eq!(status, 200);
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some("10.1.2.3"));
    assert!(!seen.headers.iter().any(|h| h == "cf-connecting-ip"));
}

#[tokio::test]
async fn lock_off_never_rejects() {
    assert_eq!(call(&layer(), request(OTHER, &[])).await.0, 200);
}

// --- AC7: shared secret -----------------------------------------------------

#[tokio::test]
async fn correct_secret_verifies_and_is_removed() {
    let (status, seen) = call(
        &secret_layer(false),
        request(
            EDGE,
            &[("cf-connecting-ip", VISITOR), ("x-origin-auth", "s3cret")],
        ),
    )
    .await;
    assert_eq!(status, 200);
    let seen = seen.expect("200");
    assert_eq!(seen.addr.as_deref(), Some(VISITOR));
    assert!(!seen.headers.iter().any(|h| h == "x-origin-auth"));
}

#[tokio::test]
async fn wrong_or_missing_secret_is_direct() {
    for headers in [
        &[("cf-connecting-ip", VISITOR), ("x-origin-auth", "s3creT")][..],
        &[("cf-connecting-ip", VISITOR), ("x-origin-auth", "s3cret!")][..],
        &[("cf-connecting-ip", VISITOR)][..],
        &[
            ("cf-connecting-ip", VISITOR),
            ("x-origin-auth", "s3cret"),
            ("x-origin-auth", "s3cret"),
        ][..],
    ] {
        let (status, seen) = call(&secret_layer(false), request(EDGE, headers)).await;
        assert_eq!(status, 200);
        let seen = seen.expect("200");
        assert_eq!(seen.addr.as_deref(), Some(EDGE), "{headers:?}");
        assert_eq!(seen.cf_client_ip, None);
        assert!(!seen.headers.iter().any(|h| h == "x-origin-auth"));
        assert!(!seen.headers.iter().any(|h| h == "cf-connecting-ip"));
    }
}

#[tokio::test]
async fn wrong_secret_with_lock_is_rejected() {
    let req = request(EDGE, &[("x-origin-auth", "nope")]);
    assert_eq!(call(&secret_layer(true), req).await.0, 403);
    let req = request(EDGE, &[("x-origin-auth", "s3cret")]);
    assert_eq!(call(&secret_layer(true), req).await.0, 200);
}

#[tokio::test]
async fn secret_header_is_removed_from_direct_requests() {
    let (_, seen) = call(
        &secret_layer(false),
        request(OTHER, &[("x-origin-auth", "s3cret")]),
    )
    .await;
    assert!(
        !seen
            .expect("200")
            .headers
            .iter()
            .any(|h| h == "x-origin-auth")
    );
}

#[tokio::test]
async fn empty_secret_fails_closed() {
    let layer = CloudflarePlugin::new()
        .require_header(HeaderName::from_static("x-origin-auth"), "")
        .layer();
    let (_, seen) = call(
        &layer,
        request(
            EDGE,
            &[("cf-connecting-ip", VISITOR), ("x-origin-auth", "")],
        ),
    )
    .await;
    assert_eq!(seen.expect("200").cf_client_ip, None);
}

#[test]
fn debug_output_hides_the_secret() {
    let text = format!("{:?}", secret_layer(true));
    assert!(!text.contains("s3cret"), "{text}");
    let text = format!(
        "{:?}",
        CloudflarePlugin::new().require_header(HeaderName::from_static("x-origin-auth"), "s3cret")
    );
    assert!(!text.contains("s3cret"), "{text}");
}
