//! The purge client against a local fake of the Cloudflare API.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use autumn_plugin_cloudflare::__private::cache_from_lookup;
use autumn_plugin_cloudflare::{ApiToken, CloudflareCache, PurgeError, PurgeReport};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::{Value, json};

const ZONE: &str = "023e105f4ecef8ad9ca31a8372d0c353";

#[derive(Debug, Clone)]
struct Recorded {
    zone: String,
    auth: Option<String>,
    body: Value,
}

#[derive(Clone, Default)]
struct Fake {
    seen: Arc<Mutex<Vec<Recorded>>>,
    replies: Arc<Mutex<VecDeque<(u16, Option<&'static str>, Value)>>>,
}

impl Fake {
    fn reply(&self, status: u16, retry_after: Option<&'static str>, body: Value) {
        self.replies
            .lock()
            .expect("lock")
            .push_back((status, retry_after, body));
    }

    fn seen(&self) -> Vec<Recorded> {
        self.seen.lock().expect("lock").clone()
    }
}

async fn purge(
    State(fake): State<Fake>,
    Path(zone): Path<String>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> impl IntoResponse {
    fake.seen.lock().expect("lock").push(Recorded {
        zone,
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: body.0,
    });
    let next = fake.replies.lock().expect("lock").pop_front();
    let (status, retry_after, body) = next.unwrap_or((
        200,
        None,
        json!({"success": true, "errors": [], "messages": [], "result": {"id": "x"}}),
    ));
    let mut res = (
        StatusCode::from_u16(status).expect("status"),
        axum::Json(body),
    )
        .into_response();
    if let Some(v) = retry_after {
        res.headers_mut()
            .insert("retry-after", v.parse().expect("value"));
    }
    res
}

async fn fake_api() -> (Fake, String) {
    let fake = Fake::default();
    let router = Router::new()
        .route("/client/v4/zones/{zone}/purge_cache", post(purge))
        .with_state(fake.clone());
    let addr = common::serve(router).await;
    (fake, format!("http://{addr}/client/v4"))
}

fn token() -> ApiToken {
    ApiToken::new("tok-123").expect("token")
}

fn cache(base: &str) -> CloudflareCache {
    CloudflareCache::new(ZONE, token())
        .expect("cache")
        .api_base(base)
}

fn urls(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("https://example.com/p/{i}"))
        .collect()
}

#[tokio::test]
async fn urls_are_sent_in_batches_of_100() {
    let (fake, base) = fake_api().await;
    let report = cache(&base).purge_urls(urls(250)).await.expect("purge");
    assert_eq!(
        report,
        PurgeReport {
            requests: 3,
            items: 250
        }
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 3);
    let sizes: Vec<usize> = seen
        .iter()
        .map(|r| r.body["files"].as_array().expect("files").len())
        .collect();
    assert_eq!(sizes, [100, 100, 50]);
    assert!(seen.iter().all(|r| r.zone == ZONE));
    assert!(
        seen.iter()
            .all(|r| r.auth.as_deref() == Some("Bearer tok-123"))
    );
    assert_eq!(seen[0].body["files"][0], "https://example.com/p/0");
    assert_eq!(seen[2].body["files"][49], "https://example.com/p/249");
}

#[tokio::test]
async fn each_kind_has_its_own_body() {
    let (fake, base) = fake_api().await;
    let c = cache(&base);
    c.purge_tags(["post:1", "posts"]).await.expect("tags");
    c.purge_prefixes(["example.com/blog/", "www.example.com/a"])
        .await
        .expect("prefixes");
    c.purge_hosts(["example.com", "img.example.com"])
        .await
        .expect("hosts");
    let report = c.purge_everything().await.expect("everything");
    assert_eq!(
        report,
        PurgeReport {
            requests: 1,
            items: 0
        }
    );
    let bodies: Vec<Value> = fake.seen().into_iter().map(|r| r.body).collect();
    assert_eq!(
        bodies,
        [
            json!({"tags": ["post:1", "posts"]}),
            json!({"prefixes": ["example.com/blog/", "www.example.com/a"]}),
            json!({"hosts": ["example.com", "img.example.com"]}),
            json!({"purge_everything": true}),
        ]
    );
}

#[tokio::test]
async fn empty_input_sends_nothing() {
    let (fake, base) = fake_api().await;
    let report = cache(&base)
        .purge_urls(Vec::<String>::new())
        .await
        .expect("purge");
    assert_eq!(
        report,
        PurgeReport {
            requests: 0,
            items: 0
        }
    );
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn bad_input_is_rejected_before_any_request() {
    let (fake, base) = fake_api().await;
    let c = cache(&base);
    let mut bad_urls = urls(150);
    bad_urls.push("ftp://example.com/x".to_owned());
    for result in [
        c.purge_urls(bad_urls).await,
        c.purge_urls(["example.com/no-scheme"]).await,
        c.purge_urls(["https://example.com/a b"]).await,
        c.purge_urls(["https://"]).await,
        c.purge_tags(["a,b"]).await,
        c.purge_tags([""]).await,
        c.purge_prefixes(["https://example.com/blog"]).await,
        c.purge_prefixes([""]).await,
        c.purge_prefixes(["example.com/a b"]).await,
        c.purge_hosts(["example.com/path"]).await,
        c.purge_hosts([""]).await,
        c.purge_hosts(["exa mple.com"]).await,
    ] {
        assert!(
            matches!(result, Err(PurgeError::InvalidInput(_))),
            "{result:?}"
        );
    }
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn rate_limit_reports_retry_after_and_progress() {
    let (fake, base) = fake_api().await;
    fake.reply(200, None, json!({"success": true, "errors": []}));
    fake.reply(
        429,
        Some("30"),
        json!({"success": false, "errors": [{"code": 10000, "message": "rate limited"}]}),
    );
    let err = cache(&base)
        .purge_urls(urls(250))
        .await
        .expect_err("rate limited");
    match &err {
        PurgeError::RateLimited {
            retry_after,
            purged,
        } => {
            assert_eq!(*retry_after, Some(Duration::from_secs(30)));
            assert_eq!(*purged, 100);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(err.purged(), 100);
    // The client stops after the error.
    assert_eq!(fake.seen().len(), 2);
}

#[tokio::test]
async fn rate_limit_without_retry_after() {
    let (fake, base) = fake_api().await;
    fake.reply(429, Some("soon"), json!({}));
    let err = cache(&base).purge_tags(["a"]).await.expect_err("429");
    assert!(matches!(
        err,
        PurgeError::RateLimited {
            retry_after: None,
            purged: 0
        }
    ));
}

#[tokio::test]
async fn api_errors_carry_the_messages() {
    let (fake, base) = fake_api().await;
    fake.reply(
        400,
        None,
        json!({"success": false, "errors": [{"code": 1012, "message": "Request must contain one of \"purge_everything\""}]}),
    );
    let err = cache(&base).purge_tags(["a"]).await.expect_err("400");
    match &err {
        PurgeError::Api {
            status,
            errors,
            purged,
        } => {
            assert_eq!(*status, 400);
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].code, 1012);
            assert!(errors[0].message.contains("purge_everything"));
            assert_eq!(*purged, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("400"));
}

#[tokio::test]
async fn success_false_is_an_error() {
    let (fake, base) = fake_api().await;
    fake.reply(200, None, json!({"success": false, "errors": []}));
    let err = cache(&base)
        .purge_hosts(["a.example"])
        .await
        .expect_err("fail");
    assert!(matches!(err, PurgeError::Api { status: 200, .. }));
}

#[tokio::test]
async fn bad_json_is_an_error() {
    let (fake, base) = fake_api().await;
    fake.reply(200, None, json!("not an object"));
    let err = cache(&base).purge_tags(["a"]).await.expect_err("fail");
    assert!(matches!(err, PurgeError::Api { status: 200, .. }));
}

#[tokio::test]
async fn server_errors_are_not_retried() {
    let (fake, base) = fake_api().await;
    fake.reply(500, None, json!({"success": false, "errors": []}));
    let err = cache(&base).purge_tags(["a"]).await.expect_err("500");
    assert!(matches!(err, PurgeError::Api { status: 500, .. }));
    assert_eq!(fake.seen().len(), 1);
}

#[tokio::test]
async fn transport_errors_are_reported() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr");
    let err = cache(&format!("http://{closed}/client/v4"))
        .purge_tags(["a"])
        .await
        .expect_err("closed");
    assert!(
        matches!(err, PurgeError::Transport { purged: 0, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("failed"));
}

#[tokio::test]
async fn batch_size_is_limited_to_1_to_100() {
    let (fake, base) = fake_api().await;
    cache(&base)
        .batch_size(10)
        .purge_urls(urls(25))
        .await
        .expect("purge");
    assert_eq!(fake.seen().len(), 3);

    let (fake, base) = fake_api().await;
    cache(&base)
        .batch_size(0)
        .purge_urls(urls(3))
        .await
        .expect("purge");
    assert_eq!(fake.seen().len(), 3);

    let (fake, base) = fake_api().await;
    cache(&base)
        .batch_size(1000)
        .purge_urls(urls(201))
        .await
        .expect("purge");
    assert_eq!(fake.seen().len(), 3);
}

#[tokio::test]
async fn trailing_slash_in_api_base_is_ok() {
    let (fake, base) = fake_api().await;
    cache(&format!("{base}/"))
        .purge_tags(["a"])
        .await
        .expect("purge");
    assert_eq!(fake.seen().len(), 1);
}

#[test]
fn token_and_zone_are_checked() {
    assert!(matches!(
        ApiToken::new(""),
        Err(PurgeError::InvalidInput(_))
    ));
    assert!(matches!(
        ApiToken::new("a\nb"),
        Err(PurgeError::InvalidInput(_))
    ));
    assert!(matches!(
        ApiToken::new("a b"),
        Err(PurgeError::InvalidInput(_))
    ));
    for zone in ["", "../x", "abc/def", "zone?x=1"] {
        assert!(
            matches!(
                CloudflareCache::new(zone, token()),
                Err(PurgeError::InvalidInput(_))
            ),
            "{zone}"
        );
    }
}

#[test]
fn debug_output_hides_the_token() {
    let t = token();
    assert_eq!(format!("{t:?}"), "ApiToken(***)");
    let c = CloudflareCache::new(ZONE, t).expect("cache");
    let text = format!("{c:?}");
    assert!(!text.contains("tok-123"), "{text}");
    assert!(text.contains(ZONE), "{text}");
}

#[test]
fn environment_lookup_builds_a_client() {
    let env = |zone: Option<&'static str>, token: Option<&'static str>| {
        move |name: &str| match name {
            "CLOUDFLARE_ZONE_ID" => zone.map(str::to_owned),
            "CLOUDFLARE_API_TOKEN" => token.map(str::to_owned),
            _ => None,
        }
    };
    assert!(cache_from_lookup(env(Some(ZONE), Some("tok"))).is_ok());
    assert!(matches!(
        cache_from_lookup(env(None, Some("tok"))),
        Err(PurgeError::MissingEnv("CLOUDFLARE_ZONE_ID"))
    ));
    assert!(matches!(
        cache_from_lookup(env(Some(ZONE), None)),
        Err(PurgeError::MissingEnv("CLOUDFLARE_API_TOKEN"))
    ));
    assert!(matches!(
        cache_from_lookup(env(Some("../"), Some("tok"))),
        Err(PurgeError::InvalidInput(_))
    ));
    assert!(
        PurgeError::MissingEnv("CLOUDFLARE_ZONE_ID")
            .to_string()
            .contains("CLOUDFLARE_ZONE_ID")
    );
    assert_eq!(PurgeError::InvalidInput("x".into()).purged(), 0);
}
