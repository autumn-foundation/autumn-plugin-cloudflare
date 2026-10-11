//! Range refresh against a local fake of `GET /client/v4/ips`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use autumn_plugin_cloudflare::__private::{refresh_once, spawn_refresh};
use autumn_plugin_cloudflare::{CloudflarePlugin, CloudflareRanges, RangeError};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use common::{VISITOR, call, request};
use serde_json::{Value, json};

#[derive(Clone)]
struct Fake {
    hits: Arc<AtomicUsize>,
    status: u16,
    body: Value,
}

async fn ips(State(fake): State<Fake>) -> (StatusCode, axum::Json<Value>) {
    fake.hits.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::from_u16(fake.status).expect("status"),
        axum::Json(fake.body),
    )
}

async fn fake_api(status: u16, body: Value) -> (Arc<AtomicUsize>, String) {
    let hits = Arc::new(AtomicUsize::new(0));
    let fake = Fake {
        hits: Arc::clone(&hits),
        status,
        body,
    };
    let router = Router::new()
        .route("/client/v4/ips", get(ips))
        .with_state(fake);
    let addr = common::serve(router).await;
    (hits, format!("http://{addr}/client/v4/ips"))
}

fn good_body() -> Value {
    json!({
        "result": {"ipv4_cidrs": ["198.51.100.0/24"], "ipv6_cidrs": ["2001:db8::/32"], "etag": "e"},
        "success": true, "errors": [], "messages": []
    })
}

#[tokio::test]
async fn refresh_replaces_the_list() {
    let (_, url) = fake_api(200, good_body()).await;
    let layer = CloudflarePlugin::new().layer();
    assert_eq!(refresh_once(&layer, &url).await, Ok(2));
    assert_eq!(
        *layer.current_ranges(),
        CloudflareRanges::parse(["198.51.100.0/24", "2001:db8::/32"]).expect("ranges")
    );
    // The layer uses the new list at once.
    let (_, seen) = call(
        &layer,
        request("198.51.100.9", &[("cf-connecting-ip", VISITOR)]),
    )
    .await;
    assert_eq!(seen.expect("200").addr.as_deref(), Some(VISITOR));
}

#[tokio::test]
async fn unsafe_or_failed_answers_keep_the_last_good_list() {
    let broad = json!({"result": {"ipv4_cidrs": ["0.0.0.0/0"], "ipv6_cidrs": []}, "success": true});
    let failed = json!({"result": null, "success": false, "errors": [{"code": 1, "message": "x"}]});
    for (status, body) in [
        (200, broad),
        (200, failed),
        (503, good_body()),
        (200, json!([])),
    ] {
        let (hits, url) = fake_api(status, body).await;
        let layer = CloudflarePlugin::new().layer();
        let before = layer.current_ranges();
        assert!(refresh_once(&layer, &url).await.is_err());
        assert_eq!(layer.current_ranges(), before);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unreachable_api_is_an_error() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr");
    let layer = CloudflarePlugin::new().layer();
    let err = refresh_once(&layer, &format!("http://{closed}/ips"))
        .await
        .expect_err("closed");
    assert!(matches!(err, RangeError::Api(_)));
    assert_eq!(*layer.current_ranges(), CloudflareRanges::builtin());
}

#[tokio::test]
async fn refresh_task_runs_now_and_at_each_interval() {
    let (hits, url) = fake_api(200, good_body()).await;
    let layer = CloudflarePlugin::new().layer();
    let task = spawn_refresh(layer.clone(), url, Duration::from_millis(50));
    tokio::time::timeout(Duration::from_secs(10), async {
        while hits.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("three refreshes");
    task.abort();
    assert_eq!(layer.current_ranges().ranges().len(), 2);
}

#[tokio::test]
async fn refresh_task_keeps_running_after_a_failure() {
    let (hits, url) = fake_api(503, json!({})).await;
    let layer = CloudflarePlugin::new().layer();
    let task = spawn_refresh(layer.clone(), url, Duration::from_millis(20));
    tokio::time::timeout(Duration::from_secs(10), async {
        while hits.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("two attempts");
    task.abort();
    assert_eq!(*layer.current_ranges(), CloudflareRanges::builtin());
}

#[tokio::test]
async fn plain_http_range_url_is_rejected_for_other_hosts() {
    let layer = CloudflarePlugin::new().layer();
    let err = refresh_once(&layer, "http://api.cloudflare.com/client/v4/ips")
        .await
        .expect_err("insecure");
    assert!(matches!(err, RangeError::Api(_)));
    assert_eq!(*layer.current_ranges(), CloudflareRanges::builtin());
}

#[tokio::test]
async fn failure_keeps_the_last_refreshed_list() {
    let (_, good) = fake_api(200, good_body()).await;
    let layer = CloudflarePlugin::new().layer();
    assert_eq!(refresh_once(&layer, &good).await, Ok(2));
    let refreshed = layer.current_ranges();
    assert_ne!(*refreshed, CloudflareRanges::builtin());
    let (_, bad) = fake_api(503, json!({})).await;
    assert!(refresh_once(&layer, &bad).await.is_err());
    assert_eq!(layer.current_ranges(), refreshed);
}

async fn redirect_to_ips() -> (StatusCode, [(&'static str, &'static str); 1]) {
    (
        StatusCode::TEMPORARY_REDIRECT,
        [("location", "/client/v4/ips")],
    )
}

#[tokio::test]
async fn refresh_does_not_follow_redirects() {
    let hits = Arc::new(AtomicUsize::new(0));
    let fake = Fake {
        hits: Arc::clone(&hits),
        status: 200,
        body: good_body(),
    };
    let router = Router::new()
        .route("/moved", get(redirect_to_ips))
        .route("/client/v4/ips", get(ips))
        .with_state(fake);
    let addr = common::serve(router).await;
    let layer = CloudflarePlugin::new().layer();
    let err = refresh_once(&layer, &format!("http://{addr}/moved"))
        .await
        .expect_err("redirect");
    assert!(matches!(err, RangeError::Api(_)));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(*layer.current_ranges(), CloudflareRanges::builtin());
}
