//! End-to-end tests: a real Autumn app (`examples/hello.rs`) in a child
//! process. Requests come from `127.0.0.1`. Tests that need a Cloudflare
//! peer set `CLOUDFLARE_RANGES=127.0.0.0/8`.

mod common;

use std::path::{Path as FsPath, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(120);

/// Returns `(target dir, profile dir)` of this test binary.
fn dirs() -> (PathBuf, PathBuf) {
    // current_exe: <target>/<profile>/deps/e2e-<hash>
    let exe = std::env::current_exe().expect("exe");
    let profile_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("profile dir")
        .to_path_buf();
    let target_dir = profile_dir.parent().expect("target dir").to_path_buf();
    (target_dir, profile_dir)
}

/// Builds the example one time, with the profile of this test binary.
fn example_binary() -> &'static FsPath {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let (target_dir, profile_dir) = dirs();
        let mut cmd = Command::new(env!("CARGO"));
        // Remove the variables that cargo set for this test. Build scripts
        // watch some of them, so they cause a full rebuild.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("CARGO_") && key != "CARGO_HOME" {
                cmd.env_remove(key);
            }
        }
        cmd.args(["build", "--quiet", "--example", "hello", "--target-dir"])
            .arg(&target_dir)
            .current_dir(env!("CARGO_MANIFEST_DIR"));
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        assert!(
            cmd.status().expect("cargo build").success(),
            "example build failed"
        );
        profile_dir.join("examples").join("hello")
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// A child app process. Drop stops it.
struct App {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl App {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .stderr(Stdio::null())
            .status();
        for _ in 0..500 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the example with a clean environment and `env`.
fn spawn(env: &[(&str, String)]) -> App {
    let port = free_port();
    let (target_dir, _) = dirs();
    let log_dir = target_dir.join("e2e-logs");
    std::fs::create_dir_all(&log_dir).expect("log dir");
    let log = log_dir.join(format!("app-{port}.log"));
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log file");
    let mut cmd = Command::new(example_binary());
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("AUTUMN_LOG__LEVEL", "warn")
        .env("AUTUMN_SERVER__PORT", port.to_string())
        .env("AUTUMN_SERVER__HOST", "127.0.0.1")
        .env(
            "AUTUMN_SECURITY__TRUSTED_HOSTS__HOSTS",
            "127.0.0.1,localhost",
        )
        .env("AUTUMN_SERVER__PRESTOP_GRACE_SECS", "0")
        .env("AUTUMN_SERVER__SHUTDOWN_TIMEOUT_SECS", "1")
        .current_dir(&log_dir)
        .stdout(out)
        .stderr(err);
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    App {
        child: cmd.spawn().expect("spawn example"),
        port,
        log,
    }
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("json body")
    }
}

async fn send(app: &App, method: &str, path: &str, headers: &[(&str, &str)]) -> Option<Reply> {
    let client = reqwest::Client::new();
    let mut req = client.request(
        method.parse().expect("method"),
        format!("http://127.0.0.1:{}{path}", app.port),
    );
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = req.send().await.ok()?;
    Some(Reply {
        status: res.status().as_u16(),
        headers: res.headers().clone(),
        body: res.text().await.ok()?,
    })
}

/// Waits until the app answers, with the given headers.
async fn ready(app: &App, headers: &[(&str, &str)]) {
    let wait = tokio::time::timeout(WAIT, async {
        loop {
            if send(app, "GET", "/posts/0", headers).await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(wait.is_ok(), "app did not start. Log:\n{}", app.log());
}

fn loopback_is_cloudflare() -> (&'static str, String) {
    ("CLOUDFLARE_RANGES", "127.0.0.0/8".to_owned())
}

#[tokio::test]
async fn visitor_ip_reaches_the_handler_and_the_rate_limit() {
    let app = spawn(&[
        loopback_is_cloudflare(),
        ("AUTUMN_SECURITY__RATE_LIMIT__ENABLED", "true".to_owned()),
        (
            "AUTUMN_SECURITY__RATE_LIMIT__REQUESTS_PER_SECOND",
            "0.01".to_owned(),
        ),
        ("AUTUMN_SECURITY__RATE_LIMIT__BURST", "1".to_owned()),
    ]);
    ready(&app, &[("cf-connecting-ip", "192.0.2.250")]).await;

    let a = [
        ("cf-connecting-ip", "203.0.113.7"),
        ("cf-ray", "8f0e1d2c3b4a5968-AMS"),
        ("cf-ipcountry", "NL"),
        ("cf-visitor", r#"{"scheme":"https"}"#),
    ];
    let first = send(&app, "GET", "/whoami", &a).await.expect("reply");
    assert_eq!(first.status, 200, "{}", first.body);
    let body = first.json();
    assert_eq!(body["client_addr"], "203.0.113.7");
    assert_eq!(body["cloudflare"]["client_ip"], "203.0.113.7");
    assert_eq!(body["cloudflare"]["edge_ip"], "127.0.0.1");
    assert_eq!(body["cloudflare"]["ray"], "8f0e1d2c3b4a5968-AMS");
    assert_eq!(body["cloudflare"]["country"], "NL");
    assert_eq!(body["cloudflare"]["scheme"], "https");

    // The same visitor is now over its limit.
    let second = send(&app, "GET", "/whoami", &a).await.expect("reply");
    assert_eq!(second.status, 429, "{}", second.body);

    // Another visitor through the same edge has its own limit.
    let b = [("cf-connecting-ip", "198.51.100.9")];
    let third = send(&app, "GET", "/whoami", &b).await.expect("reply");
    assert_eq!(third.status, 200, "{}", third.body);
    assert_eq!(third.json()["client_addr"], "198.51.100.9");
}

#[tokio::test]
async fn spoofed_headers_from_other_peers_have_no_effect() {
    let app = spawn(&[]);
    ready(&app, &[]).await;
    let reply = send(
        &app,
        "GET",
        "/whoami",
        &[("cf-connecting-ip", "203.0.113.7"), ("cf-ray", "x")],
    )
    .await
    .expect("reply");
    assert_eq!(reply.status, 200);
    let body = reply.json();
    assert_eq!(body["client_addr"], "127.0.0.1");
    assert_eq!(body["cloudflare"], Value::Null);
}

#[tokio::test]
async fn origin_lock_rejects_other_peers() {
    let app = spawn(&[("CLOUDFLARE_LOCK_ORIGIN", "1".to_owned())]);
    ready(&app, &[]).await;
    let reply = send(&app, "GET", "/whoami", &[]).await.expect("reply");
    assert_eq!(reply.status, 403);
}

#[tokio::test]
async fn shared_secret_is_required() {
    let app = spawn(&[
        loopback_is_cloudflare(),
        ("CLOUDFLARE_ORIGIN_SECRET", "s3cret".to_owned()),
    ]);
    ready(&app, &[]).await;
    let ok = send(
        &app,
        "GET",
        "/whoami",
        &[
            ("cf-connecting-ip", "203.0.113.7"),
            ("x-origin-auth", "s3cret"),
        ],
    )
    .await
    .expect("reply");
    assert_eq!(ok.json()["client_addr"], "203.0.113.7");
    let bad = send(
        &app,
        "GET",
        "/whoami",
        &[
            ("cf-connecting-ip", "203.0.113.7"),
            ("x-origin-auth", "nope"),
        ],
    )
    .await
    .expect("reply");
    assert_eq!(bad.json()["client_addr"], "127.0.0.1");
}

#[tokio::test]
async fn pages_carry_cache_tags() {
    let app = spawn(&[]);
    ready(&app, &[]).await;
    let reply = send(&app, "GET", "/posts/7", &[]).await.expect("reply");
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.headers.get("cache-tag").and_then(|v| v.to_str().ok()),
        Some("post:7,posts")
    );
}

#[derive(Clone, Default)]
struct FakeApi {
    purges: Arc<Mutex<Vec<(String, Value)>>>,
    ip_hits: Arc<AtomicUsize>,
}

async fn fake_purge(
    State(fake): State<FakeApi>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> axum::Json<Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    fake.purges.lock().expect("lock").push((auth, body.0));
    axum::Json(json!({"success": true, "errors": [], "messages": [], "result": {"id": "x"}}))
}

async fn fake_ips(State(fake): State<FakeApi>) -> axum::Json<Value> {
    fake.ip_hits.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({
        "result": {"ipv4_cidrs": ["192.0.2.0/24"], "ipv6_cidrs": ["2001:db8::/32"]},
        "success": true, "errors": [], "messages": []
    }))
}

async fn fake_api() -> (FakeApi, String) {
    let fake = FakeApi::default();
    let router = Router::new()
        .route("/client/v4/zones/{zone}/purge_cache", post(fake_purge))
        .route("/client/v4/ips", get(fake_ips))
        .with_state(fake.clone());
    let addr = common::serve(router).await;
    (fake, format!("http://{addr}/client/v4"))
}

#[tokio::test]
async fn handler_purges_through_the_api() {
    let (fake, base) = fake_api().await;
    let app = spawn(&[
        (
            "CLOUDFLARE_ZONE_ID",
            "023e105f4ecef8ad9ca31a8372d0c353".to_owned(),
        ),
        ("CLOUDFLARE_API_TOKEN", "tok-e2e".to_owned()),
        ("CLOUDFLARE_API_BASE", base),
    ]);
    ready(&app, &[]).await;
    let reply = send(&app, "POST", "/purge/posts", &[])
        .await
        .expect("reply");
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body, "purged 1");
    let purges = fake.purges.lock().expect("lock").clone();
    assert_eq!(
        purges,
        [("Bearer tok-e2e".to_owned(), json!({"tags": ["posts"]}))]
    );
}

#[tokio::test]
async fn ranges_refresh_at_startup() {
    // Loopback starts as an edge. The API list does not have loopback, so
    // after the refresh, loopback requests are direct.
    let (fake, base) = fake_api().await;
    let app = spawn(&[
        loopback_is_cloudflare(),
        ("CLOUDFLARE_RANGES_URL", format!("{base}/ips")),
        ("CLOUDFLARE_REFRESH_SECS", "3600".to_owned()),
    ]);
    ready(&app, &[]).await;
    let found = tokio::time::timeout(WAIT, async {
        loop {
            let reply = send(
                &app,
                "GET",
                "/whoami",
                &[("cf-connecting-ip", "203.0.113.7")],
            )
            .await
            .expect("reply");
            if reply.json()["client_addr"] == "127.0.0.1" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(found.is_ok(), "refresh did not run. Log:\n{}", app.log());
    assert!(fake.ip_hits.load(Ordering::SeqCst) >= 1);
}
