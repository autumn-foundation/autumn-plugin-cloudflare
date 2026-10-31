//! A small Autumn app behind Cloudflare.
//!
//! To run it on your computer, type `cargo run --example hello`.
//! Then open <http://127.0.0.1:3000/whoami>.
//!
//! All environment variables are optional:
//!
//! - `CLOUDFLARE_RANGES`: ranges, separated by commas. The app uses them
//!   instead of the built-in list. Use `127.0.0.0/8` to test on your
//!   computer.
//! - `CLOUDFLARE_LOCK_ORIGIN=1`: return `403` to peers that are not
//!   Cloudflare.
//! - `CLOUDFLARE_ORIGIN_SECRET`: require this value in `x-origin-auth`.
//! - `CLOUDFLARE_RANGES_URL` and `CLOUDFLARE_REFRESH_SECS`: refresh the
//!   ranges from this URL.
//! - `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_API_TOKEN`, and
//!   `CLOUDFLARE_API_BASE`: turn on `POST /purge/{tag}`.

use std::time::Duration;

use autumn_plugin_cloudflare::{
    CacheTags, CloudflareCache, CloudflarePlugin, CloudflareRanges, CloudflareRequest,
};
use autumn_web::extract::ClientAddr;
use autumn_web::prelude::*;
use axum::http::{HeaderName, StatusCode};
use axum::response::IntoResponse;

/// Shows the client IP and the Cloudflare data.
#[get("/whoami")]
async fn whoami(
    addr: Option<ClientAddr>,
    cf: Option<CloudflareRequest>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "client_addr": addr.map(|a| a.ip().to_string()),
        "cloudflare": cf.map(|c| serde_json::json!({
            "client_ip": c.client_ip().to_string(),
            "edge_ip": c.edge_ip().to_string(),
            "ray": c.ray(),
            "country": c.country(),
            "scheme": c.scheme(),
        })),
    }))
}

/// A page with cache tags.
#[get("/posts/{id}")]
async fn post(Path(id): Path<u32>) -> impl IntoResponse {
    let tags = CacheTags::new([format!("post:{id}"), "posts".to_owned()]).expect("valid tags");
    (tags, format!("post {id}"))
}

/// Purges one cache tag. A real app must protect this route.
#[post("/purge/{tag}")]
async fn purge(cache: CloudflareCache, Path(tag): Path<String>) -> (StatusCode, String) {
    match cache.purge_tags([tag]).await {
        Ok(report) => (StatusCode::OK, format!("purged {}", report.items)),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

fn plugin() -> CloudflarePlugin {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let mut plugin = CloudflarePlugin::new();
    if let Some(list) = env("CLOUDFLARE_RANGES") {
        let ranges = CloudflareRanges::parse(list.split(',')).expect("valid CLOUDFLARE_RANGES");
        plugin = plugin.ranges(ranges);
    }
    if env("CLOUDFLARE_LOCK_ORIGIN").as_deref() == Some("1") {
        plugin = plugin.lock_origin(true);
    }
    if let Some(secret) = env("CLOUDFLARE_ORIGIN_SECRET") {
        plugin = plugin.require_header(HeaderName::from_static("x-origin-auth"), secret);
    }
    if let (Some(url), Some(secs)) = (env("CLOUDFLARE_RANGES_URL"), env("CLOUDFLARE_REFRESH_SECS"))
    {
        let secs: u64 = secs.parse().expect("valid CLOUDFLARE_REFRESH_SECS");
        plugin = plugin
            .ranges_url(url)
            .refresh_ranges(Duration::from_secs(secs));
    }
    if env("CLOUDFLARE_ZONE_ID").is_some() {
        let mut cache = CloudflareCache::from_env().expect("valid Cloudflare variables");
        if let Some(base) = env("CLOUDFLARE_API_BASE") {
            cache = cache.api_base(base);
        }
        plugin = plugin.cache(cache);
    }
    plugin
}

#[autumn_web::main]
async fn main() {
    Box::pin(
        autumn_web::app()
            .plugin(plugin())
            .routes(routes![whoami, post, purge])
            .run(),
    )
    .await;
}
