//! Helpers for the tests.

#![allow(dead_code, unreachable_pub)]

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use autumn_plugin_cloudflare::{CloudflareLayer, CloudflareRequest};
use autumn_web::security::ResolvedClientIdentity;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::response::{IntoResponse, Response};
use http::Request;
use tower::{Layer, ServiceExt};

/// A Cloudflare edge IP (in `104.16.0.0/13`).
pub const EDGE: &str = "104.16.0.1";
/// An IP that is not Cloudflare.
pub const OTHER: &str = "198.51.100.20";
/// A visitor IP.
pub const VISITOR: &str = "203.0.113.7";

/// What the inner service saw.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Seen {
    pub addr: Option<String>,
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub cf_client_ip: Option<String>,
    pub cf_edge_ip: Option<String>,
    pub cf_ray: Option<String>,
    pub cf_country: Option<String>,
    pub cf_scheme: Option<String>,
    pub cf_worker: Option<String>,
    pub connect_ip: Option<String>,
    pub forwarded_for: Option<String>,
    pub forwarded_proto: Option<String>,
    pub headers: Vec<String>,
}

fn header(req: &Request<Body>, name: &str) -> Option<String> {
    let values: Vec<&str> = req
        .headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

async fn echo(req: Request<Body>) -> Result<Response, Infallible> {
    let id = req.extensions().get::<ResolvedClientIdentity>();
    let cf = req.extensions().get::<CloudflareRequest>();
    let seen = Seen {
        addr: id.and_then(|i| i.addr).map(|a| a.to_string()),
        host: id.and_then(|i| i.host.clone()),
        scheme: id.and_then(|i| i.scheme.clone()),
        cf_client_ip: cf.map(|c| c.client_ip().to_string()),
        cf_edge_ip: cf.map(|c| c.edge_ip().to_string()),
        cf_ray: cf.and_then(|c| c.ray().map(str::to_owned)),
        cf_country: cf.and_then(|c| c.country().map(str::to_owned)),
        cf_scheme: cf.and_then(|c| c.scheme().map(str::to_owned)),
        cf_worker: cf.and_then(|c| c.worker().map(str::to_owned)),
        connect_ip: req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string()),
        forwarded_for: header(&req, "x-forwarded-for"),
        forwarded_proto: header(&req, "x-forwarded-proto"),
        headers: req
            .headers()
            .keys()
            .map(|k| k.as_str().to_owned())
            .collect(),
    };
    Ok(axum::Json(seen).into_response())
}

/// A request with a socket peer and the identity that Autumn resolved.
pub fn request(peer: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut req = Request::builder().uri("/").header("host", "example.com");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::empty()).expect("request");
    let ip: IpAddr = peer.parse().expect("peer ip");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    req.extensions_mut().insert(ResolvedClientIdentity {
        addr: Some(ip),
        host: Some("example.com".to_owned()),
        scheme: None,
    });
    req
}

/// Send `req` through `layer`. Returns the status and, for `200`, what the
/// inner service saw.
pub async fn call(layer: &CloudflareLayer, req: Request<Body>) -> (u16, Option<Seen>) {
    let svc = layer.layer(tower::service_fn(echo));
    let res = svc.oneshot(req).await.expect("infallible");
    let status = res.status().as_u16();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    let seen = if status == 200 {
        Some(serde_json::from_slice(&body).expect("json"))
    } else {
        None
    };
    (status, seen)
}

/// Serve `router` on a free loopback port.
pub async fn serve(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, router).await });
    addr
}
