//! Plugin wiring in an Autumn `AppBuilder`.

use std::any::TypeId;
use std::time::Duration;

use autumn_plugin_cloudflare::{ApiToken, CloudflareCache, CloudflareLayer, CloudflarePlugin};

fn layer_count(app: &autumn_web::app::AppBuilder) -> usize {
    app.get_layer_types()
        .into_iter()
        .filter(|t| *t == TypeId::of::<CloudflareLayer>())
        .count()
}

#[test]
fn plugin_adds_one_layer() {
    let app = autumn_web::app().plugin(CloudflarePlugin::new());
    assert_eq!(layer_count(&app), 1);
    assert!(app.has_layer::<CloudflareLayer>());
}

#[test]
fn second_registration_is_a_no_op() {
    let app = autumn_web::app()
        .plugin(CloudflarePlugin::new())
        .plugin(CloudflarePlugin::new().lock_origin(true));
    assert_eq!(layer_count(&app), 1);
    assert_eq!(app.plugin_contracts().len(), 1);
}

#[test]
fn plugin_declares_its_contract() {
    let app = autumn_web::app().plugin(CloudflarePlugin::new());
    let contracts = app.plugin_contracts();
    assert_eq!(contracts.len(), 1);
    let label = contracts[0].label();
    assert!(label.contains("autumn-plugin-cloudflare"), "{label}");
    assert!(
        app.has_plugin(&contracts[0].plugin)
            || app.has_plugin(std::any::type_name::<CloudflarePlugin>())
    );
}

#[test]
fn all_options_build() {
    let cache = CloudflareCache::new("abc123", ApiToken::new("t").expect("token")).expect("cache");
    let app = autumn_web::app().plugin(
        CloudflarePlugin::new()
            .lock_origin(true)
            .allow("10.0.0.0/8".parse().expect("range"))
            .require_header(http::HeaderName::from_static("x-origin-auth"), "s")
            .refresh_ranges(Duration::from_secs(3600))
            .ranges_url("https://api.cloudflare.com/client/v4/ips")
            .cache(cache),
    );
    assert_eq!(layer_count(&app), 1);
}
