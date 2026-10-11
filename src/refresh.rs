//! Range refresh from the Cloudflare API.

use std::time::Duration;

use autumn_web::http::Client;
use tokio::time::MissedTickBehavior;

use crate::layer::CloudflareLayer;
use crate::ranges::{CloudflareRanges, RangeError};

/// The time limit for one refresh request.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Get the list from `url`. Replace the layer's list only when the new
/// list is safe. Returns the number of ranges.
///
/// # Errors
///
/// Returns an error when the request fails or the list is not safe.
pub async fn refresh_once(layer: &CloudflareLayer, url: &str) -> Result<usize, RangeError> {
    fetch(&Client::with_timeout(TIMEOUT), layer, url).await
}

async fn fetch(client: &Client, layer: &CloudflareLayer, url: &str) -> Result<usize, RangeError> {
    let response = client
        .get(url)
        .no_retry()
        .no_redirect()
        .send()
        .await
        .map_err(|e| RangeError::Api(e.to_string()))?;
    if !response.is_success() {
        return Err(RangeError::Api(format!("status {}", response.status())));
    }
    let ranges = CloudflareRanges::from_api_json(&response.bytes())?;
    let count = ranges.ranges().len();
    layer.set_ranges(ranges);
    Ok(count)
}

/// Start a task that refreshes now and then at each interval. The task
/// logs failures and continues.
#[must_use]
pub fn spawn_refresh(
    layer: CloudflareLayer,
    url: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = Client::with_timeout(TIMEOUT);
        let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match fetch(&client, &layer, &url).await {
                Ok(count) => tracing::debug!(count, "cloudflare: refreshed the IP ranges"),
                Err(error) => tracing::warn!(
                    %error,
                    "cloudflare: range refresh failed; the plugin keeps the last good list"
                ),
            }
        }
    })
}
