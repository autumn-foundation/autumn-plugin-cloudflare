//! Range refresh from the Cloudflare API.

use std::time::Duration;

use crate::layer::CloudflareLayer;
use crate::ranges::RangeError;

/// Get the list from `url`. Replace the layer's list when it is safe.
/// Returns the number of ranges.
///
/// # Errors
///
/// Returns an error when the request fails or the list is not safe.
pub async fn refresh_once(_layer: &CloudflareLayer, _url: &str) -> Result<usize, RangeError> {
    todo!()
}

/// Start a task that refreshes now and then at each interval.
#[must_use]
pub fn spawn_refresh(
    _layer: CloudflareLayer,
    _url: String,
    _interval: Duration,
) -> tokio::task::JoinHandle<()> {
    todo!()
}
