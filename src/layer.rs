//! The Tower layer that checks the edge and sets the client identity.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::response::Response;
use http::Request;
use tower::{Layer, Service};

use crate::ranges::CloudflareRanges;

/// Tower layer from [`CloudflarePlugin::layer`](crate::CloudflarePlugin::layer).
#[derive(Clone, Debug)]
pub struct CloudflareLayer {
    _private: (),
}

impl CloudflareLayer {
    /// The current range list.
    #[must_use]
    pub fn current_ranges(&self) -> Arc<CloudflareRanges> {
        todo!()
    }
}

impl<S> Layer<S> for CloudflareLayer {
    type Service = CloudflareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CloudflareService { inner }
    }
}

/// Tower service from [`CloudflareLayer`].
#[derive(Clone, Debug)]
pub struct CloudflareService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for CloudflareService<S>
where
    S: Service<Request<B>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, _req: Request<B>) -> Self::Future {
        todo!()
    }
}
