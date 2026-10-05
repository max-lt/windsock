//! S3 API over the engine, with axum.
//!
//! Authentication is SigV4 in the `Authorization` header. The keys come from the
//! configuration, and every key can reach every bucket.

mod auth;
mod error;
mod handlers;
mod list;
mod multipart;
pub mod sigv4;
mod time;
mod xml;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::get;
use engine::Engine;
use remote::Remote;

pub use error::S3Error;

use multipart::Uploads;

/// S3 single PUT limit.
const DEFAULT_MAX_BODY: usize = 5 * 1024 * 1024 * 1024;

pub struct S3Config {
    /// Access key to secret key.
    pub keys: HashMap<String, String>,
    /// Parts of multipart uploads wait here until the complete.
    pub uploads_dir: PathBuf,
    /// Requests with a larger body fail.
    pub max_body: usize,
}

impl S3Config {
    pub fn new(keys: HashMap<String, String>, uploads_dir: impl Into<PathBuf>) -> Self {
        Self {
            keys,
            uploads_dir: uploads_dir.into(),
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

/// The access key of an authenticated request.
#[derive(Clone, Debug)]
pub(crate) struct Caller(pub String);

pub(crate) struct AppState<R> {
    engine: Arc<Engine<R>>,
    keys: Arc<HashMap<String, String>>,
    uploads: Arc<Uploads>,
    max_body: usize,
}

impl<R> Clone for AppState<R> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            keys: self.keys.clone(),
            uploads: self.uploads.clone(),
            max_body: self.max_body,
        }
    }
}

/// The S3 routes. Serve it with `axum::serve`.
pub fn router<R: Remote + 'static>(engine: Arc<Engine<R>>, config: S3Config) -> Router {
    let state = AppState {
        engine,
        keys: Arc::new(config.keys),
        uploads: Arc::new(Uploads::new(config.uploads_dir)),
        max_body: config.max_body,
    };

    let bucket = get(handlers::bucket_get::<R>)
        .put(handlers::bucket_put::<R>)
        .delete(handlers::bucket_delete::<R>)
        .head(handlers::bucket_head::<R>)
        .post(handlers::bucket_post::<R>);
    let object = get(handlers::object_get::<R>)
        .put(handlers::object_put::<R>)
        .delete(handlers::object_delete::<R>)
        .head(handlers::object_head::<R>)
        .post(handlers::object_post::<R>);

    let max_body = state.max_body;

    Router::new()
        .route("/", get(handlers::list_buckets::<R>))
        .route("/{bucket}", bucket.clone())
        // Clients often send a trailing slash on bucket requests.
        .route("/{bucket}/", bucket)
        .route("/{bucket}/{*key}", object)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate::<R>,
        ))
        // Axum caps extracted bodies at 2 MB unless told otherwise.
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
