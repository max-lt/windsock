//! S3 API over the engine, with axum.
//!
//! Authentication is SigV4 in the `Authorization` header or in the query. The keys come from a
//! [`KeyStore`], and every key can reach every bucket.

mod auth;
mod error;
mod handlers;
mod keys;
mod list;
mod multipart;
mod presign;
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
pub use keys::{KEY_STORE_DEADLINE, KeyStore, KeyStoreError, Secret, StaticKeys};
pub use s3proto::sigv4;

pub use multipart::Uploads;

/// S3 single PUT limit.
const DEFAULT_MAX_BODY: usize = 5 * 1024 * 1024 * 1024;

/// The parts of all multipart uploads together: half of the default buffer limit, so plain
/// writes keep room when clients leave uploads open.
pub const DEFAULT_PARTS_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

pub struct S3Config {
    /// The secret keys, asked on every request.
    pub keys: Arc<dyn KeyStore>,
    /// The multipart uploads. Call [`Uploads::start`] before the first request.
    pub uploads: Arc<Uploads>,
    /// Requests with a larger body fail.
    pub max_body: usize,
}

impl S3Config {
    /// A configuration with `keys` fixed at start: access key to secret key.
    pub fn new(keys: HashMap<String, String>, uploads_dir: impl Into<PathBuf>) -> Self {
        Self {
            keys: Arc::new(StaticKeys::new(keys)),
            uploads: Arc::new(Uploads::new(uploads_dir, DEFAULT_PARTS_LIMIT)),
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

/// A PUT of an object whose body the handler streams to a spool file, with the SHA-256 that the
/// client signed, or the decoder of an aws-chunked body.
#[derive(Clone, Debug)]
pub(crate) struct StreamedBody {
    pub sha256: Option<String>,
    /// The Content-Length of the request, when it has one: the encoded length for aws-chunked.
    pub length: Option<u64>,
    /// The decoder of an aws-chunked body, with the chunk signer of the request.
    pub chunked: Option<sigv4::ChunkDecoder>,
    /// `x-amz-decoded-content-length` of an aws-chunked body.
    pub decoded_length: Option<u64>,
}

/// The access key of an authenticated request.
#[derive(Clone, Debug)]
pub(crate) struct Caller(pub String);

pub(crate) struct AppState<R> {
    engine: Arc<Engine<R>>,
    keys: Arc<dyn KeyStore>,
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
        keys: config.keys,
        uploads: config.uploads,
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
