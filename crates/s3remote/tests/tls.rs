//! The S3 remote over HTTPS, against a Windsock S3 server behind TLS.

#![cfg(feature = "tls")]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use engine::{Config, Engine};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use remote::{DirRemote, Remote};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use s3remote::{Retry, S3Config, S3Remote};
use tempfile::TempDir;

const ACCESS: &str = "TESTKEY";
const SECRET: &str = "testsecret";
const CA: &[u8] = include_bytes!("fixtures/ca.crt");
const CERT: &[u8] = include_bytes!("fixtures/localhost.crt");
const KEY: &[u8] = include_bytes!("fixtures/localhost.key");

/// A Windsock S3 server with the bucket `bkt`, on HTTPS with the test certificate.
async fn tls_server() -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let remote = Arc::new(DirRemote::open(dir.path().join("remote")).unwrap());
    let engine = Engine::open(
        dir.path().join("engine"),
        remote,
        SigningKey::from_bytes(&[1u8; 32]),
        Config::default(),
    )
    .await
    .unwrap();
    engine.create_bucket("bkt", None).await.unwrap();
    let keys = HashMap::from([(ACCESS.to_string(), SECRET.to_string())]);
    let app = s3api::router(
        Arc::new(engine),
        s3api::S3Config::new(keys, dir.path().join("uploads")),
    );

    let certs = CertificateDer::pem_slice_iter(CERT)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, app) = (acceptor.clone(), app.clone());
            tokio::spawn(async move {
                // A refused handshake ends this connection only.
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                    .await
                    .ok();
            });
        }
    });

    (dir, format!("https://{address}"))
}

fn config(endpoint: &str, prefix: &str, ca_pem: Option<&[u8]>) -> S3Config {
    S3Config {
        endpoint: endpoint.to_string(),
        bucket: "bkt".into(),
        prefix: prefix.into(),
        region: "us-east-1".into(),
        access_key: ACCESS.into(),
        secret_key: SECRET.into(),
        retry: Retry {
            attempts: 2,
            first_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            attempt_timeout: Duration::from_secs(5),
            total: Duration::from_secs(10),
        },
        ca_pem: ca_pem.map(<[u8]>::to_vec),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_https_remote_with_a_private_ca_meets_the_contract() {
    let (_dir, endpoint) = tls_server().await;
    let next = AtomicU32::new(0);

    remote::contract::check(|| {
        let prefix = format!("check-{}/", next.fetch_add(1, Ordering::SeqCst));
        let remote = S3Remote::new(config(&endpoint, &prefix, Some(CA))).unwrap();
        async move { remote }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_certificate_from_an_unknown_ca_is_refused() {
    let (_dir, endpoint) = tls_server().await;
    let remote = S3Remote::new(config(&endpoint, "", None)).unwrap();

    assert!(remote.get("any").await.is_err());
}

#[tokio::test]
async fn test_ca_file_with_no_certificate_is_refused() {
    let result = S3Remote::new(config("https://127.0.0.1:1", "", Some(b"not a pem file")));

    assert!(result.is_err());
}
