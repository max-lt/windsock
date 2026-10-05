//! The behavior every backend must show. Each check takes a fresh, empty remote
//! and panics when the backend breaks the contract. Run all of them with [`check`].

use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;

use crate::{RemoteError, Sweep};

/// Runs every check, each on a remote from `fresh`.
pub async fn check<R, F, Fut>(fresh: F)
where
    R: Sweep + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = R>,
{
    put_get_roundtrip(&fresh().await).await;
    missing_object_is_none(&fresh().await).await;
    put_replaces_object(&fresh().await).await;
    get_range_returns_slice(&fresh().await).await;
    get_range_outside_object_is_rejected(&fresh().await).await;
    list_returns_sorted_keys_under_prefix(&fresh().await).await;
    create_writes_a_new_key(&fresh().await).await;
    create_keeps_the_existing_object(&fresh().await).await;
    concurrent_creates_have_one_winner(Arc::new(fresh().await)).await;
    invalid_key_is_rejected(&fresh().await).await;
    delete_removes_the_object(&fresh().await).await;
    delete_of_a_missing_key_is_ok(&fresh().await).await;
}

pub async fn put_get_roundtrip(remote: &impl Sweep) {
    remote.put("packs/a", Bytes::from("data")).await.unwrap();

    assert_eq!(remote.get("packs/a").await.unwrap().unwrap(), "data");
}

pub async fn missing_object_is_none(remote: &impl Sweep) {
    assert!(remote.get("packs/a").await.unwrap().is_none());
    assert!(remote.get_range("packs/a", 0..1).await.unwrap().is_none());
}

pub async fn put_replaces_object(remote: &impl Sweep) {
    remote.put("heads/a", Bytes::from("old")).await.unwrap();
    remote.put("heads/a", Bytes::from("new")).await.unwrap();

    assert_eq!(remote.get("heads/a").await.unwrap().unwrap(), "new");
}

pub async fn get_range_returns_slice(remote: &impl Sweep) {
    remote
        .put("packs/a", Bytes::from("0123456789"))
        .await
        .unwrap();

    let middle = remote.get_range("packs/a", 2..5).await.unwrap().unwrap();
    let empty = remote.get_range("packs/a", 10..10).await.unwrap().unwrap();

    assert_eq!(middle, "234");
    assert!(empty.is_empty());
}

pub async fn get_range_outside_object_is_rejected(remote: &impl Sweep) {
    remote.put("packs/a", Bytes::from("0123")).await.unwrap();

    assert!(matches!(
        remote.get_range("packs/a", 2..5).await,
        Err(RemoteError::InvalidRange { len: 4, .. })
    ));
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = remote.get_range("packs/a", 3..1).await;
    assert!(matches!(reversed, Err(RemoteError::InvalidRange { .. })));
}

pub async fn list_returns_sorted_keys_under_prefix(remote: &impl Sweep) {
    for key in ["heads/b", "heads/a", "packs/x", "headsx", "log/a/b"] {
        remote.put(key, Bytes::from(key)).await.unwrap();
    }

    assert_eq!(remote.list("heads/").await.unwrap(), ["heads/a", "heads/b"]);
    assert_eq!(
        remote.list("heads").await.unwrap(),
        ["heads/a", "heads/b", "headsx"]
    );
    assert_eq!(
        remote.list("").await.unwrap(),
        ["heads/a", "heads/b", "headsx", "log/a/b", "packs/x"]
    );
    assert!(remote.list("snapshots/").await.unwrap().is_empty());
}

pub async fn create_writes_a_new_key(remote: &impl Sweep) {
    remote.create("log/a", Bytes::from("data")).await.unwrap();

    assert_eq!(remote.get("log/a").await.unwrap().unwrap(), "data");
}

pub async fn create_keeps_the_existing_object(remote: &impl Sweep) {
    remote.put("log/a", Bytes::from("old")).await.unwrap();

    let result = remote.create("log/a", Bytes::from("new")).await;

    assert!(matches!(result, Err(RemoteError::AlreadyExists(_))));
    assert_eq!(remote.get("log/a").await.unwrap().unwrap(), "old");
}

pub async fn concurrent_creates_have_one_winner<R: Sweep + 'static>(remote: Arc<R>) {
    let mut tasks = tokio::task::JoinSet::new();

    for i in 0..8u8 {
        let remote = remote.clone();
        tasks.spawn(async move {
            remote
                .create("log/a", Bytes::from(vec![i]))
                .await
                .map(|()| i)
        });
    }

    let mut winners = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(i) => winners.push(i),
            Err(RemoteError::AlreadyExists(_)) => {}
            Err(e) => panic!("{e}"),
        }
    }

    assert_eq!(winners.len(), 1);
    assert_eq!(
        remote.get("log/a").await.unwrap().unwrap(),
        vec![winners[0]]
    );
}

pub async fn invalid_key_is_rejected(remote: &impl Sweep) {
    for key in ["", "/abs", "a//b", "a/", "../x", "a/../b", ".tmp", "a/.b"] {
        let rejected = |r: Result<(), RemoteError>| matches!(r, Err(RemoteError::InvalidKey(_)));
        assert!(
            rejected(remote.put(key, Bytes::new()).await),
            "{key:?} was accepted by put"
        );
        assert!(
            rejected(remote.create(key, Bytes::new()).await),
            "{key:?} was accepted by create"
        );
        assert!(
            rejected(remote.delete(key).await),
            "{key:?} was accepted by delete"
        );
    }

    for prefix in ["/", "../", "a//"] {
        assert!(
            matches!(remote.list(prefix).await, Err(RemoteError::InvalidKey(_))),
            "{prefix:?} was accepted"
        );
    }
}

pub async fn delete_removes_the_object(remote: &impl Sweep) {
    remote.put("packs/a", Bytes::from("data")).await.unwrap();
    remote.put("packs/b", Bytes::from("data")).await.unwrap();

    remote.delete("packs/a").await.unwrap();

    assert!(remote.get("packs/a").await.unwrap().is_none());
    assert_eq!(remote.list("packs/").await.unwrap(), ["packs/b"]);
}

pub async fn delete_of_a_missing_key_is_ok(remote: &impl Sweep) {
    remote.delete("packs/a").await.unwrap();
}
