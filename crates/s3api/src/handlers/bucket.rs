//! Service and bucket operations, and listings.

use super::*;
use crate::list::{After, Item, page};

pub(crate) async fn list_buckets<R: Remote + 'static>(State(state): State<AppState<R>>) -> Reply {
    xml_reply(xml::list_buckets(&state.engine.list_buckets().await?))
}

pub(crate) async fn bucket_put<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Extension(caller): Extension<Caller>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    if params.contains_key("versioning") {
        return Err(S3Error::not_implemented("versioning cannot be enabled"));
    }

    state.engine.create_bucket(&bucket, Some(caller.0)).await?;
    info!(bucket, "create bucket");
    Ok(reply(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Body::empty())
        .expect("a bucket name is a valid header value"))
}

pub(crate) async fn bucket_delete<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    state.engine.delete_bucket(&bucket).await?;
    info!(bucket, "delete bucket");
    empty(StatusCode::NO_CONTENT)
}

pub(crate) async fn bucket_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
) -> Reply {
    state.engine.bucket(&bucket).await?;
    empty(StatusCode::OK)
}

pub(crate) async fn bucket_get<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, BUCKET_UNSUPPORTED)?;
    state.engine.bucket(&bucket).await?;

    if params.contains_key("versioning") {
        return xml_reply(xml::versioning());
    }
    if params.contains_key("location") {
        return xml_reply(xml::location());
    }
    if params.contains_key("uploads") {
        let uploads = state.uploads.list(&bucket).await?;
        return xml_reply(xml::list_uploads(&bucket, &uploads));
    }

    list_objects(&state, &bucket, &params).await
}

/// ListObjectsV2 with `list-type=2`, ListObjects (v1) without.
async fn list_objects<R: Remote + 'static>(
    state: &AppState<R>,
    bucket: &str,
    params: &BTreeMap<String, String>,
) -> Reply {
    let param = |name: &str| params.get(name).filter(|v| !v.is_empty()).cloned();
    let v2 = params.get("list-type").is_some_and(|t| t == "2");
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = param("delimiter");
    let max_keys = match params.get("max-keys") {
        Some(n) => n
            .parse::<usize>()
            .map_err(|_| S3Error::invalid_argument("max-keys must be a number"))?
            .min(MAX_KEYS),
        None => MAX_KEYS,
    };
    let encoding_type = param("encoding-type");
    if encoding_type.as_deref().is_some_and(|e| e != "url") {
        return Err(S3Error::invalid_argument("encoding-type must be 'url'"));
    }

    let continuation = param("continuation-token");
    let start_after = param("start-after");
    let marker = param("marker").unwrap_or_default();
    let after = match (v2, &continuation) {
        (true, Some(token)) => Some(After::from_token(token)?),
        (true, None) => start_after.clone().map(After::Key),
        (false, _) if marker.is_empty() => None,
        // A v1 NextMarker can be a common prefix: resume after its whole group.
        (false, _)
            if delimiter
                .as_ref()
                .is_some_and(|d| marker.ends_with(d.as_str())) =>
        {
            Some(After::Prefix(marker.clone()))
        }
        (false, _) => Some(After::Key(marker.clone())),
    };

    let objects = state.engine.list(bucket, &prefix).await?;
    let keys: Vec<String> = objects.iter().map(|o| o.key.clone()).collect();
    let page = page(
        &keys,
        &prefix,
        delimiter.as_deref(),
        max_keys,
        after.as_ref(),
    );
    let next = page.next(&keys);

    let encode = |text: &str| match encoding_type {
        Some(_) => form_urlencoded::byte_serialize(text.as_bytes()).collect(),
        None => text.to_string(),
    };
    let mut listed = ListPage {
        bucket: bucket.to_string(),
        prefix: encode(&prefix),
        delimiter: delimiter.as_deref().map(encode),
        max_keys,
        encoding_type: encoding_type.clone(),
        is_truncated: page.truncated,
        objects: Vec::new(),
        common_prefixes: Vec::new(),
    };
    for item in &page.items {
        match item {
            Item::Object(i) => listed.objects.push(ListedObject {
                key: encode(&objects[*i].key),
                size: objects[*i].size,
                etag: etag(&objects[*i]),
                last_modified: objects[*i].last_modified,
            }),
            Item::CommonPrefix(common) => listed.common_prefixes.push(encode(common)),
        }
    }

    if v2 {
        let next_token = next.map(|n| n.token());
        return xml_reply(xml::list_v2(
            &listed,
            continuation,
            next_token,
            start_after.as_deref().map(encode),
        ));
    }

    // S3 gives NextMarker only with a delimiter; without one, clients resume after the last key.
    let next_marker = next.filter(|_| delimiter.is_some()).map(|n| match n {
        After::Key(key) | After::Prefix(key) => encode(&key),
    });
    xml_reply(xml::list_v1(&listed, encode(&marker), next_marker))
}

pub(crate) async fn bucket_post<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path(bucket): Path<String>,
    Query(params): Params,
    body: Bytes,
) -> Reply {
    if !params.contains_key("delete") {
        return Err(S3Error::not_implemented(
            "this POST on a bucket is not supported",
        ));
    }

    state.engine.bucket(&bucket).await?;
    let (keys, quiet) = xml::parse_delete(&body)?;
    if keys.len() > MAX_DELETE_KEYS {
        return Err(S3Error::malformed_xml());
    }

    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for key in keys {
        match state.engine.delete(&bucket, &key).await {
            Ok(()) => deleted.push(key),
            Err(e) => errors.push((key, S3Error::from(e))),
        }
    }

    info!(
        bucket,
        deleted = deleted.len(),
        errors = errors.len(),
        "delete objects"
    );
    xml_reply(xml::delete_result(&deleted, &errors, quiet))
}
