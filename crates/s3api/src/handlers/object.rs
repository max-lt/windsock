//! Object operations and multipart uploads.

use super::conditions::{Precondition, byte_range, not_modified, precondition};
use super::*;

pub(crate) async fn object_put<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let (Some(upload_id), Some(number)) = (params.get("uploadId"), params.get("partNumber")) {
        if headers.contains_key("x-amz-copy-source") {
            return Err(S3Error::not_implemented("UploadPartCopy is not supported"));
        }
        let part_etag = state
            .uploads
            .put_part(upload_id, &bucket, &key, number, &body)
            .await?;
        return Ok(reply(StatusCode::OK)
            .header("etag", xml::quoted(&part_etag))
            .body(Body::empty())
            .expect("a hex ETag is a valid header value"));
    }

    if let Some(source) = header(&headers, "x-amz-copy-source") {
        return copy_object(&state, source, &bucket, &key, &headers).await;
    }

    if headers.contains_key("if-match") {
        return Err(S3Error::not_implemented(
            "If-Match on PutObject is not supported",
        ));
    }
    let mode = match header(&headers, "if-none-match") {
        Some("*") => WriteMode::CreateOnly,
        Some(_) => {
            return Err(S3Error::not_implemented(
                "If-None-Match on PutObject takes only '*'",
            ));
        }
        None => WriteMode::Overwrite,
    };

    let info = state
        .engine
        .put(&bucket, &key, body, metadata(&headers), mode)
        .await?;
    Ok(reply(StatusCode::OK)
        .header("etag", xml::quoted(&etag(&info)))
        .body(Body::empty())
        .expect("a hex ETag is a valid header value"))
}

/// CopyObject reads the source and writes it again: the engine has no reference copy.
async fn copy_object<R: Remote + 'static>(
    state: &AppState<R>,
    source: &str,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Reply {
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-copy-source-if-"))
    {
        return Err(S3Error::not_implemented(
            "conditional copy is not supported",
        ));
    }

    let source = form_urlencoded::parse(format!("s={}", source.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let source = source.strip_prefix('/').unwrap_or(&source);
    if source.contains("?versionId=") {
        return Err(S3Error::not_implemented(
            "versioned copy sources are not supported",
        ));
    }
    let (source_bucket, source_key) = source
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))?;

    let replace = match header(headers, "x-amz-metadata-directive") {
        None | Some("COPY") => false,
        Some("REPLACE") => true,
        Some(_) => {
            return Err(S3Error::invalid_argument(
                "x-amz-metadata-directive must be COPY or REPLACE",
            ));
        }
    };
    if !replace && source_bucket == bucket && source_key == key {
        return Err(S3Error::new(
            "InvalidRequest",
            StatusCode::BAD_REQUEST,
            "a copy onto itself must replace the metadata",
        ));
    }

    let object = state.engine.get(source_bucket, source_key, None).await?;
    let metadata = if replace {
        metadata(headers)
    } else {
        object.info.metadata
    };
    let info = state
        .engine
        .put(bucket, key, object.data, metadata, WriteMode::Overwrite)
        .await?;

    xml_reply(xml::copy_result(&etag(&info), info.last_modified))
}

pub(crate) async fn object_get<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let Some(upload_id) = params.get("uploadId") {
        let parts = state.uploads.parts(upload_id, &bucket, &key).await?;
        return xml_reply(xml::list_parts(&bucket, &key, upload_id, &parts));
    }

    // The head decides the preconditions and the range; the read must return the same object.
    loop {
        let info = state.engine.head(&bucket, &key).await?;
        match precondition(&headers, &info) {
            Precondition::Failed => return Err(S3Error::precondition_failed()),
            Precondition::NotModified => return not_modified(&info),
            Precondition::Proceed => {}
        }

        let range = byte_range(&headers, info.size)?;
        let object = state.engine.get(&bucket, &key, range.clone()).await?;
        if object.info.content_hash != info.content_hash {
            continue;
        }

        let mut builder = object_headers(reply(StatusCode::OK), &object.info)
            .header("content-length", object.data.len().to_string());
        if let Some(range) = range {
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                "content-range",
                format!("bytes {}-{}/{}", range.start, range.end - 1, info.size),
            );
        }

        return Ok(builder
            .body(Body::from(object.data))
            .expect("object headers are valid"));
    }
}

pub(crate) async fn object_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Reply {
    let info = state.engine.head(&bucket, &key).await?;
    match precondition(&headers, &info) {
        Precondition::Failed => return Err(S3Error::precondition_failed()),
        Precondition::NotModified => return not_modified(&info),
        Precondition::Proceed => {}
    }

    Ok(object_headers(reply(StatusCode::OK), &info)
        .header("content-length", info.size.to_string())
        .body(Body::empty())
        .expect("object headers are valid"))
}

pub(crate) async fn object_delete<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
) -> Reply {
    reject_unsupported(&params, OBJECT_UNSUPPORTED)?;

    if let Some(upload_id) = params.get("uploadId") {
        state.uploads.abort(upload_id, &bucket, &key).await?;
        return empty(StatusCode::NO_CONTENT);
    }

    state.engine.delete(&bucket, &key).await?;
    empty(StatusCode::NO_CONTENT)
}

pub(crate) async fn object_post<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if params.contains_key("uploads") {
        state.engine.bucket(&bucket).await?;
        let upload_id = state
            .uploads
            .initiate(&bucket, &key, metadata(&headers))
            .await?;
        info!(bucket, key, upload_id, "initiate multipart upload");
        return xml_reply(xml::initiate(&bucket, &key, &upload_id));
    }

    let Some(upload_id) = params.get("uploadId") else {
        return Err(S3Error::not_implemented(
            "this POST on an object is not supported",
        ));
    };

    let requested = xml::parse_complete(&body)?;
    let assembled = state
        .uploads
        .assemble(upload_id, &bucket, &key, &requested)
        .await?;
    let info = state
        .engine
        .put(
            &bucket,
            &key,
            Bytes::from(assembled.data),
            assembled.metadata,
            WriteMode::Overwrite,
        )
        .await?;
    state.uploads.finish(upload_id).await?;

    info!(
        bucket,
        key,
        upload_id,
        parts = requested.len(),
        "complete multipart upload"
    );
    xml_reply(xml::complete(&bucket, &key, &etag(&info)))
}
