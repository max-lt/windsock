//! Object operations and multipart uploads.

use super::conditions::{
    Precondition, byte_range, check_conditions, not_modified, precondition, write_mode,
};
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
        let size = body.len() as u64;
        // A new part replaces the part with its number, so only the growth needs room.
        let grow = size.saturating_sub(state.uploads.part_size(upload_id, number).await);
        state.engine.reserve(grow).await?;
        let (part_etag, replaced) = match state
            .uploads
            .put_part(upload_id, &bucket, &key, number, &body)
            .await
        {
            Ok(done) => done,
            Err(e) => {
                state.engine.release(grow);
                return Err(e);
            }
        };
        state.engine.release((grow + replaced).saturating_sub(size));
        return Ok(reply(StatusCode::OK)
            .header("etag", xml::quoted(&part_etag))
            .body(Body::empty())
            .expect("a hex ETag is a valid header value"));
    }

    if let Some(source) = header(&headers, "x-amz-copy-source") {
        return copy_object(&state, source, &bucket, &key, &headers).await;
    }

    let mode = write_mode(&headers)?;

    let info = state
        .engine
        .put(&bucket, &key, body, metadata(&headers)?, mode)
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
        metadata(headers)?
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

    check_conditions(&headers)?;
    // The head decides the preconditions and the range; the read must return the same object.
    loop {
        let info = state.engine.head(&bucket, &key).await?;
        match precondition(&headers, &info) {
            Precondition::Failed => return Err(S3Error::precondition_failed()),
            Precondition::NotModified => return not_modified(&info),
            Precondition::Proceed => {}
        }

        let range = byte_range(&headers, info.size)?;
        let reader = state
            .engine
            .get_reader(&bucket, &key, range.clone())
            .await?;
        if reader.info.content_hash != info.content_hash {
            continue;
        }

        let length = range
            .as_ref()
            .map_or(info.size, |range| range.end - range.start);
        let mut builder = object_headers(reply(StatusCode::OK), &reader.info)
            .header("content-length", length.to_string());
        if let Some(range) = range {
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                "content-range",
                format!("bytes {}-{}/{}", range.start, range.end - 1, info.size),
            );
        }

        return Ok(builder
            .body(object_body(state.engine.clone(), reader, bucket, key))
            .expect("object headers are valid"));
    }
}

pub(crate) async fn object_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Reply {
    check_conditions(&headers)?;
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
        let freed = state.uploads.abort(upload_id, &bucket, &key).await?;
        state.engine.release(freed);
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
            .initiate(&bucket, &key, metadata(&headers)?)
            .await?;
        info!(bucket, key, upload_id, "initiate multipart upload");
        return xml_reply(xml::initiate(&bucket, &key, &upload_id));
    }

    let Some(upload_id) = params.get("uploadId") else {
        return Err(S3Error::not_implemented(
            "this POST on an object is not supported",
        ));
    };

    let mode = write_mode(&headers)?;
    let requested = xml::parse_complete(&body)?;
    let assembled = state
        .uploads
        .assemble(
            upload_id,
            &bucket,
            &key,
            &requested,
            state.engine.max_object_size(),
        )
        .await?;
    // The put counts the object in the buffer, so its parts must stop to count first.
    let parts = state.uploads.bytes(upload_id).await?;
    state.engine.release(parts);
    let info = state
        .engine
        .put(
            &bucket,
            &key,
            Bytes::from(assembled.data),
            assembled.metadata,
            mode,
        )
        .await;
    let info = match info {
        Ok(info) => info,
        Err(e) => {
            state.engine.reserve_unchecked(parts);
            return Err(e.into());
        }
    };
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

/// The body of a GET, one piece at a time. An error ends the body with an error, so the client
/// sees a cut response and never a short object.
fn object_body<R: Remote + 'static>(
    engine: Arc<Engine<R>>,
    reader: ObjectReader,
    bucket: String,
    key: String,
) -> Body {
    let pieces = futures_util::stream::try_unfold((engine, reader), move |(engine, mut reader)| {
        let (bucket, key) = (bucket.clone(), key.clone());
        async move {
            match engine.next_piece(&mut reader).await {
                Ok(piece) => Ok(piece.map(|piece| (piece, (engine, reader)))),
                Err(e) => {
                    warn!(bucket, key, %e, "GET body cut");
                    Err(e)
                }
            }
        }
    });
    Body::from_stream(pieces)
}
