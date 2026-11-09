//! Object operations and multipart uploads.

use super::conditions::{
    Precondition, byte_range, check_conditions, check_copy_headers, copy_source_range,
    not_modified, precondition, write_mode,
};
use super::*;

pub(crate) async fn object_put<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    streamed: Option<Extension<StreamedBody>>,
    headers: HeaderMap,
    body: Body,
) -> Reply {
    let part = params.get("uploadId").zip(params.get("partNumber"));
    only(&params, if part.is_some() { PART_KEYS } else { &[] })?;
    only_read_headers(&headers)?;
    check_copy_headers(&headers)?;
    if let Some(Extension(streamed)) = streamed {
        if let Some((upload_id, number)) = part {
            let part = (upload_id.as_str(), number.as_str());
            let etag = streamed_part(&state, (&bucket, &key), part, body, streamed).await?;
            return Ok(reply(StatusCode::OK)
                .header("etag", xml::quoted(&etag))
                .body(Body::empty())
                .expect("a hex ETag is a valid header value"));
        }
        let mode = write_mode(&headers)?;
        let metadata = metadata(&headers)?;
        let info = streamed_put(&state, &bucket, &key, metadata, mode, body, streamed).await?;
        return Ok(reply(StatusCode::OK)
            .header("etag", xml::quoted(&etag(&info)))
            .body(Body::empty())
            .expect("a hex ETag is a valid header value"));
    }
    // The middleware read this body already: it is in memory.
    let body = axum::body::to_bytes(body, usize::MAX).await.map_err(|_| {
        S3Error::new(
            "IncompleteBody",
            StatusCode::BAD_REQUEST,
            "the body did not arrive whole",
        )
    })?;

    // Every other upload part streams: here only a part copy comes.
    if let Some((upload_id, number)) = part {
        let source = header(&headers, "x-amz-copy-source")
            .ok_or_else(|| S3Error::invalid_argument("a part with no body stream is a copy"))?;
        let part = (upload_id.as_str(), number.as_str());
        return copy_part(&state, source, (&bucket, &key), part, &headers).await;
    }

    let mode = write_mode(&headers)?;
    if let Some(source) = header(&headers, "x-amz-copy-source") {
        return copy_object(&state, source, (&bucket, &key), &headers, mode).await;
    }

    let info = state
        .engine
        .put(&bucket, &key, body, metadata(&headers)?, mode)
        .await?;
    Ok(reply(StatusCode::OK)
        .header("etag", xml::quoted(&etag(&info)))
        .body(Body::empty())
        .expect("a hex ETag is a valid header value"))
}

/// CopyObject: by reference to the stored chunks of the source, or through a spool file.
async fn copy_object<R: Remote + 'static>(
    state: &AppState<R>,
    source: &str,
    (bucket, key): (&str, &str),
    headers: &HeaderMap,
    mode: WriteMode,
) -> Reply {
    let (source_bucket, source_key) = copy_source(source, headers)?;
    let (source_bucket, source_key) = (source_bucket.as_str(), source_key.as_str());

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

    let _slot = copy_slot(state)?;
    let metadata = match replace {
        true => Some(metadata(headers)?),
        false => None,
    };
    // As a GET: with no room in the read budget, a 503 after the wait of the first piece.
    let info = state
        .engine
        .copy(
            (source_bucket, source_key),
            (bucket, key),
            metadata,
            mode,
            FIRST_PIECE_WAIT,
        )
        .await?
        .info;

    xml_reply(xml::copy_result(&etag(&info), info.last_modified))
}

/// The bucket and key of `x-amz-copy-source`. No condition on the source is checked, so a copy
/// that asks for one is refused.
fn copy_source(source: &str, headers: &HeaderMap) -> Result<(String, String), S3Error> {
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-copy-source-if-"))
    {
        return Err(S3Error::not_implemented(
            "conditional copy is not supported",
        ));
    }

    if source.contains("?versionId=") {
        return Err(S3Error::not_implemented(
            "versioned copy sources are not supported",
        ));
    }
    copy_source_path(source)
        .ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))
}

/// The bucket and key of an `x-amz-copy-source` value, percent-decoded.
pub(crate) fn copy_source_path(source: &str) -> Option<(String, String)> {
    let source = form_urlencoded::parse(format!("s={}", source.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let source = source.strip_prefix('/').unwrap_or(&source);
    let (bucket, key) = source.split_once('/')?;
    Some((bucket.to_string(), key.to_string()))
}

/// One of the MAX_COPIES slots of the copies that run at once, or 503.
fn copy_slot<R>(state: &AppState<R>) -> Result<tokio::sync::SemaphorePermit<'_>, S3Error> {
    state.copies.try_acquire().map_err(|_| {
        S3Error::new(
            "SlowDown",
            StatusCode::SERVICE_UNAVAILABLE,
            format!("{} copies run at once: try again", crate::MAX_COPIES),
        )
    })
}

/// UploadPartCopy: a range of the source, read as a GET and written as an upload part. The part
/// ETag is the blake3 hash of its data, as for UploadPart.
async fn copy_part<R: Remote + 'static>(
    state: &AppState<R>,
    source: &str,
    object: (&str, &str),
    (upload_id, number): (&str, &str),
    headers: &HeaderMap,
) -> Reply {
    let (source_bucket, source_key) = copy_source(source, headers)?;
    // A part waits for no buffer room, but a far-ahead clock or a drain stops every write.
    state.engine.check_writes()?;
    let _slot = copy_slot(state)?;
    // The head decides the range; the reader must open the same version, which it then keeps.
    let (mut reader, length, room) = loop {
        let info = state.engine.head(&source_bucket, &source_key).await?;
        let range = copy_source_range(headers, info.size)?;
        let length = range
            .as_ref()
            .map_or(info.size, |range| range.end - range.start);
        // As a GET: with no room in the read budget, a 503 after the wait of the first piece.
        let room = state.engine.read_room(Some(FIRST_PIECE_WAIT)).await?;
        let reader = state
            .engine
            .get_reader(&source_bucket, &source_key, range)
            .await?;
        if reader.info.content_hash == info.content_hash {
            break (reader, length, room);
        }
    };
    let mut part = state
        .uploads
        .begin_part(upload_id, object, number, length)
        .await?;
    let mut room = Some(room);
    loop {
        let held = match room.take() {
            Some(room) => room,
            None => state.engine.piece_room(&mut reader).await?,
        };
        let Some(piece) = state.engine.next_piece(&mut reader).await? else {
            break;
        };
        for piece in piece.chunks(PUT_PIECE) {
            Sink::write(&mut part, piece).await?;
        }
        drop(held);
    }
    let etag = part.finish().await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64);
    xml_reply(xml::copy_part_result(&etag, now))
}

pub(crate) async fn object_get<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
) -> Reply {
    only_read_headers(&headers)?;
    if let Some(upload_id) = params.get("uploadId") {
        only(&params, &["uploadId"])?;
        let parts = state.uploads.parts(upload_id, &bucket, &key).await?;
        return xml_reply(xml::list_parts(&bucket, &key, upload_id, &parts));
    }

    only(&params, RESPONSE_KEYS)?;
    let overrides = response_headers(&params)?;
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
        // With no room in the budget, a 503 before the body: the client retries cleanly.
        let room = state.engine.read_room(Some(FIRST_PIECE_WAIT)).await?;
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
        let mut builder = object_headers(reply(StatusCode::OK), &reader.info, &overrides)
            .header("content-length", length.to_string());
        if let Some(range) = range {
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                "content-range",
                format!("bytes {}-{}/{}", range.start, range.end - 1, info.size),
            );
        }

        return Ok(builder
            .body(object_body(state.engine.clone(), reader, room, bucket, key))
            .expect("object headers are valid"));
    }
}

pub(crate) async fn object_head<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
) -> Reply {
    only(&params, RESPONSE_KEYS)?;
    only_read_headers(&headers)?;
    let overrides = response_headers(&params)?;
    check_conditions(&headers)?;
    let info = state.engine.head(&bucket, &key).await?;
    match precondition(&headers, &info) {
        Precondition::Failed => return Err(S3Error::precondition_failed()),
        Precondition::NotModified => return not_modified(&info),
        Precondition::Proceed => {}
    }

    Ok(object_headers(reply(StatusCode::OK), &info, &overrides)
        .header("content-length", info.size.to_string())
        .body(Body::empty())
        .expect("object headers are valid"))
}

pub(crate) async fn object_delete<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
) -> Reply {
    if let Some(upload_id) = params.get("uploadId") {
        only(&params, &["uploadId"])?;
        state.uploads.abort(upload_id, &bucket, &key).await?;
        return empty(StatusCode::NO_CONTENT);
    }

    only(&params, &[])?;
    state.engine.delete(&bucket, &key).await?;
    empty(StatusCode::NO_CONTENT)
}

/// Streams the parts of a claimed upload to a spool, in pieces of at most 1 MiB, and commits it.
/// The buffer room of the whole object is taken first, so completes that start together cannot
/// pass the buffer limit together. The hash of the spool, made as it is written, is the content
/// hash; it goes into the claimed upload before the commit.
async fn complete<R: Remote + 'static>(
    state: &AppState<R>,
    (bucket, key): (&str, &str),
    claimed: &std::path::Path,
    requested: &[(u16, String)],
    mode: WriteMode,
) -> Result<ObjectInfo, S3Error> {
    use tokio::io::AsyncReadExt;

    let plan = state
        .uploads
        .plan(claimed, requested, state.engine.max_object_size())
        .await?;
    let mut spool = state
        .engine
        .begin_put_sized(bucket, key, plan.metadata, mode, plan.size)
        .await?;
    let mut piece = vec![0u8; PUT_PIECE];
    for part in &plan.parts {
        let mut file = tokio::fs::File::open(part)
            .await
            .map_err(|e| S3Error::internal(format!("{}: {e}", part.display())))?;
        loop {
            let size = file
                .read(&mut piece)
                .await
                .map_err(|e| S3Error::internal(format!("{}: {e}", part.display())))?;
            if size == 0 {
                break;
            }
            state.engine.spool_write(&mut spool, &piece[..size]).await?;
            engine::sim::crash_point(Point::CompleteAssembly)?;
        }
    }
    if spool.len() != plan.size {
        return Err(S3Error::internal(format!(
            "the parts hold {} bytes, and {} at the start of the complete",
            spool.len(),
            plan.size
        )));
    }
    state.uploads.mark(claimed, spool.content_hash()).await?;
    engine::sim::crash_point(Point::CompleteMarked)?;
    Ok(state.engine.finish_put(spool).await?)
}

pub(crate) async fn object_post<R: Remote + 'static>(
    State(state): State<AppState<R>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    only_read_headers(&headers)?;
    if params.contains_key("uploads") {
        only(&params, &["uploads"])?;
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
    only(&params, &["uploadId"])?;

    let mode = write_mode(&headers)?;
    let requested = xml::parse_complete(&body)?;
    let _slot = state.uploads.complete_slot()?;
    // One complete owns the upload: a second one at the same time gets NoSuchUpload.
    let claimed = state
        .uploads
        .claim(upload_id, &bucket, &key, Claim::Complete)
        .await?;
    let written = complete(&state, (&bucket, &key), &claimed, &requested, mode).await;
    let info = match written {
        Ok(info) => info,
        Err(e) => {
            state.uploads.unclaim(upload_id, &claimed).await?;
            return Err(e);
        }
    };
    // From here the object is committed: a crash leaves the parts to the next start.
    engine::sim::crash_point(Point::CompleteCommitted)?;
    state.uploads.remove(&claimed).await?;

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
    first: ReadRoom,
    bucket: String,
    key: String,
) -> Body {
    let state = (engine, reader, Some(first), None);
    let pieces =
        futures_util::stream::try_unfold(state, move |(engine, mut reader, first, held)| {
            let (bucket, key) = (bucket.clone(), key.clone());
            async move {
                // hyper polls again once less than 417,792 bytes (8 KiB + 400 KiB) of the last piece
                // wait in its queue: the room of that piece comes back while those bytes stay in
                // memory, so a reader can hold 2 pieces against the room of 1.
                drop::<Option<ReadRoom>>(held);
                let room = match first {
                    Some(room) => room,
                    None => engine.piece_room(&mut reader).await?,
                };
                match engine.next_piece(&mut reader).await {
                    Ok(piece) => Ok(piece.map(|piece| (piece, (engine, reader, None, Some(room))))),
                    Err(e) => {
                        warn!(bucket, key, %e, "GET body cut");
                        Err(e)
                    }
                }
            }
        });
    Body::from_stream(pieces)
}

/// The largest piece that a streamed PUT writes at once: the memory of one PUT.
const PUT_PIECE: usize = 1024 * 1024;

/// Where a streamed body goes, one piece at a time.
trait Sink {
    async fn write(&mut self, piece: &[u8]) -> Result<(), S3Error>;
}

impl<R: Remote + 'static> Sink for (&Engine<R>, &mut PutSpool) {
    async fn write(&mut self, piece: &[u8]) -> Result<(), S3Error> {
        Ok(self.0.spool_write(self.1, piece).await?)
    }
}

impl Sink for PartWriter<'_> {
    async fn write(&mut self, piece: &[u8]) -> Result<(), S3Error> {
        PartWriter::write(self, piece).await?;
        Ok(engine::sim::crash_point(Point::PartWrite)?)
    }
}

/// Reads a body as it arrives, decoded when it is aws-chunked, into `sink` in pieces of at most
/// 1 MiB, and checks it: max_body, Content-Length, x-amz-content-sha256, each chunk and trailer
/// signature, and x-amz-decoded-content-length. The caller commits only after an Ok.
async fn stream_body(
    max_body: usize,
    mut body: Body,
    streamed: StreamedBody,
    sink: &mut impl Sink,
) -> Result<(), S3Error> {
    use http_body_util::BodyExt;
    use sha2::Digest;

    let mut sha256 = streamed.sha256.as_ref().map(|_| sha2::Sha256::new());
    let mut decoder = streamed.chunked;
    let (mut received, mut written) = (0u64, 0u64);
    let incomplete = |message: &str| {
        S3Error::new(
            "IncompleteBody",
            StatusCode::BAD_REQUEST,
            message.to_string(),
        )
    };
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| incomplete("the body did not arrive whole"))?;
        let Ok(frame) = frame.into_data() else {
            continue;
        };
        received += frame.len() as u64;
        let mut decoded = Vec::new();
        let data = match &mut decoder {
            Some(decoder) => {
                decoder
                    .push(&frame, &mut decoded)
                    .map_err(crate::auth::chunk_error)?;
                decoded
            }
            None => vec![&frame[..]],
        };
        for piece in data.iter().flat_map(|data| data.chunks(PUT_PIECE)) {
            // A body with no Content-Length meets the limit only here.
            if written + piece.len() as u64 > max_body as u64 {
                return Err(S3Error::entity_too_large(max_body));
            }
            if let Some(sha256) = &mut sha256 {
                sha256.update(piece);
            }
            sink.write(piece).await?;
            written += piece.len() as u64;
        }
    }
    if streamed.length.is_some_and(|length| length != received) {
        return Err(incomplete("the body did not arrive whole"));
    }
    if let Some(decoder) = &decoder {
        decoder.finish().map_err(crate::auth::chunk_error)?;
        if streamed
            .decoded_length
            .is_some_and(|length| length != written)
        {
            return Err(incomplete(
                "the body is shorter or longer than x-amz-decoded-content-length",
            ));
        }
    }
    if let (Some(expected), Some(sha256)) = (&streamed.sha256, sha256)
        && hex::encode(sha256.finalize()) != *expected
    {
        return Err(S3Error::new(
            "XAmzContentSHA256Mismatch",
            StatusCode::BAD_REQUEST,
            "the body does not match x-amz-content-sha256",
        ));
    }
    Ok(())
}

/// The size that a streamed body declares, for the room it takes at the start.
fn declared(streamed: &StreamedBody) -> u64 {
    match streamed.chunked {
        Some(_) => streamed.decoded_length.unwrap_or(0),
        None => streamed.length.unwrap_or(0),
    }
}

/// A PUT whose body goes to a spool file as it arrives. A cut body or a failed check drops the
/// spool file, and nothing is written.
async fn streamed_put<R: Remote + 'static>(
    state: &AppState<R>,
    bucket: &str,
    key: &str,
    metadata: BTreeMap<String, String>,
    mode: WriteMode,
    body: Body,
    streamed: StreamedBody,
) -> Result<ObjectInfo, S3Error> {
    // The room of a declared body is taken at once, so puts that start together cannot pass the
    // buffer limit in the middle of their bodies.
    let size = declared(&streamed);
    let mut spool = state
        .engine
        .begin_put_sized(bucket, key, metadata, mode, size)
        .await?;
    stream_body(
        state.max_body,
        body,
        streamed,
        &mut (state.engine.as_ref(), &mut spool),
    )
    .await?;
    Ok(state.engine.finish_put(spool).await?)
}

/// An upload part whose body goes to a temporary file as it arrives; it takes its name once the
/// body passed every check. A cut body or a failed check leaves no part and gives the room back.
async fn streamed_part<R: Remote + 'static>(
    state: &AppState<R>,
    object: (&str, &str),
    (upload_id, number): (&str, &str),
    body: Body,
    streamed: StreamedBody,
) -> Result<String, S3Error> {
    // A part waits for no buffer room, but a far-ahead clock or a drain stops every write.
    state.engine.check_writes()?;
    let mut part = state
        .uploads
        .begin_part(upload_id, object, number, declared(&streamed))
        .await?;
    stream_body(state.max_body, body, streamed, &mut part).await?;
    part.finish().await
}
