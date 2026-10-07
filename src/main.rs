//! oxbucket — S3-compatible object storage server (stage 1: bucket CRUD,
//! stage 2: SigV4 header auth).
//!
//! Stage 1 scope (path-style addressing; routes protected by the stage-2
//! SigV4 middleware whenever credentials are configured via the environment):
//! - PUT    /<bucket>        create bucket          -> 200 + `Location: /<bucket>`
//! - HEAD   /<bucket>        bucket exists?         -> 200 / 404 (no body)
//! - DELETE /<bucket>        delete *empty* bucket  -> 204; 409 BucketNotEmpty otherwise
//! - GET    /                ListBuckets XML (ListAllMyBucketsResult)
//! - any    /<bucket>/<key>  404 NoSuchBucket when the bucket is missing
//! - every error body is an S3 XML `<Error>` document with Code + Message
//!
//! Configuration:
//! - `S3RS_PORT` — TCP port (default 7333), bound on 127.0.0.1
//! - `S3RS_DATA` — data directory (default ./data), created at startup
//!
//! Storage layout: one directory per bucket directly under the data dir.
//! Objects are files inside those directories plus sidecar `.meta.json`
//! files (stage 3: PUT/GET/HEAD/DELETE with md5 etags and content-types).

use std::{
    env, fs,
    // Aliased: `Path` (unqualified) below is axum's extractor, not this.
    path::{Path as StdPath, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, Bytes},
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};

mod auth;

mod md5;

const DEFAULT_PORT: u16 = 7333;
const DEFAULT_DATA_DIR: &str = "./data";
const XML_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Shared server state.
#[derive(Clone)]
struct AppState {
    /// Root directory holding one sub-directory per bucket.
    data_dir: PathBuf,
    /// SigV4 credentials and enforcement switch (stage 2).
    auth: auth::Credentials,
}

#[tokio::main]
async fn main() {
    let port: u16 = env::var("S3RS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let data_dir =
        PathBuf::from(env::var("S3RS_DATA").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string()));

    // Buckets are plain directories under the data dir; make sure it exists
    // before the first request arrives.
    fs::create_dir_all(&data_dir)
        .unwrap_or_else(|e| panic!("cannot create data dir {}: {e}", data_dir.display()));

    // Stage 2: read the credential pair. Auth is enforced when the operator
    // configured at least one of S3RS_ACCESS_KEY / S3RS_SECRET_KEY; a bare
    // default environment (tests spawning without credentials) keeps the
    // open stage-1 behavior.
    let credentials = auth::Credentials::from_env();

    let state = AppState {
        data_dir,
        auth: credentials,
    };
    let app = Router::new()
        .route("/", get(list_buckets))
        .route("/{bucket}", any(bucket_endpoint))
        .route("/{bucket}/{*key}", any(object_endpoint))
        .fallback(unknown_resource)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::authorize,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("cannot bind 127.0.0.1:{port}: {e}"));
    println!("oxbucket (s3rs) listening on http://127.0.0.1:{port}");

    axum::serve(listener, app).await.expect("server error");
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET / — ListBuckets.
async fn list_buckets(State(state): State<AppState>) -> Response {
    let entries = match fs::read_dir(&state.data_dir) {
        Ok(entries) => entries,
        Err(err) => return internal_error("could not read data directory", err),
    };

    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();

    let mut buckets = String::new();
    for name in &names {
        let created = bucket_creation_date(&state.data_dir.join(name));
        buckets.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(name),
            created
        ));
    }

    let owner = xml_escape(&owner_id());
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ListAllMyBucketsResult xmlns=\"{XML_NS}\">\
         <Owner><ID>{owner}</ID><DisplayName>{owner}</DisplayName></Owner>\
         <Buckets>{buckets}</Buckets>\
         </ListAllMyBucketsResult>"
    );
    xml_response(StatusCode::OK, body)
}

/// /<bucket> — dispatch on the method (explicit, so HEAD never falls back to
/// the GET handler).
async fn bucket_endpoint(
    method: Method,
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    if method == Method::PUT {
        create_bucket(&state, &bucket)
    } else if method == Method::HEAD {
        head_bucket(&state, &bucket)
    } else if method == Method::DELETE {
        delete_bucket(&state, &bucket)
    } else if method == Method::GET {
        get_bucket(&state, &bucket, query.as_deref())
    } else {
        method_not_allowed(format!("/{bucket}"))
    }
}

/// PUT /<bucket> — CreateBucket: 200, empty body, Location header.
fn create_bucket(state: &AppState, bucket: &str) -> Response {
    if !is_valid_bucket_name(bucket) {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            "The specified bucket is not valid",
            format!("/{bucket}"),
        )
        .into_response();
    }
    // Idempotent: creating an existing bucket owned by us is still 200.
    if let Err(err) = fs::create_dir_all(state.data_dir.join(bucket)) {
        return internal_error("could not create bucket", err);
    }
    let mut res = empty_response(StatusCode::OK);
    // Bucket names are validated above, so this cannot contain bad bytes.
    res.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/{bucket}")).expect("valid header value"),
    );
    res
}

/// HEAD /<bucket> — HeadBucket: 200 if it exists, 404 otherwise (no body).
fn head_bucket(state: &AppState, bucket: &str) -> Response {
    if !is_valid_bucket_name(bucket) || !bucket_dir(state, bucket).is_dir() {
        return ApiError::no_such_bucket(format!("/{bucket}")).into_response();
    }
    empty_response(StatusCode::OK)
}

/// DELETE /<bucket> — DeleteBucket: 204 when empty, 409 when not, 404 if missing.
fn delete_bucket(state: &AppState, bucket: &str) -> Response {
    if !is_valid_bucket_name(bucket) || !bucket_dir(state, bucket).is_dir() {
        return ApiError::no_such_bucket(format!("/{bucket}")).into_response();
    }
    let dir = bucket_dir(state, bucket);
    let not_empty = match fs::read_dir(&dir) {
        Ok(mut entries) => entries.next().is_some(),
        Err(err) => return internal_error("could not read bucket directory", err),
    };
    if not_empty {
        return ApiError::new(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "The bucket you tried to delete is not empty",
            format!("/{bucket}"),
        )
        .into_response();
    }
    match fs::remove_dir(&dir) {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(err) => internal_error("could not delete bucket", err),
    }
}

/// GET /<bucket>?list-type=2 — ListObjectsV2 (stage 4).
///
/// Pinned by tests/list_tests.rs: keys sorted lexicographically; envelope
/// Name/Prefix/KeyCount/MaxKeys/IsTruncated (+ NextContinuationToken only
/// when truncated); Contents(Key, LastModified, ETag *bare* md5 — the
/// quoted form is the GET-object header convention from stage 3; Size,
/// StorageClass); CommonPrefixes(Prefix) rollup under `delimiter`, applied
/// after `prefix` narrowing; `max-keys` (default 1000) truncates the merged
/// key/prefix sequence and returns NextContinuationToken = last emitted
/// key; `continuation-token` resumes strictly after that key. `.meta.json`
/// sidecars never list as keys.
fn get_bucket(state: &AppState, bucket: &str, query: Option<&str>) -> Response {
    if !is_valid_bucket_name(bucket) || !bucket_dir(state, bucket).is_dir() {
        return ApiError::no_such_bucket(format!("/{bucket}")).into_response();
    }
    let p = ListParams::parse(query);

    let mut keys = Vec::new();
    collect_keys(&bucket_dir(state, bucket), "", &mut keys);
    keys.sort(); // String Ord = byte-wise lexicographic, as S3 requires

    let keys = keys
        .into_iter()
        .filter(|k| k.starts_with(&p.prefix))
        .filter(|k| p.start_after.as_deref().map_or(true, |s| k.as_str() > s))
        .filter(|k| p.token.as_deref().map_or(true, |t| k.as_str() > t));

    // Delimiter rollup: every key sharing the first delimiter boundary
    // after the prefix collapses into one CommonPrefixes entry. Sorted keys
    // make each group contiguous, so deduping against the previous entry
    // suffices. The first producing key rides along as the resume anchor.
    let mut entries: Vec<ListEntry> = Vec::new();
    for key in keys {
        let rolled = p.delimiter.as_deref().and_then(|d| {
            key[p.prefix.len()..]
                .find(d)
                .map(|i| key[..p.prefix.len() + i + d.len()].to_string())
        });
        match rolled {
            Some(cp) => {
                let dup = matches!(entries.last(), Some(ListEntry::Prefix(prev, _)) if prev.as_str() == cp);
                if !dup {
                    entries.push(ListEntry::Prefix(cp, key));
                }
            }
            None => entries.push(ListEntry::Key(key)),
        }
    }

    let truncated = p.max_keys > 0 && entries.len() > p.max_keys;
    let page: Vec<ListEntry> = entries.into_iter().take(p.max_keys).collect();
    let next_token = if truncated {
        page.last().map(ListEntry::resume_key).map(str::to_string)
    } else {
        None
    };

    // No inter-tag whitespace anywhere: the tests assert exact adjacent
    // substrings such as <CommonPrefixes><Prefix>photos/</Prefix></CommonPrefixes>.
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"{XML_NS}\">\
         <Name>{}</Name>\
         <Prefix>{}</Prefix>",
        xml_escape(bucket),
        xml_escape(&p.prefix),
    );
    if let Some(d) = &p.delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    if let Some(s) = &p.start_after {
        body.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(s)));
    }
    body.push_str(&format!(
        "<KeyCount>{}</KeyCount><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated>",
        page.len(),
        p.max_keys,
        truncated
    ));
    if let Some(t) = &next_token {
        body.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(t)
        ));
    }
    for entry in &page {
        match entry {
            ListEntry::Key(key) => {
                let path = object_path(state, bucket, key);
                let etag = read_meta(&meta_path(state, bucket, key))
                    .map(|m| m.etag)
                    .unwrap_or_else(|_| md5::md5_hex(&fs::read(&path).unwrap_or_default()));
                let modified = fs::metadata(&path)
                    .ok()
                    .and_then(|md| md.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| format_epoch(d.as_secs()))
                    .unwrap_or_else(|| format_epoch(0));
                let size = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
                body.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified>\
                     <ETag>{}</ETag><Size>{}</Size>\
                     <StorageClass>STANDARD</StorageClass></Contents>",
                    xml_escape(key),
                    modified,
                    xml_escape(&etag),
                    size
                ));
            }
            ListEntry::Prefix(cp, _) => body.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(cp)
            )),
        }
    }
    body.push_str("</ListBucketResult>");
    xml_response(StatusCode::OK, body)
}

/// One listing entry: an object key, or a delimiter-rolled common prefix
/// carrying the first key that produced it as the resume anchor.
enum ListEntry {
    Key(String),
    Prefix(String, String),
}

impl ListEntry {
    /// The key a continuation token must resume strictly after.
    fn resume_key(&self) -> &str {
        match self {
            ListEntry::Key(key) => key,
            ListEntry::Prefix(_, anchor) => anchor,
        }
    }
}

/// Parsed ListObjectsV2 query parameters. Hand-parsed: a serde query
/// extractor would pull in serde_urlencoded for no gain (minimal-deps pin).
struct ListParams {
    prefix: String,
    delimiter: Option<String>,
    max_keys: usize,
    start_after: Option<String>,
    token: Option<String>,
}

impl ListParams {
    fn parse(query: Option<&str>) -> Self {
        let mut p = ListParams {
            prefix: String::new(),
            delimiter: None,
            max_keys: 1000, // S3 default and service cap
            start_after: None,
            token: None,
        };
        let Some(q) = query else { return p };
        for pair in q.split('&') {
            let (name, value) = match pair.split_once('=') {
                Some((n, v)) => (n, percent_decode(v)),
                None => (pair, String::new()),
            };
            match name {
                "prefix" => p.prefix = value,
                "delimiter" => p.delimiter = Some(value).filter(|d| !d.is_empty()),
                "max-keys" => p.max_keys = value.parse().unwrap_or(1000).min(1000),
                "start-after" => p.start_after = Some(value),
                "continuation-token" => p.token = Some(value),
                _ => {} // list-type and anything else: the v2 shape is always served
            }
        }
        p
    }
}

/// Recursively collect object keys under a bucket directory: the relative
/// path of every data file. Sidecar `<key>.meta.json` files are never keys.
/// (Accepted ambiguity of the pinned sidecar layout: a PUT of the literal
/// key `x.meta.json` shares its data path with `x`'s sidecar and is hidden.)
fn collect_keys(dir: &StdPath, rel: &str, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // non-UTF-8 names cannot be S3 keys here
        };
        let child = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let path = entry.path();
        if path.is_dir() {
            collect_keys(&path, &child, out);
        } else if !child.ends_with(".meta.json") {
            out.push(child);
        }
    }
}

/// Percent-decode a query parameter value (%XX pairs). `+` is left alone:
/// S3 query parameters are not form-encoded.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = if bytes[i] == b'%' && i + 2 < bytes.len() {
            std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        match decoded {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// /<bucket>/<key> — object core (stage 3): PUT/GET/HEAD/DELETE. An unknown
/// bucket answers 404 NoSuchBucket for every method; an unusable key is a
/// 400 (the key guard doubles as the traversal guard, like the bucket-name
/// validator).
async fn object_endpoint(
    method: Method,
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_valid_bucket_name(&bucket) || !bucket_dir(&state, &bucket).is_dir() {
        return ApiError::no_such_bucket(format!("/{bucket}/{key}")).into_response();
    }
    if !is_valid_key(&key) {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The specified key is not valid",
            format!("/{bucket}/{key}"),
        )
        .into_response();
    }
    // Explicit dispatch, mirroring bucket_endpoint, so HEAD never falls back
    // to the GET handler.
    if method == Method::PUT {
        // CopyObject (stage 5): a body-less PUT carrying x-amz-copy-source.
        // The header is listed in SignedHeaders, so verify() above already
        // folded it into the signature check.
        if let Some(source) = headers
            .get("x-amz-copy-source")
            .and_then(|value| value.to_str().ok())
        {
            return copy_object(
                &state,
                &bucket,
                &key,
                source,
                &format!("/{bucket}/{key}"),
            );
        }
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(DEFAULT_CONTENT_TYPE)
            .to_string();
        put_object(&state, &bucket, &key, &body, &content_type)
    } else if method == Method::GET {
        get_object(&state, &bucket, &key, &format!("/{bucket}/{key}"))
    } else if method == Method::HEAD {
        head_object(&state, &bucket, &key, &format!("/{bucket}/{key}"))
    } else if method == Method::DELETE {
        delete_object(&state, &bucket, &key)
    } else {
        method_not_allowed(format!("/{bucket}/{key}"))
    }
}

/// PUT /<bucket>/<key> — PutObject: store the bytes plus the sidecar
/// `.meta.json` (etag + content-type), answer 200 with the ETag header.
fn put_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    body: &[u8],
    content_type: &str,
) -> Response {
    let path = object_path(state, bucket, key);
    // Nested keys ("a/b") live in sub-directories; create them on demand.
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return internal_error("could not create object directory", err);
        }
    }
    if let Err(err) = fs::write(&path, body) {
        return internal_error("could not write object", err);
    }
    let meta = ObjectMeta {
        etag: md5::md5_hex(body),
        content_type: content_type.to_string(),
    };
    if let Err(err) = write_meta(&meta_path(state, bucket, key), &meta) {
        return internal_error("could not write object metadata", err);
    }
    let mut res = empty_response(StatusCode::OK);
    res.headers_mut()
        .insert(header::ETAG, quoted_etag(&meta.etag));
    res
}

/// PUT /<bucket>/<key> with x-amz-copy-source — CopyObject (stage 5).
///
/// Pinned by tests/copy_tests.rs: the source spec is `[ / ]<bucket>/<key>`
/// (URL-encoded, optional leading slash, optional `?versionId` suffix that
/// is split off before decoding); the bytes AND the `.meta.json` sidecar
/// (content-type + etag) are copied to the destination, overwriting any
/// object already there. Answers 200 with CopyObjectResult XML whose ETag
/// is the *bare* md5 (the ListObjectsV2 convention) plus LastModified. A
/// missing source (bucket or key) is a 404 NoSuchKey; copying an object
/// onto itself is an allowed no-op rewrite.
fn copy_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    source: &str,
    resource: &str,
) -> Response {
    // A literal '?' in a key always travels percent-encoded, so the first
    // raw '?' starts the versionId suffix — split it off BEFORE decoding.
    let source = source.split('?').next().unwrap_or(source);
    let decoded = percent_decode(source);
    let decoded = decoded.strip_prefix('/').unwrap_or(decoded.as_str());
    let Some((src_bucket, src_key)) = decoded.split_once('/') else {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-copy-source must be <bucket>/<key>",
            resource.to_string(),
        )
        .into_response();
    };
    if !is_valid_key(src_key) {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The specified copy source key is not valid",
            resource.to_string(),
        )
        .into_response();
    }

    let src = object_path(state, src_bucket, src_key);
    let dst = object_path(state, bucket, key);
    // Copying onto itself would read and truncate the same file, so it is
    // an allowed no-op: keep the existing bytes and sidecar.
    if src != dst {
        // Missing source bucket or key -> 404 NoSuchKey, as pinned.
        if let Err(err) = fs::metadata(&src) {
            if err.kind() == std::io::ErrorKind::NotFound {
                return ApiError::no_such_key(resource).into_response();
            }
            return internal_error("could not stat copy source", err);
        }
        if let Some(parent) = dst.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return internal_error("could not create object directory", err);
            }
        }
        if let Err(err) = fs::copy(&src, &dst) {
            return internal_error("could not copy object bytes", err);
        }
        // Equal bytes carry the same etag; the sidecar is copied wholesale
        // so content-type and etag travel with them.
        if let Err(err) =
            fs::copy(meta_path(state, src_bucket, src_key), meta_path(state, bucket, key))
        {
            return internal_error("could not copy object metadata", err);
        }
    }

    let body = fs::read(&dst).unwrap_or_default();
    let etag = read_meta(&meta_path(state, bucket, key))
        .map(|meta| meta.etag)
        .unwrap_or_else(|_| md5::md5_hex(&body));
    let modified = fs::metadata(&dst)
        .ok()
        .and_then(|md| md.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| format_epoch(d.as_secs()))
        .unwrap_or_else(|| format_epoch(0));
    xml_response(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <CopyObjectResult xmlns=\"{XML_NS}\">\
             <ETag>{}</ETag>\
             <LastModified>{}</LastModified>\
             </CopyObjectResult>",
            xml_escape(&etag),
            modified
        ),
    )
}

/// GET /<bucket>/<key> — GetObject: 200 with the stored bytes plus
/// Content-Type and the quoted-md5 ETag; 404 NoSuchKey when absent.
fn get_object(state: &AppState, bucket: &str, key: &str, resource: &str) -> Response {
    let body = match fs::read(object_path(state, bucket, key)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return ApiError::no_such_key(resource).into_response();
        }
        Err(err) => return internal_error("could not read object", err),
    };
    let meta = match read_meta(&meta_path(state, bucket, key)) {
        Ok(meta) => meta,
        Err(err) => return internal_error("could not read object metadata", err),
    };
    let mut res = Response::new(Body::from(body));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&meta.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_CONTENT_TYPE)),
    );
    res.headers_mut()
        .insert(header::ETAG, quoted_etag(&meta.etag));
    res
}

/// HEAD /<bucket>/<key> — HeadObject: the headers GET would send, no body.
/// (Echoing the object size as Content-Length can wait for a later stage.)
fn head_object(state: &AppState, bucket: &str, key: &str, resource: &str) -> Response {
    let path = object_path(state, bucket, key);
    if let Err(err) = fs::metadata(&path) {
        if err.kind() == std::io::ErrorKind::NotFound {
            return ApiError::no_such_key(resource).into_response();
        }
        return internal_error("could not stat object", err);
    }
    let meta = match read_meta(&meta_path(state, bucket, key)) {
        Ok(meta) => meta,
        Err(err) => return internal_error("could not read object metadata", err),
    };
    let mut res = empty_response(StatusCode::OK);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&meta.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_CONTENT_TYPE)),
    );
    res.headers_mut()
        .insert(header::ETAG, quoted_etag(&meta.etag));
    res
}

/// DELETE /<bucket>/<key> — DeleteObject: 204, idempotent — deleting a key
/// that does not exist is still 204, matching S3.
fn delete_object(state: &AppState, bucket: &str, key: &str) -> Response {
    let path = object_path(state, bucket, key);
    if let Err(err) = fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return internal_error("could not delete object", err);
        }
    }
    if let Err(err) = fs::remove_file(meta_path(state, bucket, key)) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return internal_error("could not delete object metadata", err);
        }
    }
    // A nested key may leave its (now empty) parent directory behind; prune
    // it so delete_bucket's BucketNotEmpty check stays truthful. Harmless
    // when the parent is the bucket directory itself or still has siblings.
    if let Some(parent) = path.parent() {
        if parent != bucket_dir(state, bucket).as_path() {
            let _ = fs::remove_dir(parent);
        }
    }
    empty_response(StatusCode::NO_CONTENT)
}

/// Anything else — keep the pinned invariant that errors are XML documents.
async fn unknown_resource(uri: Uri) -> Response {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "NotFound",
        "The requested resource could not be found",
        uri.path().to_string(),
    )
    .into_response()
}

// ---------------------------------------------------------------------------
// Error documents
// ---------------------------------------------------------------------------

/// An S3-shaped error: rendered as an XML `<Error>` document.
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    resource: String,
}

impl ApiError {
    pub(crate) fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message,
            resource: resource.into(),
        }
    }

    fn no_such_bucket(resource: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            resource,
        )
    }

    fn no_such_key(resource: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist",
            resource,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource>\
             <RequestId>{}</RequestId></Error>",
            self.code,
            xml_escape(self.message),
            xml_escape(&self.resource),
            new_request_id(),
        );
        xml_response(self.status, body)
    }
}

fn internal_error(message: &'static str, err: std::io::Error) -> Response {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        message,
        err.to_string(),
    )
    .into_response()
}

fn method_not_allowed(resource: String) -> Response {
    let mut res = ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        "The specified method is not allowed against this resource",
        resource,
    )
    .into_response();
    res.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("GET, HEAD, PUT, DELETE"),
    );
    res
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn xml_response(status: StatusCode, body: String) -> Response {
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    res
}

fn empty_response(status: StatusCode) -> Response {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = status;
    res
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn bucket_dir(state: &AppState, bucket: &str) -> PathBuf {
    state.data_dir.join(bucket)
}

/// Raw byte path of the object `key` inside `bucket`.
fn object_path(state: &AppState, bucket: &str, key: &str) -> PathBuf {
    bucket_dir(state, bucket).join(key)
}

/// Sidecar `.meta.json` path — the pinned storage layout keeps etag and
/// content-type next to the object bytes. Stage-4 note: listings must skip
/// these names.
fn meta_path(state: &AppState, bucket: &str, key: &str) -> PathBuf {
    let mut name = object_path(state, bucket, key).into_os_string();
    name.push(".meta.json");
    PathBuf::from(name)
}

/// Object-key rules, doubling as the traversal guard like
/// `is_valid_bucket_name` above: reject empty keys, absolute paths, NULs,
/// backslashes (a path separator on the Windows build) and any `..`
/// component that could escape the bucket directory.
fn is_valid_key(key: &str) -> bool {
    if key.is_empty() || key.starts_with('/') || StdPath::new(key).is_absolute() {
        return false;
    }
    if key.bytes().any(|b| b == 0 || b == b'\\') {
        return false;
    }
    !key.split('/').any(|segment| segment == "..")
}

/// Content-type kept when a PUT carries no usable one (S3's binary default).
const DEFAULT_CONTENT_TYPE: &str = "binary/octet-stream";

/// The sidecar's payload: what GET/HEAD need beyond the raw bytes. Stored as
/// a tiny fixed-shape JSON document that the server both writes and reads
/// (`serde_json` is deliberately not a dependency).
struct ObjectMeta {
    etag: String,
    content_type: String,
}

impl ObjectMeta {
    fn to_json(&self) -> String {
        format!(
            "{{\"etag\":\"{}\",\"content_type\":\"{}\"}}",
            json_escape(&self.etag),
            json_escape(&self.content_type)
        )
    }

    fn from_json(text: &str) -> Option<Self> {
        Some(Self {
            etag: json_string_field(text, "etag")?,
            content_type: json_string_field(text, "content_type")?,
        })
    }
}

/// Escape a value for embedding in the sidecar JSON string literal. Etags
/// are hex and content-types are visible ASCII, so the two mandatory
/// escapes plus control characters cover everything.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Read one `"field":"value"` pair back out of a sidecar written by
/// [`ObjectMeta::to_json`], honoring its escapes.
fn json_string_field(text: &str, field: &str) -> Option<String> {
    let marker = format!("\"{field}\":\"");
    let start = text.find(&marker)? + marker.len();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return String::from_utf8(out).ok(),
            b'\\' => {
                i += 1;
                match bytes.get(i) {
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    Some(b'n') => out.push(b'\n'),
                    _ => return None,
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    None
}

fn write_meta(path: &StdPath, meta: &ObjectMeta) -> std::io::Result<()> {
    fs::write(path, meta.to_json())
}

fn read_meta(path: &StdPath) -> std::io::Result<ObjectMeta> {
    let text = fs::read_to_string(path)?;
    ObjectMeta::from_json(&text).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed sidecar metadata")
    })
}

/// ETag header value: lowercase md5 hex in double quotes.
fn quoted_etag(etag: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{etag}\"")).expect("md5 hex is a valid header value")
}

/// S3 bucket-name rules (the subset that matters here): 3-63 chars of
/// lowercase letters, digits, dots and hyphens, starting/ending
/// alphanumerically and never containing "..". Doubles as the traversal
/// guard: names like `..` or containing path separators are rejected before
/// anything touches the filesystem.
fn is_valid_bucket_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if !(3..=63).contains(&bytes.len()) {
        return false;
    }
    let head = bytes[0];
    let tail = bytes[bytes.len() - 1];
    if name.contains("..") || head == b'-' || head == b'.' || tail == b'-' || tail == b'.' {
        return false;
    }
    bytes.iter().all(|&b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
    })
}

/// CreationDate for a bucket directory: birth time when available, falling
/// back to mtime, rendered as ISO 8601 (`2006-03-01T17:45:09Z`).
fn bucket_creation_date(dir: &StdPath) -> String {
    let secs = fs::metadata(dir)
        .ok()
        .and_then(|md| md.created().or_else(|_| md.modified()).ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch(secs)
}

/// Bucket owner identity. Auth (stage 2) reads the same credential pair.
fn owner_id() -> String {
    env::var("S3RS_ACCESS_KEY").unwrap_or_else(|_| "test".to_string())
}

fn new_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:016x}")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Format UNIX seconds as `YYYY-MM-DDThh:mm:ssZ` (civil-from-days,
/// H. Hinnant) — no chrono dependency.
fn format_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468; // shift to days since 0000-03-01
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}
