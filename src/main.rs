//! oxbucket — S3-compatible object storage server (stage 1: bucket CRUD).
//!
//! Stage 1 scope (path-style addressing only, auth not yet enforced):
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
//! Objects (stage 3) will be files inside those directories plus sidecar
//! `.meta.json` files.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};

const DEFAULT_PORT: u16 = 7333;
const DEFAULT_DATA_DIR: &str = "./data";
const XML_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Shared server state.
#[derive(Clone)]
struct AppState {
    /// Root directory holding one sub-directory per bucket.
    data_dir: PathBuf,
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

    let app = Router::new()
        .route("/", get(list_buckets))
        .route("/:bucket", any(bucket_endpoint))
        .route("/:bucket/*key", any(object_endpoint))
        .fallback(unknown_resource)
        .with_state(AppState { data_dir });

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
) -> Response {
    if method == Method::PUT {
        create_bucket(&state, &bucket)
    } else if method == Method::HEAD {
        head_bucket(&state, &bucket)
    } else if method == Method::DELETE {
        delete_bucket(&state, &bucket)
    } else if method == Method::GET {
        get_bucket(&state, &bucket)
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

/// GET /<bucket> — object listing; ListObjectsV2 lands in stage 4.
fn get_bucket(state: &AppState, bucket: &str) -> Response {
    if !is_valid_bucket_name(bucket) || !bucket_dir(state, bucket).is_dir() {
        return ApiError::no_such_bucket(format!("/{bucket}")).into_response();
    }
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "GET bucket (ListObjects) is implemented in stage 4",
        format!("/{bucket}"),
    )
    .into_response()
}

/// /<bucket>/<key> — object operations land in stage 3; until then an
/// unknown bucket must still answer 404 NoSuchBucket.
async fn object_endpoint(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    if !is_valid_bucket_name(&bucket) || !bucket_dir(&state, &bucket).is_dir() {
        return ApiError::no_such_bucket(resource).into_response();
    }
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "Object operations are implemented in stage 3",
        resource,
    )
    .into_response()
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
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    resource: String,
}

impl ApiError {
    fn new(
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
fn bucket_creation_date(dir: &Path) -> String {
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
