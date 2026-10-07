# oxbucket (`s3rs`)

oxbucket is a small S3-compatible object-storage server in Rust, built
stage-by-stage against its integration tests. It serves the core S3 REST
API — bucket CRUD, object PUT/GET/HEAD/DELETE, ListObjectsV2, CopyObject
and multipart uploads — straight from a filesystem, guarded by AWS
Signature Version 4 (header-based) authentication and answering with
S3-style XML documents and status codes.

Implemented directly on axum + tokio (edition 2021, minimal deps). The
server binary links **no crypto and no XML crates**: SHA-256, HMAC, hex,
MD5 and all XML handling are hand-rolled — see
[Design notes](#design-notes). The executable stays `s3rs` (the name the
test suites spawn); the crate is `oxbucket`.

## Quick start

Build:

```sh
cargo build              # produces target/debug/s3rs (cargo build --release for target/release/s3rs)
```

Run:

```sh
S3RS_PORT=7333 \
S3RS_DATA=./data \
S3RS_ACCESS_KEY=test \
S3RS_SECRET_KEY=testsecret \
target/debug/s3rs
```

| Env var            | Default  | Meaning                                             |
|--------------------|----------|-----------------------------------------------------|
| `S3RS_PORT`        | `7333`   | TCP port; the server binds `127.0.0.1` only         |
| `S3RS_DATA`        | `./data` | storage root (created at startup if missing)        |
| `S3RS_ACCESS_KEY`  | `test`   | expected SigV4 access key id                        |
| `S3RS_SECRET_KEY`  | `test`   | expected SigV4 secret key                           |

SigV4 enforcement switches on when **at least one** of
`S3RS_ACCESS_KEY` / `S3RS_SECRET_KEY` is set explicitly. A bare default
environment keeps the server open (unauthenticated requests accepted);
the `test`/`test` defaults still feed the bucket-owner identity in XML.

The API is path-style only — bucket and key live in the URL path:

```sh
# unauthenticated quick check (server without the env vars above)
curl --upload-file hello.txt http://127.0.0.1:7333/my-bucket/hello.txt
```

Any SigV4-signing client works, e.g. the AWS CLI:

```sh
aws --endpoint-url http://127.0.0.1:7333 s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:7333 s3 cp hello.txt s3://my-bucket/hello.txt
```

### Tests

```sh
cargo test
```

Every suite spawns its own server on `127.0.0.1` (binary resolved from
`target/debug/s3rs`, overridable with `$S3RS_BIN`):

- **stages 1–6** — raw HTTP via `reqwest` plus a hand-rolled SigV4
  signer in `tests/common/mod.rs`; these suites do not depend on aws
  crates.
- **stage 7** — `tests/sdk_conformance.rs`, driven by the real
  `aws-sdk-s3` client (force-path-style, region `cn-north-1`, creds
  `test`/`testsecret`). The aws crates are dev-dependencies only; the
  server binary never links them.

## API coverage

| Operation | Wire call | Behavior / status |
|---|---|---|
| ListBuckets | `GET /` | 200 `ListAllMyBucketsResult` — `Owner`, `Bucket`/`Name`/`CreationDate`, sorted; dot-prefixed state dirs never listed |
| CreateBucket | `PUT /{bucket}` (also `/{bucket}/`) | 200, empty body + `Location` header; idempotent; 400 `InvalidBucketName`; SDK `CreateBucketConfiguration` body + `content-md5`/`x-amz-checksum-*` headers accepted and ignored |
| HeadBucket | `HEAD /{bucket}` | 200 exists / 404 `NoSuchBucket` (no body) |
| DeleteBucket | `DELETE /{bucket}` | 204 empty; 409 `BucketNotEmpty`; 404 `NoSuchBucket` |
| ListObjectsV2 | `GET /{bucket}?list-type=2` | `prefix`, `delimiter` (`CommonPrefixes`), `max-keys`, `continuation-token` → `NextContinuationToken`; keys sorted; a delimiter group with a single key stays in `Contents`, only multi-key groups roll up to `CommonPrefixes`; unknown bucket → 404 `NoSuchBucket` |
| SigV4 auth | `Authorization` header on every route | header scheme only — no presigned/query auth; 403 XML `AccessDenied` (missing/malformed auth material) or `SignatureDoesNotMatch` (well-formed header, signature does not verify) |
| PutObject | `PUT /{bucket}/{key}` | 200, `ETag` = quoted MD5 hex; `Content-Type` stored (default `binary/octet-stream`); unknown bucket → 404 `NoSuchBucket`; unusable key → 400 |
| GetObject | `GET /{bucket}/{key}` | 200 stored bytes + `Content-Type` + `ETag`; 404 `NoSuchKey` |
| HeadObject | `HEAD /{bucket}/{key}` | same headers as GET, no body; `Content-Length` echoes object size |
| DeleteObject | `DELETE /{bucket}/{key}` | 204 |
| CopyObject | `PUT /{bucket}/{key}` + `x-amz-copy-source` | source `[ / ]<bucket>/<key>` (URL-encoded, optional `?versionId` suffix split off before decoding); copies bytes **and** the metadata sidecar; 200 `CopyObjectResult` (bare MD5 `ETag` + `LastModified`); 404 `NoSuchKey` on missing source; self-copy is an allowed no-op; no conditional copy (`If-None-Match`) or metadata REPLACE directive |
| Multipart initiate | `POST /{bucket}/{key}?uploads` | 200 `InitiateMultipartUploadResult` with URL-safe `UploadId` (hex + `-`) |
| Multipart upload part | `PUT /{bucket}/{key}?partNumber=N&uploadId=X` | 200 + quoted MD5 of the part; part numbers 1..=10000 else 400 `InvalidArgument`; unknown/aborted id → 404 `NoSuchUpload` |
| Multipart complete | `POST /{bucket}/{key}?uploadId=X` | validates every listed part's `ETag` against stored bytes → 400 `InvalidPart` on mismatch; assembles in list order; final `ETag` = `md5(concat part md5s)-<count>`; upload state removed |
| Multipart abort | `DELETE /{bucket}/{key}?uploadId=X` | 204; state removed; unknown id → 404 `NoSuchUpload` |
| aws-sdk-s3 conformance | `tests/sdk_conformance.rs` | passing — the real SDK round-trips create/head/list/put/get/delete, CopyObject and the full multipart flow against the server |

Every error — including unmatched routes (fallback handler) — is an S3
XML `<Error>` document with `Code`, `Message`, `Resource`, `RequestId`.

## Storage layout

```
<S3RS_DATA>/                    default ./data
├── my-bucket/                  one directory per bucket
│   ├── hello.txt               object bytes (raw)
│   └── photos/a.jpg            '/' in the key = nested directory
│       └── …
├── photos/a.jpg.meta.json      sidecar NEXT TO each object:
│                               {"etag":"…","content_type":"…"}
└── .uploads/                   multipart state root (dot-prefixed:
    └── <upload-id>/            never a bucket, hidden from ListBuckets)
        └── part-<N>            one file per uploaded part
```

- Buckets are plain directories; object keys map to relative paths, so
  `a/b/c` is a two-directory deep file.
- The `.meta.json` sidecar is written and parsed **by hand** (fixed
  shape; `serde_json` is not a dependency). Listings and key collection
  skip sidecars.
- Only dot-prefixed entries under the data root are reserved for server
  state (`.uploads/`). Bucket names are validated per S3 rules, and
  object keys / upload ids are rejected when they could escape the data
  root (`..`, absolute, NUL, backslash) — the validation doubles as the
  path-traversal guard.
- Deletion is a plain filesystem remove; the tree on disk is the source
  of truth (no journal, no index to rebuild).

## Design notes

- **axum 0.8 routing quirks.** Routing resolves *before*
  `Router::layer` middleware runs, and `/{bucket}` (single-segment
  capture) does not match `/{bucket}/` — a distinct pattern. The
  aws-sdk-s3 sends bucket-level calls as `PUT /{bucket}/` on the wire,
  which 404'd until an explicit sibling `/{bucket}/` route was added;
  the `normalize_bucket_root` URI-rewrite middleware remains only as a
  safety net. `authorize` is added **last** (outermost layer sees the
  request first) so SigV4 is verified against the original wire URI the
  client signed. Handler signatures put body-consuming extractors
  (`Bytes`) last, per axum 0.8 extractor ordering.
- **Canonical-query SigV4 quirks.** The canonical query string follows
  the AWS URI rules: clients percent-encode query *values* (the SDK
  sends `delimiter=%2F`), so the server percent-decodes them back.
  Valueless parameters (`?uploads`) canonicalize as `k=` on both sides,
  leaving signatures unaffected. `x-amz-content-sha256` of
  `UNSIGNED-PAYLOAD` or the streaming-payload marker (single-chunk
  bodies) is accepted verbatim. Signature hex is normalized to
  lowercase, unknown `Authorization` components are tolerated, and
  verification folds only the headers in `SignedHeaders`
  (`content-md5`, `expect`, `x-amz-checksum-*` pass through unsigned).
  Any region/service/date scope passes shape validation. Known
  simplification: authorization component values are trimmed but inner
  whitespace is not collapsed.
- **Hand-rolled XML.** No XML crate: responses are emitted as exact
  strings (no inter-tag whitespace — the raw suites assert adjacent
  substrings), escaping the five XML entities; the one parsed body
  (`CompleteMultipartUpload`) is extracted with small helpers.
- **Hand-rolled crypto.** SHA-256, HMAC, hex (auth.rs) and MD5 (RFC
  1321, md5.rs) are implemented in-tree and pinned against published
  test vectors by dev-dependency tests (`sha2`, `hmac`, `hex`, `md-5`
  are dev-deps only). `ETag` is the quoted lowercase MD5 hex; multipart
  completes use the S3-style `md5(<concatenated part md5 hexes>)-<N>`.

## Scope / non-goals

Path-style addressing only (no virtual-host style), loopback binding,
single credential pair, no TLS, no versioning, no presigned URLs, no
ACLs/policies, no `ListParts` / in-progress upload listing, no Range or
conditional GETs, no server-side encryption. Requests are handled
synchronously against the filesystem — this is a test/dev-grade server,
not a production store.
