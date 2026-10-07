# oxbucket — S3-compatible object storage in Rust

Agent-built under the runner-harness long task. The human runs cargo
build/test externally and feeds results back; you implement, verify by
reading, and COMMIT per stage (git add -A && git commit -m "stage N: ...").

Architecture decisions (pinned by owner):
- axum web framework, tokio runtime, port 7333 default (S3RS_PORT env)
- storage: filesystem under ./data (buckets = directories, objects = files
  with sidecar .meta.json for etag/content-type/user-metadata); create the
  data dir at startup if missing
- SigV4 auth: single credential pair from env (S3RS_ACCESS_KEY /
  S3RS_SECRET_KEY, defaults test/test); header-based SigV4 only (query
  auth is stretch); UNSIGNED-PAYLOAD and single chunked body both accepted
- error responses: S3 XML error documents with proper status codes
- tests: cargo integration tests in tests/ using raw HTTP + SigV4 signer
  (tests themselves must NOT depend on aws crates; stage 7 adds an
  aws-sdk-s3 conformance suite behind a feature flag)

Stage plan (tests arrive per stage, specs in test docstrings):
1. bucket CRUD  — PUT/GET/DELETE bucket, GET / (ListBuckets), XML shapes — done
2. SigV4        — real signer; reject bad signature with 403 — done
3. object core  — PUT/GET/HEAD/DELETE object, etag, content-type — done
4. ListObjectsV2 — keys, prefix, delimiter (common prefixes), max-keys — done
5. CopyObject   — + conditional If-None-Match/* / metadata replace — done
6. Multipart    — create/upload-part/complete/abort + assembled GET — done
7. conformance  — aws-sdk-s3 suite (feature-gated), compat fixes — done

Ground rules: never modify tests; each stage ends green in the human's
external cargo run; no shell on this platform (verify by trace); commit
per stage. Rust edition 2021, minimal deps.
