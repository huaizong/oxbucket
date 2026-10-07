//! Stage 11 — object user metadata (x-amz-meta-*) + multi-delete.
//!
//! PUT with x-amz-meta-* headers stores them (sidecar); HEAD/GET return
//! them verbatim (case-insensitive lookup, values trimmed). Metadata
//! survives CopyObject (default: copied). POST /<b>?delete with XML
//! <Delete><Object><Key>k</Key></Object>...</Delete> deletes ALL listed
//! keys atomically-ish, returns <DeleteResult><Deleted><Key>..</Key>...
//! for each. Unknown keys in the batch still report <Deleted> (S3
//! idempotency).
mod common;
use common::*;

#[test]
fn metadata_roundtrip_and_copy() {
    let _svc = Svc::new(7501);
    signed_request(7501, "PUT", "/md1", None, None);
    let b = reqwest::blocking::Client::new().put("http://127.0.0.1:7501/md1/orig.txt");
    let r = sign_with_extra(7501, "PUT", "/md1/orig.txt", Some(b"meta body"),
        &[("x-amz-meta-owner", "zhw"), ("x-amz-meta-project", "oxbucket stage 11")], b);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
    let h = signed_request(7501, "HEAD", "/md1/orig.txt", None, None);
    assert_eq!(h.headers().get("x-amz-meta-owner").unwrap(), "zhw");
    assert_eq!(h.headers().get("x-amz-meta-project").unwrap(), "oxbucket stage 11");
    // copy preserves metadata
    let cb = reqwest::blocking::Client::new().put("http://127.0.0.1:7501/md1/copy.txt");
    let cp = sign_with_extra(7501, "PUT", "/md1/copy.txt", None,
        &[("x-amz-copy-source", "/md1/orig.txt")], cb);
    assert_eq!(cp.status(), 200, "{}", cp.text().unwrap());
    let h2 = signed_request(7501, "HEAD", "/md1/copy.txt", None, None);
    assert_eq!(h2.headers().get("x-amz-meta-owner").unwrap(), "zhw");
}

#[test]
fn multi_delete_batch() {
    let _svc = Svc::new(7502);
    signed_request(7502, "PUT", "/md2", None, None);
    for k in ["a", "b", "c"] {
        signed_request(7502, "PUT", &format!("/md2/{k}"), Some(k.as_bytes()), None);
    }
    let body = "<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object><Object><Key>ghost</Key></Object></Delete>";
    let r = signed_request(7502, "POST", "/md2?delete", Some(body.as_bytes()), None);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
    let x = r.text().unwrap();
    assert!(x.contains("<DeleteResult"), "{x}");
    for k in ["a", "b", "ghost"] {
        assert!(x.contains(&format!("<Key>{k}</Key>")), "{x}");
    }
    assert_eq!(signed_request(7502, "GET", "/md2/a", None, None).status(), 404);
    assert_eq!(signed_request(7502, "GET", "/md2/c", None, None).status(), 200);
}
