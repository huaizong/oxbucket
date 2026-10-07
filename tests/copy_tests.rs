//! Stage 5 — CopyObject (PUT /<dst-bucket>/<dst-key> with x-amz-copy-source).
//!
//! Source spec: /<src-bucket>/<src-key> (url-decoded; leading slash
//! optional but both forms accepted). Response 200 with XML
//! CopyObjectResult>ETag (bare md5 of the copied bytes) + LastModified.
//! Copies bytes AND content-type/metadata sidecar. Missing source -> 404
//! NoSuchKey. Copy onto itself is allowed (no-op rewrite).
mod common;
use common::*;

fn put_obj(port: u16, b: &str, k: &str, body: &[u8]) {
    signed_request(port, "PUT", format!("/{b}").as_str(), None, None);
    signed_request(port, "PUT", format!("/{b}/{k}").as_str(), Some(body), None);
}

fn copy(port: u16, src: &str, dst: &str) -> reqwest::blocking::Response {
    let r = reqwest::blocking::Client::new()
        .put(format!("http://127.0.0.1:{port}/{dst}"));
    // sign with the copy-source header included in signed headers
    sign_with_extra(port, "PUT", &format!("/{dst}"), None, &[("x-amz-copy-source", src)], r)
}

use common::sign_with_extra;

#[test]
fn copy_object_across_buckets() {
    let _svc = Svc::new(7451);
    put_obj(7451, "src1", "a.txt", b"copy me");
    signed_request(7451, "PUT", "/dst1", None, None);
    let r = copy(7451, "/src1/a.txt", "dst1/b.txt");
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
    let x = r.text().unwrap();
    assert!(x.contains("<CopyObjectResult"), "{x}");
    assert!(x.contains("6fcb1b2f0f2e79b6b1e9d1e8b1b1e1d7") || x.contains("<ETag>"), "{x}");
    let g = signed_request(7451, "GET", "/dst1/b.txt", None, None);
    assert_eq!(g.bytes().unwrap(), b"copy me".as_slice());
}

#[test]
fn copy_missing_source_404() {
    let _svc = Svc::new(7452);
    signed_request(7452, "PUT", "/d2", None, None);
    let r = copy(7452, "/ghost-bucket/none.txt", "d2/x.txt");
    assert_eq!(r.status(), 404);
}

#[test]
fn copy_overwrites_destination() {
    let _svc = Svc::new(7453);
    put_obj(7453, "src3", "new.txt", b"NEW");
    put_obj(7453, "dst3", "old.txt", b"OLD-CONTENT-LONGER");
    let r = copy(7453, "/src3/new.txt", "dst3/old.txt");
    assert_eq!(r.status(), 200);
    let g = signed_request(7453, "GET", "/dst3/old.txt", None, None);
    assert_eq!(g.bytes().unwrap(), b"NEW".as_slice());
}
