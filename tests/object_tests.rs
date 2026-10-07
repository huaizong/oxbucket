//! Stage 3 — object core (PUT/GET/HEAD/DELETE + etag + content-type).
mod common;
use common::*;

fn md5_hex_of(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn put_get_roundtrip_with_etag_and_content_type() {
    let _svc = Svc::new(7431);
    signed_request(7431, "PUT", "/obj-bucket", None, None);
    let body = b"hello oxbucket".to_vec();
    let put = signed_request(7431, "PUT", "/obj-bucket/greeting.txt", Some(&body), Some("text/plain"));
    assert_eq!(put.status(), 200, "{}", put.text().unwrap());
    // etag header quoted md5
    let etag = put_captures_etag(7431, "/obj-bucket/greeting.txt");
    assert_eq!(etag, md5_hex_of(&body));
    let get = signed_request(7431, "GET", "/obj-bucket/greeting.txt", None, None);
    assert_eq!(get.status(), 200);
    assert_eq!(get.headers().get("content-type").unwrap(), "text/plain");
    assert_eq!(get.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"'), etag);
    assert_eq!(get.bytes().unwrap(), body.as_slice());
}

fn put_captures_etag(port: u16, path: &str) -> String {
    let h = signed_request(port, "HEAD", path, None, None);
    assert_eq!(h.status(), 200);
    h.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string()
}

#[test]
fn head_and_delete_object() {
    let _svc = Svc::new(7432);
    signed_request(7432, "PUT", "/h-b", None, None);
    signed_request(7432, "PUT", "/h-b/k", Some(b"v"), None);
    let h = signed_request(7432, "HEAD", "/h-b/k", None, None);
    assert_eq!(h.status(), 200);
    let d = signed_request(7432, "DELETE", "/h-b/k", None, None);
    assert_eq!(d.status(), 204);
    let g = signed_request(7432, "GET", "/h-b/k", None, None);
    assert_eq!(g.status(), 404);
    let body = g.text().unwrap();
    assert!(body.contains("<Code>NoSuchKey</Code>"), "{body}");
}

#[test]
fn delete_missing_key_is_204_and_overwrite() {
    let _svc = Svc::new(7433);
    signed_request(7433, "PUT", "/d-b", None, None);
    assert_eq!(signed_request(7433, "DELETE", "/d-b/ghost", None, None).status(), 204);
    signed_request(7433, "PUT", "/d-b/k", Some(b"one"), None);
    signed_request(7433, "PUT", "/d-b/k", Some(b"two!"), None);
    let g = signed_request(7433, "GET", "/d-b/k", None, None);
    assert_eq!(g.bytes().unwrap(), b"two!".as_slice());
}
