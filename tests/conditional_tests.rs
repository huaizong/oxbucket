//! Stage 9 — conditional GET + Range GET.
//!
//! - If-None-Match: "<etag>" matching current etag -> 304 Not Modified
//!   (empty body); non-matching -> 200 full body.
//! - If-Match: "<etag>" matching -> 200; mismatching -> 412 PreconditionFailed
//!   with Error>Code PreconditionFailed.
//! - Range: bytes=0-4 -> 206 Partial Content with Content-Range
//!   "bytes 0-4/<total>"; bytes=2- -> suffix-inclusive; invalid/unsatisfiable
//!   range -> 416 InvalidRange.
mod common;
use common::*;

fn put(port: u16, b: &str, k: &str, body: &[u8]) -> String {
    signed_request(port, "PUT", format!("/{b}").as_str(), None, None);
    let r = signed_request(port, "PUT", format!("/{b}/{k}").as_str(), Some(body), None);
    r.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string()
}

#[test]
fn if_none_match_304_and_miss_200() {
    let _svc = Svc::new(7481);
    let etag = put(7481, "cond1", "k", b"0123456789");
    let r304 = reqwest::blocking::Client::new()
        .get("http://127.0.0.1:7481/cond1/k");
    let r = sign_with_extra(7481, "GET", "/cond1/k", None,
        &[("if-none-match", &format!("\"{etag}\""))], r304);
    assert_eq!(r.status(), 304);
    assert!(r.bytes().unwrap().is_empty());
    // different etag -> full 200
    let r200 = reqwest::blocking::Client::new()
        .get("http://127.0.0.1:7481/cond1/k");
    let r = sign_with_extra(7481, "GET", "/cond1/k", None,
        &[("if-none-match", "\"deadbeef\"")], r200);
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().unwrap(), b"0123456789".as_slice());
}

#[test]
fn if_match_412_on_mismatch() {
    let _svc = Svc::new(7482);
    let etag = put(7482, "cond2", "k", b"abc");
    let b = reqwest::blocking::Client::new().get("http://127.0.0.1:7482/cond2/k");
    let r = sign_with_extra(7482, "GET", "/cond2/k", None,
        &[("if-match", &format!("\"{etag}\""))], b);
    assert_eq!(r.status(), 200);
    let b = reqwest::blocking::Client::new().get("http://127.0.0.1:7482/cond2/k");
    let r = sign_with_extra(7482, "GET", "/cond2/k", None,
        &[("if-match", "\"wrong\"")], b);
    assert_eq!(r.status(), 412);
    assert!(r.text().unwrap().contains("PreconditionFailed"));
}

#[test]
fn range_get_206_and_416() {
    let _svc = Svc::new(7483);
    put(7483, "cond3", "k", b"0123456789");
    let b = reqwest::blocking::Client::new().get("http://127.0.0.1:7483/cond3/k");
    let r = sign_with_extra(7483, "GET", "/cond3/k", None,
        &[("range", "bytes=0-4")], b);
    assert_eq!(r.status(), 206);
    assert_eq!(r.headers().get("content-range").unwrap(), "bytes 0-4/10");
    assert_eq!(r.bytes().unwrap(), b"01234".as_slice());
    // suffix form
    let b = reqwest::blocking::Client::new().get("http://127.0.0.1:7483/cond3/k");
    let r = sign_with_extra(7483, "GET", "/cond3/k", None,
        &[("range", "bytes=8-")], b);
    assert_eq!(r.status(), 206);
    assert_eq!(r.bytes().unwrap(), b"89".as_slice());
    // unsatisfiable
    let b = reqwest::blocking::Client::new().get("http://127.0.0.1:7483/cond3/k");
    let r = sign_with_extra(7483, "GET", "/cond3/k", None,
        &[("range", "bytes=99-")], b);
    assert_eq!(r.status(), 416);
}
