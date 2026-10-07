//! Stage 4 — ListObjectsV2 (GET /<bucket>?list-type=2).
//!
//! Response XML: ListBucketResult with Name, KeyCount, MaxKeys,
//! IsTruncated, Contents* (Key, Size, LastModified, ETag bare md5),
//! CommonPrefixes* when delimiter is used. Keys sorted lexicographically.
//! Query params: prefix, delimiter, max-keys (default 1000), start-after.
//! Truncation: IsTruncated=true + NextContinuationToken when max-keys
//! exceeded; continuation-token param resumes (token = last key).
mod common;
use common::*;

fn put(port: u16, b: &str, k: &str) {
    signed_request(port, "PUT", format!("/{b}").as_str(), None, None);
    signed_request(port, "PUT", format!("/{b}/{k}").as_str(), Some(k.as_bytes()), None);
}

#[test]
fn list_keys_sorted_with_size() {
    let _svc = Svc::new(7441);
    put(7441, "l1", "zebra");
    put(7441, "l1", "apple");
    put(7441, "l1", "mango");
    let r = signed_request(7441, "GET", "/l1?list-type=2", None, None);
    assert_eq!(r.status(), 200);
    let x = r.text().unwrap();
    assert!(x.contains("<KeyCount>3</KeyCount>"), "{x}");
    let a = x.find("<Key>apple</Key>").unwrap();
    let m = x.find("<Key>mango</Key>").unwrap();
    let z = x.find("<Key>zebra</Key>").unwrap();
    assert!(a < m && m < z, "sorted order: {x}");
    assert!(x.contains("<Size>5</Size>"), "{x}"); // apple/mango are 5 bytes
    assert!(x.contains("<ETag>"), "{x}");
}

#[test]
fn prefix_and_delimiter_common_prefixes() {
    let _svc = Svc::new(7442);
    for k in ["photos/a/1.jpg", "photos/a/2.jpg", "photos/b/1.jpg", "readme.txt"] {
        put(7442, "l2", k);
    }
    let r = signed_request(7442, "GET", "/l2?list-type=2&delimiter=/", None, None);
    let x = r.text().unwrap();
    assert!(x.contains("<CommonPrefixes><Prefix>photos/</Prefix></CommonPrefixes>"), "{x}");
    assert!(x.contains("<Key>readme.txt</Key>"), "{x}");
    assert!(!x.contains("<Key>photos/"), "prefixed keys roll up: {x}");
    // prefix filter narrows the rollup
    let r2 = signed_request(7442, "GET", "/l2?list-type=2&prefix=photos/a/&delimiter=/", None, None);
    let x2 = r2.text().unwrap();
    assert!(x2.contains("<Key>photos/a/1.jpg</Key>") && x2.contains("<Key>photos/a/2.jpg</Key>"), "{x2}");
}

#[test]
fn max_keys_truncation_and_continuation() {
    let _svc = Svc::new(7443);
    for i in 0..5 {
        put(7443, "l3", &format!("k{i}"));
    }
    let r = signed_request(7443, "GET", "/l3?list-type=2&max-keys=2", None, None);
    let x = r.text().unwrap();
    assert!(x.contains("<IsTruncated>true</IsTruncated>"), "{x}");
    assert!(x.contains("<KeyCount>2</KeyCount>"), "{x}");
    assert!(x.contains("<NextContinuationToken>"), "{x}");
    let token = x.split("<NextContinuationToken>").nth(1).unwrap().split('<').next().unwrap().to_string();
    let r2 = signed_request(7443, "GET", format!("/l3?list-type=2&max-keys=2&continuation-token={token}").as_str(), None, None);
    let x2 = r2.text().unwrap();
    assert!(x2.contains("<Key>k2</Key>"), "{x2}");
    assert!(x2.contains("<IsTruncated>true</IsTruncated>"), "{x2}");
}
