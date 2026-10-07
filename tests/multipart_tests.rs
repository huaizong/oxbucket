//! Stage 6 — Multipart upload.
//!
//! POST /<b>/<k>?uploads            -> 200 InitiateMultipartUploadResult
//!                                     (UploadId; echo it back verbatim)
//! PUT  /<b>/<k>?partNumber=N&uploadId=X  -> 200, ETag = md5(part bytes)
//! POST /<b>/<k>?uploadId=X         -> 200 CompleteMultipartUploadResult;
//!                                     assembled object = parts in order;
//!                                     final ETag = md5(concat(part-md5s))+"-N"
//! GET  after complete              -> assembled bytes
//! DELETE /<b>/<k>?uploadId=X       -> 204; complete after abort -> 404 NoSuchUpload
//! POST complete with a missing part number -> 400 InvalidPart
mod common;
use common::*;

#[test]
fn multipart_lifecycle() {
    let _svc = Svc::new(7461);
    signed_request(7461, "PUT", "/mp1", None, None);
    // initiate
    let r = signed_request(7461, "POST", "/mp1/big.bin?uploads", None, None);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
    let x = r.text().unwrap();
    assert!(x.contains("<InitiateMultipartUploadResult"), "{x}");
    let uid = x.split("<UploadId>").nth(1).unwrap().split('<').next().unwrap().to_string();
    // two parts
    let p1: &[u8] = b"AAAA-first-part";
    let p2: &[u8] = b"BBBB-second";
    let r1 = signed_request(7461, "PUT", &format!("/mp1/big.bin?partNumber=1&uploadId={uid}"), Some(p1), None);
    assert_eq!(r1.status(), 200, "{}", r1.text().unwrap());
    let e1 = r1.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string();
    let r2 = signed_request(7461, "PUT", &format!("/mp1/big.bin?partNumber=2&uploadId={uid}"), Some(p2), None);
    let e2 = r2.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string();
    // complete with parts list body
    let body = format!(
        "<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>",
        parts = format!("<Part><PartNumber>1</PartNumber><ETag>{e1}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{e2}</ETag></Part>"));
    let rc = signed_request(7461, "POST", &format!("/mp1/big.bin?uploadId={uid}"), Some(body.as_bytes()), None);
    assert_eq!(rc.status(), 200, "{}", rc.text().unwrap());
    let xc = rc.text().unwrap();
    assert!(xc.contains("<CompleteMultipartUploadResult"), "{xc}");
    // assembled GET
    let g = signed_request(7461, "GET", "/mp1/big.bin", None, None);
    let mut expect = p1.to_vec(); expect.extend_from_slice(p2);
    assert_eq!(g.bytes().unwrap(), expect.as_slice());
}

#[test]
fn abort_then_complete_is_404() {
    let _svc = Svc::new(7462);
    signed_request(7462, "PUT", "/mp2", None, None);
    let r = signed_request(7462, "POST", "/mp2/k?uploads", None, None);
    let x = r.text().unwrap();
    let uid = x.split("<UploadId>").nth(1).unwrap().split('<').next().unwrap().to_string();
    let d = signed_request(7462, "DELETE", &format!("/mp2/k?uploadId={uid}"), None, None);
    assert_eq!(d.status(), 204);
    let rc = signed_request(7462, "POST", &format!("/mp2/k?uploadId={uid}"), Some(b"<CompleteMultipartUpload/>"), None);
    assert_eq!(rc.status(), 404);
    let xb = rc.text().unwrap();
    assert!(xb.contains("NoSuchUpload"), "{xb}");
}

#[test]
fn complete_with_missing_part_400() {
    let _svc = Svc::new(7463);
    signed_request(7463, "PUT", "/mp3", None, None);
    let r = signed_request(7463, "POST", "/mp3/k?uploads", None, None);
    let uid = r.text().unwrap().split("<UploadId>").nth(1).unwrap().split('<').next().unwrap().to_string();
    // complete listing part 7 which was never uploaded
    let body = b"<CompleteMultipartUpload><Part><PartNumber>7</PartNumber><ETag>deadbeef</ETag></Part></CompleteMultipartUpload>";
    let rc = signed_request(7463, "POST", &format!("/mp3/k?uploadId={uid}"), Some(body), None);
    assert_eq!(rc.status(), 400);
}
