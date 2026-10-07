//! Stage 10 — presigned URLs (query-string SigV4 auth).
//!
//! GET /<b>/<k>?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=<ak>/<date>/cn-north-1/s3/aws4_request
//!   &X-Amz-Date=<ts>&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=<sig>
//! unsigned-payload hash. Valid -> 200 body. Tampered sig -> 403. EXPIRED
//! (X-Amz-Date far past + small Expires) -> 403 AccessDenied with message
//! mentioning expired. Extra query params must be canonicalized (sorted).
mod common;
use common::*;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }


fn presign_get(port: u16, bucket: &str, key: &str, tamper: bool, expired: bool) -> String {
    let now = chrono::Utc::now() - if expired {
        chrono::Duration::hours(2)
    } else {
        chrono::Duration::zero()
    };
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = amz_date[..8].to_string();
    let host = format!("127.0.0.1:{port}");
    let cred = format!("test/{date}/cn-north-1/s3/aws4_request");
    // canonical query: the five X-Amz-* params, SORTED (Algorithm<Credential<Date<Expires<SignedHeaders)
    let q = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={cred}&X-Amz-Date={amz_date}&X-Amz-Expires=300&X-Amz-SignedHeaders=host"
    );
    let canonical_req = format!("GET\n/{bucket}/{key}\n{q}\nhost:{host}\nhost\nUNSIGNED-PAYLOAD");
    let scope = format!("{date}/cn-north-1/s3/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical_req.as_bytes()));
    let k = hmac(format!("AWS4testsecret").as_bytes(), date.as_bytes());
    let k = hmac(&k, b"cn-north-1");
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let mut sig = hex(&hmac(&k, string_to_sign.as_bytes()));
    if tamper {
        sig = format!("{}0", &sig[..63]);
    }
    format!("http://{host}/{bucket}/{key}?{q}&X-Amz-Signature={sig}")
}

fn plain_get(url: &str) -> reqwest::blocking::Response {
    // presigned needs NO Authorization header - plain client
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
        .get(url)
        .send()
        .unwrap()
}

#[test]
fn presigned_get_works_without_headers() {
    let _svc = Svc::new(7491);
    signed_request(7491, "PUT", "/ps1", None, None);
    signed_request(7491, "PUT", "/ps1/doc.txt", Some(b"presigned body"), None);
    let url = presign_get(7491, "ps1", "doc.txt", false, false);
    let r = plain_get(&url);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
    assert_eq!(r.bytes().unwrap(), b"presigned body".as_slice());
}

#[test]
fn presigned_tampered_403_and_expired_403() {
    let _svc = Svc::new(7492);
    signed_request(7492, "PUT", "/ps2", None, None);
    signed_request(7492, "PUT", "/ps2/k", Some(b"x"), None);
    let bad = presign_get(7492, "ps2", "k", true, false);
    let r = plain_get(&bad);
    assert_eq!(r.status(), 403);
    let old = presign_get(7492, "ps2", "k", false, true);
    let r = plain_get(&old);
    assert_eq!(r.status(), 403);
    assert!(r.text().unwrap().to_lowercase().contains("expire"), "expiry message");
}
