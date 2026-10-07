//! Stage 2 — SigV4 header auth (single credential pair).
//!
//! Server reads S3RS_ACCESS_KEY / S3RS_SECRET_KEY (spawn() injects
//! test/testsecret). Requests must carry a valid AWS SigV4 Authorization
//! header (AWS4-HMAC-SHA256 Credential=<ak>/.../s3/aws4_request,
//! SignedHeaders=..., Signature=...) computed with UNSIGNED-PAYLOAD.
//! Missing/invalid auth -> 403 with Error>Code AccessDenied (or
//! SignatureDoesNotMatch for a well-formed but wrong signature).
//! Stage-1 routes are now protected too.
use std::process::{Child, Command};

fn spawn(port: u16) -> Child {
    let data = std::env::temp_dir().join(format!("s3rs-t2-{port}"));
    let _ = std::fs::remove_dir_all(&data);
    let child = Command::new(std::env::var("S3RS_BIN").unwrap_or_else(|_| "target/debug/s3rs".into()))
        .env("S3RS_PORT", port.to_string())
        .env("S3RS_DATA", &data)
        .env("S3RS_ACCESS_KEY", "test")
        .env("S3RS_SECRET_KEY", "testsecret")
        .spawn()
        .expect("spawn");
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("no server on {port}");
}

struct Svc(Child);
impl Svc {
    fn new(port: u16) -> Self { Svc(spawn(port)) }
}
impl Drop for Svc {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

// Minimal SigV4 signer (header auth, UNSIGNED-PAYLOAD).
fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Hmac, Sha256};
    let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn sign_put(port: u16, bucket: &str, secret: &str, tamper: bool) -> reqwest::blocking::Response {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = amz_date[..8].to_string();
    let host = format!("127.0.0.1:{port}");
    let payload_hash = "UNSIGNED-PAYLOAD";
    let canonical_headers = format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_req = format!(
        "PUT\n/{bucket}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{date}/cn-north-1/s3/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical_req.as_bytes()));
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, b"cn-north-1");
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let sig = hex(&hmac(&k, string_to_sign.as_bytes()));
    let sig = if tamper { format!("{}0", &sig[..63]) } else { sig };
    let auth = format!("AWS4-HMAC-SHA256 Credential=test/{scope}, SignedHeaders={signed_headers}, Signature={sig}");
    reqwest::blocking::Client::new()
        .put(format!("http://{host}/{bucket}"))
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth)
        .send().unwrap()
}

#[test]
fn signed_request_passes() {
    let _svc = Svc::new(7421);
    let r = sign_put(7421, "signed-bucket", "testsecret", false);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap());
}

#[test]
fn tampered_signature_is_403() {
    let _svc = Svc::new(7422);
    let r = sign_put(7422, "evil", "testsecret", true);
    assert_eq!(r.status(), 403);
    let body = r.text().unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
}

#[test]
fn unsigned_request_is_403() {
    let _svc = Svc::new(7423);
    let r = reqwest::blocking::Client::new()
        .put("http://127.0.0.1:7423/unsigned")
        .send().unwrap();
    assert_eq!(r.status(), 403);
    let body = r.text().unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
}

#[test]
fn wrong_secret_is_403() {
    let _svc = Svc::new(7424);
    let r = sign_put(7424, "b", "wrong-secret-entirely", false);
    assert_eq!(r.status(), 403);
}
