//! Shared test harness: server spawn + SigV4 header signer (tests/../sigv4_tests.rs is the origin).
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

pub struct Svc(Child);
impl Svc {
    pub fn new(port: u16) -> Self { Svc(spawn(port)) }
}
impl Drop for Svc {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

// Minimal SigV4 signer (header auth, UNSIGNED-PAYLOAD).
fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
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


#[allow(dead_code)]
pub fn signed_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
) -> reqwest::blocking::Response {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = amz_date[..8].to_string();
    let host = format!("127.0.0.1:{port}");
    let payload_hash = "UNSIGNED-PAYLOAD";
    // canonical headers: host + x-amz-* (+ content-type when present, signed)
    let mut header_lines = vec![format!("host:{host}")];
    let mut extra = reqwest::blocking::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("http://{host}{path}"));
    header_lines.push(format!("x-amz-content-sha256:{payload_hash}"));
    header_lines.push(format!("x-amz-date:{amz_date}"));
    if let Some(ct) = content_type {
        header_lines.push(format!("content-type:{ct}"));
        extra = extra.header("content-type", ct);
    }
    header_lines.sort();
    let canonical_headers = header_lines.join("
") + "
";
    let mut signed_list = header_lines.iter().map(|h| h.split(':').next().unwrap().to_string()).collect::<Vec<_>>();
    signed_list.sort();
    let signed_headers = signed_list.join(";");
    let body_str = body.map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_default();
    let canonical_req = format!(
        "{method}
{path}

{canonical_headers}
{signed_headers}
{payload_hash}");
    let scope = format!("{date}/cn-north-1/s3/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256
{amz_date}
{scope}
{}", sha256_hex(canonical_req.as_bytes()));
    let k = hmac(format!("AWS4testsecret").as_bytes(), date.as_bytes());
    let k = hmac(&k, b"cn-north-1");
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let sig = hex(&hmac(&k, string_to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential=test/{scope}, SignedHeaders={signed_headers}, Signature={sig}");
    extra
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth)
        .body(body_str)
        .send()
        .unwrap()
}
