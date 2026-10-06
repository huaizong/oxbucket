//! Stage 1 — bucket CRUD over raw HTTP (auth: not yet enforced).
//!
//! Server binds 127.0.0.1:7333 (S3RS_PORT). Each test boots its own
//! server instance on a private port with a fresh data dir (see spawn()).
//!
//! S3 XML shapes pinned:
//! - ListAllMyBucketsResult>Owner>ID/DisplayName, Buckets>Bucket>Name/CreationDate
//! - CreateBucket: 200 empty body + Location header (path-style: /<bucket>)
//! - HeadBucket: 200 or 404 (no body)
//! - DeleteBucket: 204 empty; deleting a non-empty bucket -> 409 with
//!   Error>Code BucketNotEmpty
//! - unknown bucket on GET object-ish paths -> 404 Error>Code NoSuchBucket
//! - every error response body is XML Error with Code and Message
use std::process::{Child, Command};

fn spawn(port: u16) -> Child {
    let data = std::env::temp_dir().join(format!("s3rs-test-{port}"));
    let _ = std::fs::remove_dir_all(&data);
    let child = Command::new(std::env::var("S3RS_BIN").unwrap_or_else(|_| "target/debug/s3rs".into()))
        .env("S3RS_PORT", port.to_string())
        .env("S3RS_DATA", &data)
        .spawn()
        .expect("spawn s3rs");
    // wait for readiness
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("server never came up on {port}");
}

struct Svc(Child);
impl Svc {
    fn new(port: u16) -> Self {
        Svc(spawn(port))
    }
}
impl Drop for Svc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

fn url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

#[test]
fn create_list_delete_bucket() {
    let _svc = Svc::new(7411);
    let http = client();
    // create
    let r = http.put(url(7411, "/alpha")).send().unwrap();
    assert_eq!(r.status(), 200, "create bucket");
    assert_eq!(r.headers().get("Location").unwrap(), "/alpha");
    // list contains it
    let r = http.get(url(7411, "/")).send().unwrap();
    assert_eq!(r.status(), 200);
    let body = r.text().unwrap();
    assert!(body.contains("<Name>alpha</Name>"), "list body: {body}");
    assert!(body.contains("<ListAllMyBucketsResult"), "{body}");
    assert!(body.contains("<Owner>") && body.contains("<ID>"), "{body}");
    // head bucket
    assert_eq!(http.head(url(7411, "/alpha")).send().unwrap().status(), 200);
    // delete
    let r = http.delete(url(7411, "/alpha")).send().unwrap();
    assert_eq!(r.status(), 204);
    // gone
    assert_eq!(http.head(url(7411, "/alpha")).send().unwrap().status(), 404);
}

#[test]
fn delete_nonempty_bucket_conflicts() {
    let _svc = Svc::new(7412);
    let http = client();
    http.put(url(7412, "/full")).send().unwrap();
    std::fs::write(
        std::env::temp_dir().join("s3rs-test-7412/full/hello.txt"),
        b"hi",
    )
    .unwrap();
    let r = http.delete(url(7412, "/full")).send().unwrap();
    assert_eq!(r.status(), 409);
    let body = r.text().unwrap();
    assert!(body.contains("<Code>BucketNotEmpty</Code>"), "{body}");
}

#[test]
fn error_document_shape_on_unknown_bucket() {
    let _svc = Svc::new(7413);
    let http = client();
    let r = http.get(url(7413, "/ghost/key")).send().unwrap();
    assert_eq!(r.status(), 404);
    let body = r.text().unwrap();
    assert!(body.contains("<Error") && body.contains("<Code>NoSuchBucket</Code>") && body.contains("<Message>"), "{body}");
}
