//! Stage 7 — aws-sdk-s3 conformance (the REAL S3 client).
//!
//! The SDK signs SigV4 itself, sends its own headers (content-md5,
//! x-amz-checksum-* variants, expect-100), and parses our XML strictly.
//! Server: spawned per test with creds test/testsecret. SDK client built
//! with force-path-style (http://127.0.0.1:PORT), region cn-north-1.
use std::process::{Child, Command};

fn spawn(port: u16) -> Child {
    let data = std::env::temp_dir().join(format!("s3rs-t7-{port}"));
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

fn client(port: u16) -> aws_sdk_s3::Client {
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().unwrap().block_on(f)
    }
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "test", "testsecret", None, None, "static",
        ))
        .region(aws_config::Region::new("cn-north-1"))
        .endpoint_url(format!("http://127.0.0.1:{port}"))
        .load();
    let cfg = block_on(cfg);
    let s3_cfg = aws_sdk_s3::config::Builder::from(&cfg)
        .force_path_style(true)
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .build();
    aws_sdk_s3::Client::from_conf(s3_cfg)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

#[test]
fn sdk_bucket_and_object_lifecycle() {
    let _svc = Svc::new(7471);
    let c = client(7471);
    rt().block_on(async {
        c.create_bucket().bucket("sdk-bucket").send().await.expect("create_bucket");
        let buckets = c.list_buckets().send().await.expect("list_buckets");
        let names: Vec<&str> = buckets.buckets().iter().filter_map(|b| b.name()).collect();
        assert!(names.contains(&"sdk-bucket"), "{names:?}");

        c.put_object()
            .bucket("sdk-bucket").key("dir/hello sdk.txt")
            .body(aws_sdk_s3::primitives::ByteStream::from_static(b"SDK body 123"))
            .content_type("application/x-custom")
            .send().await.expect("put_object");

        let head = c.head_object().bucket("sdk-bucket").key("dir/hello sdk.txt")
            .send().await.expect("head_object");
        assert_eq!(head.content_length(), Some(12));
        assert_eq!(head.content_type(), Some("application/x-custom"));

        let get = c.get_object().bucket("sdk-bucket").key("dir/hello sdk.txt")
            .send().await.expect("get_object");
        let body = get.body.collect().await.expect("collect").into_bytes();
        assert_eq!(body.as_ref(), b"SDK body 123");

        c.delete_object().bucket("sdk-bucket").key("dir/hello sdk.txt")
            .send().await.expect("delete_object");
        let err = c.get_object().bucket("sdk-bucket").key("dir/hello sdk.txt")
            .send().await.expect_err("gone");
        let se = err.into_service_error();
        assert!(format!("{se:?}").contains("404") || se.to_string().contains("NoSuchKey"), "{se:?}");
    });
}

#[test]
fn sdk_list_objects_v2() {
    let _svc = Svc::new(7472);
    let c = client(7472);
    rt().block_on(async {
        c.create_bucket().bucket("sdk-list").send().await.expect("create");
        for k in ["a/1", "a/2", "b/3"] {
            c.put_object().bucket("sdk-list").key(k)
                .body(aws_sdk_s3::primitives::ByteStream::from_static(b"x"))
                .send().await.expect("put");
        }
        let page = c.list_objects_v2().bucket("sdk-list").delimiter("/")
            .send().await.expect("list");
        let keys: Vec<&str> = page.contents().iter().filter_map(|o| o.key()).collect();
        let cps: Vec<&str> = page.common_prefixes().iter().filter_map(|p| p.prefix()).collect();
        assert!(keys.contains(&"b/3"), "{keys:?}");
        assert!(cps.contains(&"a/"), "{cps:?}");
    });
}

#[test]
fn sdk_copy_and_multipart() {
    let _svc = Svc::new(7473);
    let c = client(7473);
    rt().block_on(async {
        c.create_bucket().bucket("sdk-mp").send().await.expect("create");
        c.put_object().bucket("sdk-mp").key("src.txt")
            .body(aws_sdk_s3::primitives::ByteStream::from_static(b"copy-source"))
            .send().await.expect("put src");
        // copy
        let cp = c.copy_object()
            .copy_source("sdk-mp/src.txt")
            .bucket("sdk-mp").key("dst.txt")
            .send().await.expect("copy");
        let _ = cp.copy_object_result();
        let get = c.get_object().bucket("sdk-mp").key("dst.txt").send().await.expect("get dst");
        let body = get.body.collect().await.expect("collect").into_bytes();
        assert_eq!(body.as_ref(), b"copy-source");
        // multipart
        let mp = c.create_multipart_upload().bucket("sdk-mp").key("big.bin")
            .send().await.expect("create mpu");
        let uid = mp.upload_id().expect("upload id");
        let p1 = c.upload_part().bucket("sdk-mp").key("big.bin").upload_id(uid).part_number(1)
            .body(aws_sdk_s3::primitives::ByteStream::from_static(b"part-one--"))
            .send().await.expect("part1");
        let p2 = c.upload_part().bucket("sdk-mp").key("big.bin").upload_id(uid).part_number(2)
            .body(aws_sdk_s3::primitives::ByteStream::from_static(b"part-two"))
            .send().await.expect("part2");
        let done = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .parts(
                aws_sdk_s3::types::CompletedPart::builder().part_number(1)
                    .e_tag(p1.e_tag().unwrap_or_default()).build(),
            )
            .parts(
                aws_sdk_s3::types::CompletedPart::builder().part_number(2)
                    .e_tag(p2.e_tag().unwrap_or_default()).build(),
            )
            .build();
        c.complete_multipart_upload().bucket("sdk-mp").key("big.bin").upload_id(uid)
            .multipart_upload(done).send().await.expect("complete");
        let get = c.get_object().bucket("sdk-mp").key("big.bin").send().await.expect("get big");
        let body = get.body.collect().await.expect("collect").into_bytes();
        assert_eq!(body.as_ref(), b"part-one--part-two");
    });
}

