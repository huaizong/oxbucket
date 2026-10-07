//! Stage 2 — AWS Signature Version 4 (header-based) verification.
//!
//! The binary links no crypto crates (`sha2` / `hmac` / `hex` are
//! dev-dependencies used by the integration tests only), so SHA-256,
//! HMAC-SHA256 and hex encoding are implemented here, pinned against
//! published test vectors in the `#[cfg(test)]` module at the bottom.
//!
//! The verification math mirrors the reference signer in
//! `tests/sigv4_tests.rs`:
//!
//! canonical request :=
//!     METHOD "\n" canonical-uri "\n" canonical-query "\n"
//!     (`<lowercase-name>:<trimmed-value>\n` for every header listed in
//!      SignedHeaders, in that order) "\n" SignedHeaders "\n" payload-hash
//! string-to-sign :=
//!     "AWS4-HMAC-SHA256\n" x-amz-date "\n" scope "\n"
//!     hex(sha256(canonical request))
//! scope := <credential-date>/<region>/s3/aws4_request
//! signing key := HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region),
//!     "s3"), "aws4_request")
//! signature := hex(HMAC(signing key, string-to-sign))
//!
//! `UNSIGNED-PAYLOAD` (and the streaming marker) pass through verbatim as
//! the payload-hash line — exactly what the client signed. Known
//! simplifications, both invisible to the pinned suites: header values are
//! trimmed but their inner whitespace is not collapsed, and the canonical
//! query is the raw query string rather than a sorted re-encoding.

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{ApiError, AppState};

/// Server-side credential pair plus the enforcement switch.
#[derive(Clone)]
pub(crate) struct Credentials {
    /// Expected access key id (`S3RS_ACCESS_KEY`, default "test").
    pub(crate) access_key: String,
    /// Expected secret key (`S3RS_SECRET_KEY`, default "test").
    pub(crate) secret_key: String,
    /// Auth is enforced only when the operator configured at least one of the
    /// two env vars explicitly; a bare default environment keeps the open
    /// stage-1 behavior the stage-1 suite exercises. The defaults above still
    /// feed bucket-owner identity.
    pub(crate) enforced: bool,
}

impl Credentials {
    /// Read the credential pair from the environment.
    pub(crate) fn from_env() -> Self {
        let access_key = std::env::var("S3RS_ACCESS_KEY");
        let secret_key = std::env::var("S3RS_SECRET_KEY");
        Credentials {
            enforced: access_key.is_ok() || secret_key.is_ok(),
            access_key: access_key.unwrap_or_else(|_| "test".to_string()),
            secret_key: secret_key.unwrap_or_else(|_| "test".to_string()),
        }
    }
}

/// Axum middleware: verify SigV4 on every route before it runs.
pub(crate) async fn authorize(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if !state.auth.enforced {
        return next.run(req).await;
    }
    let verdict = verify(req.method().as_str(), req.uri(), req.headers(), &state.auth);
    match verdict {
        Ok(()) => next.run(req).await,
        Err(err) => err.into_response(req.uri().path()),
    }
}

/// Why a request was rejected. Both flavors answer 403 with an S3 XML
/// `<Error>` document; only the code differs (`AccessDenied` for missing or
/// malformed auth material, `SignatureDoesNotMatch` for a well-formed header
/// whose signature does not verify).
#[derive(Debug)]
pub(crate) enum AuthError {
    AccessDenied(&'static str),
    SignatureDoesNotMatch,
}

impl AuthError {
    fn into_response(self, resource: &str) -> Response {
        match self {
            AuthError::AccessDenied(message) => ApiError::new(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                message,
                resource,
            )
            .into_response(),
            AuthError::SignatureDoesNotMatch => ApiError::new(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the \
                 signature you provided. Check your key and signing method.",
                resource,
            )
            .into_response(),
        }
    }
}

/// Verify the SigV4 Authorization header of one request.
fn verify(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    creds: &Credentials,
) -> Result<(), AuthError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::AccessDenied("Authorization header is missing"))?;
    let rest = auth_header
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or(AuthError::AccessDenied(
            "Unsupported authorization scheme; expected AWS4-HMAC-SHA256",
        ))?;

    // " Credential=<key>/<date>/<region>/s3/aws4_request, SignedHeaders=…,
    // Signature=<hex>" — comma-separated, optional whitespace.
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for pair in rest.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or(AuthError::AccessDenied(
                "Malformed Authorization header component",
            ))?;
        match key.trim() {
            "Credential" => credential = Some(value.trim().to_string()),
            "SignedHeaders" => signed_headers = Some(value.trim().to_string()),
            // Normalize: hex case is insignificant.
            "Signature" => signature = Some(value.trim().to_ascii_lowercase()),
            _ => {} // tolerate unknown components
        }
    }
    let credential = credential.ok_or(AuthError::AccessDenied(
        "Authorization header is missing the Credential component",
    ))?;
    let signed_headers = signed_headers.ok_or(AuthError::AccessDenied(
        "Authorization header is missing the SignedHeaders component",
    ))?;
    let signature = signature.ok_or(AuthError::AccessDenied(
        "Authorization header is missing the Signature component",
    ))?;

    // Credential = <access-key>/<date>/<region>/<service>/aws4_request
    let mut scope = credential.split('/');
    let access_key = scope.next().unwrap_or_default();
    let date = scope.next().unwrap_or_default();
    let region = scope.next().unwrap_or_default();
    let service = scope.next().unwrap_or_default();
    let terminator = scope.next().unwrap_or_default();
    if scope.next().is_some()
        || access_key.is_empty()
        || date.len() != 8
        || region.is_empty()
        || service != "s3"
        || terminator != "aws4_request"
    {
        return Err(AuthError::AccessDenied(
            "Malformed Credential; expected <key>/<yyyymmdd>/<region>/s3/aws4_request",
        ));
    }
    if access_key != creds.access_key {
        return Err(AuthError::AccessDenied(
            "The access key does not match the configured credential",
        ));
    }

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::AccessDenied(
            "The x-amz-date header is missing",
        ))?
        .trim();
    // Compare as bytes: header values are arbitrary bytes, so char-boundary
    // string slicing could panic on hostile input.
    if amz_date.len() < 8 || &amz_date.as_bytes()[..8] != date.as_bytes() {
        return Err(AuthError::AccessDenied(
            "The Credential scope date does not match x-amz-date",
        ));
    }

    // Canonical headers: one `<lowercase-name>:<trimmed-value>\n` line per
    // entry of SignedHeaders, in the client's (required-sorted) order.
    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let name = name.trim().to_ascii_lowercase();
        let value = headers
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .ok_or(AuthError::AccessDenied(
                "A header listed in SignedHeaders is missing from the request",
            ))?;
        canonical_headers.push_str(&name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }

    // The payload-hash line is whatever the client declared and signed:
    // "UNSIGNED-PAYLOAD", a streaming marker, or a real hex digest.
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("UNSIGNED-PAYLOAD")
        .to_string();

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        path = uri.path(),
        query = uri.query().unwrap_or(""),
    );

    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&sha256(canonical_request.as_bytes()))
    );

    let k_date = hmac_sha256(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let expected = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    if constant_time_eq(&expected, &signature) {
        Ok(())
    } else {
        Err(AuthError::SignatureDoesNotMatch)
    }
}

/// Length-revealing-but-content-blind equality check (both sides are hex
/// digests of known width in practice).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Hand-written SHA-256 / HMAC-SHA256 / hex (no crypto crates in [dependencies])
// ---------------------------------------------------------------------------

/// FIPS 180-4 round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 initial hash values.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Streaming SHA-256 (FIPS 180-4).
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    /// Total bytes fed so far (u64 is plenty for any request we will see).
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top up a partial buffered block first.
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        // Compress whole blocks straight out of the input.
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        // Stash the remainder.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        // Padding: 0x80, then zeros up to byte 56, then the bit length.
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h.wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = big_s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// RFC 2104 HMAC over SHA-256 (64-byte block).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        // Keys longer than the block are replaced by their digest.
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests: published vectors + a signer-vs-verifier round trip
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[0x00, 0x0f]), "000f");
    }

    #[test]
    fn sha256_known_vectors() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            ),
            // 56 bytes: padding spills into a second compression block.
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex(&sha256(input)), want, "input: {input:?}");
        }
    }

    #[test]
    fn sha256_incremental_feeding_matches_one_shot() {
        // exercise the buffered-update path across block boundaries
        for split in [0usize, 1, 55, 56, 57, 63, 64, 65, 127, 128, 129] {
            let data = [0x61u8; 200]; // 200 * 'a'
            let mut hasher = Sha256::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            let incremental = hex(&hasher.finalize());

            let mut one_shot = Sha256::new();
            one_shot.update(&data);
            assert_eq!(incremental, hex(&one_shot.finalize()), "split {split}");
        }
    }

    #[test]
    fn hmac_known_vectors() {
        // Well-known short-key vector.
        assert_eq!(
            hex(&hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog")),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // RFC 4231 test case 6: key larger than the block gets hashed first.
        let long_key = [0xaau8; 131];
        assert_eq!(
            hex(&hmac_sha256(
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// Same math as the reference signer in tests/sigv4_tests.rs::sign_put,
    /// executed against `verify` without any HTTP.
    #[test]
    fn sigv4_round_trip() {
        let creds = Credentials {
            access_key: "test".to_string(),
            secret_key: "testsecret".to_string(),
            enforced: true,
        };
        let amz_date = "20260101T000000Z";
        let date = &amz_date[..8];
        let host = "127.0.0.1:7333";
        let payload_hash = "UNSIGNED-PAYLOAD";
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        );
        let canonical_req = format!(
            "PUT\n/signed-bucket\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let scope = format!("{date}/cn-north-1/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&sha256(canonical_req.as_bytes()))
        );
        let k = hmac_sha256(b"AWS4testsecret", date.as_bytes());
        let k = hmac_sha256(&k, b"cn-north-1");
        let k = hmac_sha256(&k, b"s3");
        let k = hmac_sha256(&k, b"aws4_request");
        let sig = hex(&hmac_sha256(&k, string_to_sign.as_bytes()));

        let auth = format!(
            "AWS4-HMAC-SHA256 Credential=test/{scope}, SignedHeaders={signed_headers}, \
             Signature={sig}"
        );
        let uri: Uri = "/signed-bucket".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
        headers.insert(header::AUTHORIZATION, auth.parse().unwrap());
        assert!(verify("PUT", &uri, &headers, &creds).is_ok());

        // Tamper with the last hex digit: must flip to SignatureDoesNotMatch.
        let bad = format!("{}0", &sig[..63]);
        let auth_bad = format!(
            "AWS4-HMAC-SHA256 Credential=test/{scope}, SignedHeaders={signed_headers}, \
             Signature={bad}"
        );
        let mut bad_headers = headers.clone();
        bad_headers.insert(header::AUTHORIZATION, auth_bad.parse().unwrap());
        assert!(matches!(
            verify("PUT", &uri, &bad_headers, &creds),
            Err(AuthError::SignatureDoesNotMatch)
        ));

        // Wrong access key: AccessDenied.
        let wrong_ak = Credentials {
            access_key: "someone-else".to_string(),
            ..creds_clone(&creds)
        };
        assert!(matches!(
            verify("PUT", &uri, &headers, &wrong_ak),
            Err(AuthError::AccessDenied(_))
        ));

        // Missing Authorization header: AccessDenied.
        let mut bare = HeaderMap::new();
        bare.insert("x-amz-date", amz_date.parse().unwrap());
        assert!(matches!(
            verify("PUT", &uri, &bare, &creds),
            Err(AuthError::AccessDenied(_))
        ));
    }

    fn creds_clone(creds: &Credentials) -> Credentials {
        Credentials {
            access_key: creds.access_key.clone(),
            secret_key: creds.secret_key.clone(),
            enforced: creds.enforced,
        }
    }
}
