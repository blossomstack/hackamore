//! AWS Signature Version 4 — the one outbound auth mechanism that is a *request
//! transform* rather than a header set. halter re-signs an allowed request with the real
//! account credential before forwarding (the consumer never holds it). The same
//! primitive [`verify`]s an inbound signature against a minted dummy credential.
//!
//! Built on `ring` (SHA-256 + HMAC), no AWS SDK. Two things matter for real-CLI fidelity:
//!
//! 1. **The inbound check honors the request's own `SignedHeaders`.** A real `aws` CLI
//!    signs a larger, service-specific header set than halter's own minimal signer; we
//!    must recompute the canonical request over *exactly* the headers the client listed,
//!    reading their live values, not a fixed set.
//! 2. **Canonicalization matches AWS.** URI paths and query strings are percent-encoded
//!    per the SigV4 rules (so e.g. S3 keys with spaces sign correctly), and the request's
//!    `x-amz-date` is checked against a freshness window to bound replay.

use ring::{digest, hmac};

/// Maximum clock skew between the request's `x-amz-date` and halter's clock. Outside this
/// window an inbound signature is rejected as stale (replay/clock-skew bound). AWS itself
/// uses 5 minutes.
const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// An AWS credential pair.
pub struct Creds<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
}

/// The headers a caller must set on the outbound request to make it SigV4-signed.
pub struct Signed {
    pub authorization: String,
    pub amz_date: String,
    pub content_sha256: String,
}

/// halter's own outbound signer uses this minimal header set — the common AWS request
/// shape, accepted by every service. (The *inbound* check is not limited to this set; it
/// honors whatever the client signed.)
const OUTBOUND_SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

/// Sign a request, returning the `Authorization`, `X-Amz-Date`, and `X-Amz-Content-Sha256`
/// header values. `canonical_uri` is the (already `/`-prefixed) path; `query` is the raw
/// query string; `epoch_ms` is the signing time.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    creds: &Creds,
    region: &str,
    service: &str,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    body: &[u8],
    epoch_ms: u64,
) -> Signed {
    let (amz_date, datestamp) = format_amz_datetime(epoch_ms);
    let content_sha256 = sha256_hex(body);
    let headers = [
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), content_sha256.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let canonical = canonical_request(
        method,
        path,
        query,
        &headers,
        OUTBOUND_SIGNED_HEADERS,
        &content_sha256,
        double_encode_for(service),
    );
    let signature = signature_for(
        creds.secret_access_key,
        region,
        service,
        &amz_date,
        &datestamp,
        &canonical,
    );
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={OUTBOUND_SIGNED_HEADERS}, Signature={signature}",
        creds.access_key_id
    );
    Signed {
        authorization,
        amz_date,
        content_sha256,
    }
}

/// A parsed inbound SigV4 `Authorization` header.
pub struct Parsed {
    pub access_key_id: String,
    pub datestamp: String,
    pub region: String,
    pub service: String,
    /// The lowercase header names the client signed, in the order listed (already sorted by
    /// any conforming client). The canonical request must be recomputed over exactly these.
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Why an inbound SigV4 verification failed. A typed error so the data plane can audit the
/// precise cause (signature mismatch vs. a stale request vs. a missing signed header)
/// rather than a bare bool.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The recomputed signature did not match the presented one.
    Mismatch,
    /// The request's `x-amz-date` is outside the freshness window (or unparseable).
    Stale,
    /// A header the client listed in `SignedHeaders` is absent from the request.
    MissingSignedHeader(String),
}

/// Parse an `AWS4-HMAC-SHA256 Credential=AKID/<date>/<region>/<service>/aws4_request,
/// SignedHeaders=h1;h2, Signature=<sig>` header. Returns `None` if malformed.
pub fn parse_authorization(header: &str) -> Option<Parsed> {
    let rest = header.strip_prefix("AWS4-HMAC-SHA256")?.trim_start();
    let mut access_key_id = None;
    let mut scope: Option<(String, String, String)> = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(cred) = part.strip_prefix("Credential=") {
            let fields: Vec<&str> = cred.splitn(5, '/').collect();
            let [akid, date, region, service, _terminator] = fields.as_slice() else {
                continue;
            };
            access_key_id = Some((*akid).to_string());
            scope = Some((
                (*date).to_string(),
                (*region).to_string(),
                (*service).to_string(),
            ));
        } else if let Some(sh) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(
                sh.split(';')
                    .filter(|h| !h.is_empty())
                    .map(|h| h.to_ascii_lowercase())
                    .collect::<Vec<_>>(),
            );
        } else if let Some(sig) = part.strip_prefix("Signature=") {
            signature = Some(sig.to_string());
        }
    }
    let (datestamp, region, service) = scope?;
    let signed_headers = signed_headers.filter(|h: &Vec<String>| !h.is_empty())?;
    Some(Parsed {
        access_key_id: access_key_id?,
        datestamp,
        region,
        service,
        signed_headers,
        signature: signature?,
    })
}

/// Verify an inbound signature against `secret`, recomputing the canonical request over the
/// header set the client actually signed (`parsed.signed_headers`, read live from
/// `headers`). `now_ms` bounds replay via the `x-amz-date` freshness window. The body is
/// used to compute the payload hash when the request carries no `x-amz-content-sha256`.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    secret: &str,
    parsed: &Parsed,
    method: &str,
    path: &str,
    query: &str,
    headers: &http::HeaderMap,
    body: &[u8],
    now_ms: u64,
) -> Result<(), VerifyError> {
    // Freshness: the signed `x-amz-date` must be within the skew window of halter's clock.
    let amz_date = header_value(headers, "x-amz-date").ok_or(VerifyError::Stale)?;
    let signed_ms = parse_amz_datetime(&amz_date).ok_or(VerifyError::Stale)?;
    if now_ms.abs_diff(signed_ms) > MAX_SKEW_MS {
        return Err(VerifyError::Stale);
    }

    // Collect the live values for every signed header, failing closed if one is absent.
    let mut signed: Vec<(String, String)> = Vec::with_capacity(parsed.signed_headers.len());
    for name in &parsed.signed_headers {
        let value = header_value(headers, name)
            .ok_or_else(|| VerifyError::MissingSignedHeader(name.clone()))?;
        signed.push((name.clone(), value));
    }

    // Payload hash: the request's `x-amz-content-sha256` if present (what the client
    // signed), else the SHA-256 of the buffered body.
    let payload_hash =
        header_value(headers, "x-amz-content-sha256").unwrap_or_else(|| sha256_hex(body));

    let signed_headers_str = parsed.signed_headers.join(";");
    let canonical = canonical_request(
        method,
        path,
        query,
        &signed,
        &signed_headers_str,
        &payload_hash,
        double_encode_for(&parsed.service),
    );
    let expected = signature_for(
        secret,
        &parsed.region,
        &parsed.service,
        &amz_date,
        &parsed.datestamp,
        &canonical,
    );
    if constant_time_eq(expected.as_bytes(), parsed.signature.as_bytes()) {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// Build the SigV4 canonical request string. `headers` are `(lowercase-name, value)` pairs
/// for exactly the signed set; they are sorted and value-trimmed here. `double_encode`
/// applies the second URI-encode pass that every non-S3 service expects.
fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    signed_headers: &str,
    payload_hash: &str,
    double_encode: bool,
) -> String {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.clone(), trim_header_value(v)))
        .collect();
    sorted.sort();
    let canonical_headers: String = sorted.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_uri(path, double_encode),
        canonical_query(query),
    )
}

/// `string_to_sign` ∘ `derive_signing_key` ∘ HMAC — the signature for a canonical request.
fn signature_for(
    secret: &str,
    region: &str,
    service: &str,
    amz_date: &str,
    datestamp: &str,
    canonical_request: &str,
) -> String {
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = derive_signing_key(secret, datestamp, region, service);
    to_hex(&hmac256(&signing_key, string_to_sign.as_bytes()))
}

/// The SigV4 signing-key derivation chain.
fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac256(&k_date, region.as_bytes());
    let k_service = hmac256(&k_region, service.as_bytes());
    hmac256(&k_service, b"aws4_request")
}

/// Whether a service double-URI-encodes the canonical path. Every AWS service except S3
/// does; S3 uses the path as-is.
fn double_encode_for(service: &str) -> bool {
    !service.eq_ignore_ascii_case("s3")
}

/// The canonical URI: an empty path becomes `/`; non-S3 services URI-encode the (already
/// wire-encoded) path a second time, preserving `/`. S3 uses the path verbatim.
fn canonical_uri(path: &str, double_encode: bool) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if double_encode {
        uri_encode(path.as_bytes(), false)
    } else {
        path.to_string()
    }
}

/// Canonicalize a query string per SigV4: decode each `k=v` pair, re-encode key and value
/// (slashes included), and sort by encoded key then value.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (
                uri_encode(&percent_decode(k), true),
                uri_encode(&percent_decode(v), true),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// SigV4 URI-encode: every byte except the unreserved set `A-Za-z0-9-_.~` is `%`-escaped
/// with uppercase hex. `/` is left intact when `encode_slash` is false (path encoding).
/// Shared with [`crate::canonicalize`], which re-encodes path segments the same way.
pub(crate) fn uri_encode(input: &[u8], encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode `%XX` escapes (and `+` as space) into raw bytes. Malformed escapes pass through
/// literally — canonicalization is best-effort recovery, the signature check is the gate.
/// Shared with [`crate::canonicalize`].
pub(crate) fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Trim leading/trailing whitespace and collapse internal runs of spaces, as SigV4 header
/// canonicalization requires.
fn trim_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_space = false;
    for c in value.trim().chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Format epoch milliseconds as the SigV4 `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` strings (UTC).
fn format_amz_datetime(epoch_ms: u64) -> (String, String) {
    let secs = (epoch_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Parse a SigV4 `YYYYMMDDTHHMMSSZ` timestamp back to epoch milliseconds (UTC). Returns
/// `None` if the shape is wrong — treated as a stale/invalid request by the caller.
fn parse_amz_datetime(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |a: usize, z: usize| s.get(a..z).and_then(|v| v.parse::<i64>().ok());
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, se) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    u64::try_from(secs * 1000).ok()
}

/// Convert days-since-Unix-epoch to a civil (year, month, day). Howard Hinnant's
/// `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Convert a civil (year, month, day) to days-since-Unix-epoch. Howard Hinnant's
/// `days_from_civil`, the inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn datetime_round_trips_known_epoch() {
        // 2012-02-15T00:00:00Z = 1329264000 s.
        let (amz, date) = format_amz_datetime(1_329_264_000_000);
        assert_eq!(amz, "20120215T000000Z");
        assert_eq!(date, "20120215");
        assert_eq!(parse_amz_datetime(&amz), Some(1_329_264_000_000));
        assert_eq!(parse_amz_datetime("nope"), None);
        assert_eq!(parse_amz_datetime("20120215T000000X"), None);
    }

    #[test]
    fn signing_key_matches_aws_documented_vector() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            to_hex(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn matches_aws_sig_v4_test_suite_get_vanilla() {
        // The canonical "get-vanilla" vector from AWS's published SigV4 test suite: a bare
        // GET signed over host;x-amz-date for the synthetic "service" service. Validates the
        // whole canonical-request → string-to-sign → signature chain against AWS's own
        // expected output, including generic (non-minimal) signed-header handling.
        let parsed = Parsed {
            access_key_id: "AKIDEXAMPLE".into(),
            datestamp: "20150830".into(),
            region: "us-east-1".into(),
            service: "service".into(),
            signed_headers: vec!["host".into(), "x-amz-date".into()],
            signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31".into(),
        };
        let h = headers(&[
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ]);
        let now = parse_amz_datetime("20150830T123600Z").unwrap();
        assert_eq!(
            verify(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                &parsed,
                "GET",
                "/",
                "",
                &h,
                b"",
                now,
            ),
            Ok(())
        );
    }

    #[test]
    fn parses_authorization_with_signed_headers() {
        let h = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20231114/us-east-1/ec2/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abcd1234";
        let p = parse_authorization(h).unwrap();
        assert_eq!(p.access_key_id, "AKIDEXAMPLE");
        assert_eq!(p.datestamp, "20231114");
        assert_eq!(p.region, "us-east-1");
        assert_eq!(p.service, "ec2");
        assert_eq!(
            p.signed_headers,
            vec!["host", "x-amz-content-sha256", "x-amz-date"]
        );
        assert_eq!(p.signature, "abcd1234");
        // Missing SignedHeaders → unparseable (fail closed).
        assert!(
            parse_authorization("AWS4-HMAC-SHA256 Credential=A/d/r/s/aws4_request, Signature=x")
                .is_none()
        );
        assert!(parse_authorization("Bearer xyz").is_none());
    }

    #[test]
    fn sign_then_verify_round_trips_and_detects_tampering() {
        let creds = Creds {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "secret-key",
        };
        let now = 1_700_000_000_000;
        let body = b"Action=DescribeInstances&Version=2016-11-15";
        let signed = sign(
            &creds,
            "us-east-1",
            "ec2",
            "POST",
            "ec2.us-east-1.amazonaws.com",
            "/",
            "",
            body,
            now,
        );
        let h = headers(&[
            ("host", "ec2.us-east-1.amazonaws.com"),
            ("x-amz-date", &signed.amz_date),
            ("x-amz-content-sha256", &signed.content_sha256),
            ("authorization", &signed.authorization),
        ]);
        let parsed = parse_authorization(&signed.authorization).unwrap();
        assert_eq!(
            verify("secret-key", &parsed, "POST", "/", "", &h, body, now),
            Ok(())
        );
        // Wrong secret → mismatch.
        assert_eq!(
            verify("WRONG", &parsed, "POST", "/", "", &h, body, now),
            Err(VerifyError::Mismatch)
        );
        // Outside the skew window → stale.
        assert_eq!(
            verify(
                "secret-key",
                &parsed,
                "POST",
                "/",
                "",
                &h,
                body,
                now + MAX_SKEW_MS + 1
            ),
            Err(VerifyError::Stale)
        );
    }

    #[test]
    fn verify_honors_larger_signed_header_set() {
        // A client that signs an extra header (x-custom) — the way a real CLI signs a
        // service-specific set — must verify only when that header's live value is present
        // and unchanged.
        let creds = Creds {
            access_key_id: "AKID",
            secret_access_key: "sk",
        };
        let now = 1_700_000_000_000;
        let (amz_date, datestamp) = format_amz_datetime(now);
        let content = sha256_hex(b"");
        // Hand-build a request signed over host;x-amz-date;x-custom.
        let signed_headers = "x-amz-date;x-custom";
        let hdrs = [
            ("x-amz-date".to_string(), amz_date.clone()),
            ("x-custom".to_string(), "Value".to_string()),
        ];
        let canonical = canonical_request("GET", "/", "", &hdrs, signed_headers, &content, true);
        let sig = signature_for(
            creds.secret_access_key,
            "us-east-1",
            "ec2",
            &amz_date,
            &datestamp,
            &canonical,
        );
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential=AKID/{datestamp}/us-east-1/ec2/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
        );
        let parsed = parse_authorization(&auth).unwrap();
        let h = headers(&[("x-amz-date", &amz_date), ("x-custom", "Value")]);
        assert_eq!(verify("sk", &parsed, "GET", "/", "", &h, b"", now), Ok(()));
        // Drop the signed custom header → fail closed.
        let h_missing = headers(&[("x-amz-date", &amz_date)]);
        assert_eq!(
            verify("sk", &parsed, "GET", "/", "", &h_missing, b"", now),
            Err(VerifyError::MissingSignedHeader("x-custom".into()))
        );
    }

    #[test]
    fn uri_and_query_canonicalization() {
        assert_eq!(uri_encode(b"/foo bar/x", false), "/foo%20bar/x");
        assert_eq!(uri_encode(b"a/b", true), "a%2Fb");
        // Sorted by encoded key; spaces become %20; values encoded.
        assert_eq!(canonical_query("b=2&a=hello world"), "a=hello%20world&b=2");
        // Already-encoded input is decoded then re-encoded canonically.
        assert_eq!(canonical_query("k=a%2Bb"), "k=a%2Bb");
    }

    #[test]
    fn header_value_whitespace_is_collapsed() {
        assert_eq!(trim_header_value("  a   b  "), "a b");
    }
}
