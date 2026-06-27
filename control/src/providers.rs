//! Minting, rotating credential providers.
//!
//! The base [`crate::credentials::InMemoryCredentials`] vault is static: an id maps to a
//! pre-provisioned secret. Real upstreams instead want *short-lived* credentials minted on
//! demand and rotated before they expire — an AWS EKS `get-token` (a presigned STS URL,
//! ~15 min) or a GitHub-App installation token (~1 h). This module adds that without
//! changing the data plane: a [`CredentialProvider`] mints a secret, and
//! [`CachingCredentials`] caches the latest minted value behind the *synchronous*
//! [`CredentialStore`] the gateway already calls on the request path. A background refresher
//! ([`CachingCredentials::refresh_due`], driven by [`spawn_refresher`]) re-mints before
//! expiry, so `resolve` stays fast and never blocks — and **fails closed**: until a value is
//! minted, `resolve` returns `None` and the request is denied.

use crate::credentials::{AwsCredential, CredentialStore, Secret};
use base64::Engine;
use parking_lot::RwLock;
use ring::{digest, hmac, rand, signature};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A freshly minted secret and when it expires (epoch ms).
#[derive(Clone)]
pub struct MintedSecret {
    pub secret: Secret,
    pub expires_at_ms: u64,
}

/// Mints a short-lived upstream credential, and re-mints it on rotation. Async because real
/// minters call out (the GitHub-App exchange is HTTP; the EKS presign is local but shares
/// the signature). Returns the secret and its expiry; an error fails closed (the cache keeps
/// the previous value until it too expires).
pub trait CredentialProvider: Send + Sync {
    /// Mint a fresh secret as of `now_ms`.
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>>;

    /// Re-mint this many milliseconds *before* the cached secret expires, to rotate without
    /// a gap. Defaults to one minute.
    fn refresh_skew_ms(&self) -> u64 {
        60_000
    }
}

/// A freshly minted AWS credential bundle. Mirrors [`MintedSecret`], but the expiry lives in
/// the bundle (`cred.expires_at_ms`) rather than alongside it.
#[derive(Clone, Debug)]
pub struct MintedAws {
    pub cred: AwsCredential,
}

/// Mints a short-lived AWS credential *bundle* (akid + secret + session token + expiry), and
/// re-mints it on rotation. The AWS analogue of [`CredentialProvider`], for the one source
/// kind whose material is a triple, not a single token: STS `AssumeRole`, the instance chain,
/// EKS. Async because the real minters call out (the AssumeRole exchange is HTTP). An error
/// fails closed (the cache keeps the previous bundle until it too expires).
pub trait AwsCredentialProvider: Send + Sync {
    /// Mint a fresh bundle as of `now_ms`.
    fn mint_aws(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredential, String>> + Send + '_>>;

    /// Re-mint this many milliseconds *before* the cached bundle expires. One minute.
    fn refresh_skew_ms(&self) -> u64 {
        60_000
    }
}

/// A credential store that serves the latest minted value for each provider-backed id, and
/// pre-seeded static secrets for the rest. The data plane calls [`CredentialStore::resolve`]
/// / [`CredentialStore::resolve_aws`] (sync); minting happens out of band in
/// [`Self::refresh_due`]. AWS bundles get a parallel provider + cache map, so a token-shaped
/// and a bundle-shaped credential never collide on the same id.
pub struct CachingCredentials {
    static_secrets: RwLock<HashMap<String, Secret>>,
    providers: HashMap<String, Arc<dyn CredentialProvider>>,
    cache: RwLock<HashMap<String, MintedSecret>>,
    /// Static AWS bundles (an `aws-static` source, or an IAM-user key pair) registered at
    /// runtime — served directly by `resolve_aws` with no minting.
    static_aws: RwLock<HashMap<String, AwsCredential>>,
    /// AWS-bundle minting providers (assume-role / instance), registered at runtime.
    aws_providers: RwLock<HashMap<String, Arc<dyn AwsCredentialProvider>>>,
    /// The latest minted bundle for each AWS provider id.
    aws_cache: RwLock<HashMap<String, AwsCredential>>,
}

impl CachingCredentials {
    /// A store with the given static secrets and minting providers. Ids must be disjoint;
    /// a provider id shadows a static one of the same name.
    pub fn new(
        static_secrets: HashMap<String, Secret>,
        providers: HashMap<String, Arc<dyn CredentialProvider>>,
    ) -> Self {
        Self {
            static_secrets: RwLock::new(static_secrets),
            providers,
            cache: RwLock::new(HashMap::new()),
            static_aws: RwLock::new(HashMap::new()),
            aws_providers: RwLock::new(HashMap::new()),
            aws_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Register or replace a static secret (used in tests and for late-bound config).
    pub fn insert_static(&self, id: impl Into<String>, secret: Secret) {
        self.static_secrets.write().insert(id.into(), secret);
    }

    /// Register or replace an AWS-bundle minting provider at runtime. The next
    /// [`Self::refresh_due`] mints it; until then `resolve_aws` fails closed for the id.
    pub fn insert_aws_provider(&self, id: String, provider: Arc<dyn AwsCredentialProvider>) {
        self.aws_providers.write().insert(id, provider);
    }

    /// Mint every provider-backed credential (token *and* AWS) whose cached value is missing
    /// or within its refresh skew of expiry. Returns the ids (re)minted. Errors are logged
    /// and skipped so one failing provider doesn't stall the others.
    pub async fn refresh_due(&self, now_ms: u64) -> Vec<String> {
        let mut refreshed = Vec::new();
        for (id, provider) in &self.providers {
            if !self.needs_refresh(id, provider.as_ref(), now_ms) {
                continue;
            }
            match provider.mint(now_ms).await {
                Ok(minted) => {
                    self.cache.write().insert(id.clone(), minted);
                    refreshed.push(id.clone());
                }
                Err(e) => tracing::warn!(credential = %id, "credential mint failed: {e}"),
            }
        }
        // AWS-bundle providers, snapshotted so the lock isn't held across `.await`.
        let aws: Vec<(String, Arc<dyn AwsCredentialProvider>)> = self
            .aws_providers
            .read()
            .iter()
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, provider) in aws {
            if !self.aws_needs_refresh(&id, provider.as_ref(), now_ms) {
                continue;
            }
            match provider.mint_aws(now_ms).await {
                Ok(cred) => {
                    self.aws_cache.write().insert(id.clone(), cred);
                    refreshed.push(id.clone());
                }
                Err(e) => tracing::warn!(credential = %id, "aws credential mint failed: {e}"),
            }
        }
        refreshed
    }

    fn needs_refresh(&self, id: &str, provider: &dyn CredentialProvider, now_ms: u64) -> bool {
        match self.cache.read().get(id) {
            None => true,
            Some(m) => now_ms.saturating_add(provider.refresh_skew_ms()) >= m.expires_at_ms,
        }
    }

    /// An AWS bundle needs (re)minting when it is uncached, or within skew of its expiry. A
    /// cached bundle with no expiry never rotates on a timer (a static IAM key shouldn't be
    /// served through a provider, but if one is, leave it).
    fn aws_needs_refresh(
        &self,
        id: &str,
        provider: &dyn AwsCredentialProvider,
        now_ms: u64,
    ) -> bool {
        match self.aws_cache.read().get(id) {
            None => true,
            Some(c) => match c.expires_at_ms {
                Some(exp) => now_ms.saturating_add(provider.refresh_skew_ms()) >= exp,
                None => false,
            },
        }
    }
}

impl CredentialStore for CachingCredentials {
    fn resolve(&self, id: &str) -> Option<Secret> {
        if let Some(s) = self.static_secrets.read().get(id) {
            return Some(s.clone());
        }
        // Provider-backed: serve the cached minted value (the refresher keeps it fresh).
        // Absent ⇒ not yet minted ⇒ fail closed.
        self.cache.read().get(id).map(|m| m.secret.clone())
    }

    fn resolve_aws(&self, id: &str) -> Option<AwsCredential> {
        if let Some(c) = self.static_aws.read().get(id) {
            return Some(c.clone());
        }
        // Provider-backed AWS bundle: serve the cached minted bundle. Absent ⇒ not yet
        // minted ⇒ fail closed.
        self.aws_cache.read().get(id).cloned()
    }

    fn insert_runtime(&self, id: String, secret: Secret) -> bool {
        // A live-registered service's inline secret joins the static set (a provider id of
        // the same name would still shadow it on resolve, as documented in `new`).
        self.static_secrets.write().insert(id, secret);
        true
    }

    fn insert_aws_runtime(&self, id: String, cred: AwsCredential) -> bool {
        self.static_aws.write().insert(id, cred);
        true
    }

    fn register_aws_provider(
        &self,
        id: String,
        provider: Box<dyn std::any::Any + Send + Sync>,
    ) -> bool {
        // The data plane hands the provider type-erased (the `CredentialStore` trait, in the
        // `credentials` module, can't name `AwsCredentialProvider`, which lives here). Recover
        // it; a wrong payload fails closed.
        match provider.downcast::<Arc<dyn AwsCredentialProvider>>() {
            Ok(p) => {
                self.insert_aws_provider(id, *p);
                true
            }
            Err(_) => false,
        }
    }

    fn ids(&self) -> Vec<String> {
        // The union of every credential this store can resolve (static + provider, token +
        // AWS), by id only (never the secret). Provider ids are included even before they
        // are minted, so an operator sees the configured set.
        let mut ids: std::collections::BTreeSet<String> =
            self.static_secrets.read().keys().cloned().collect();
        ids.extend(self.providers.keys().cloned());
        ids.extend(self.static_aws.read().keys().cloned());
        ids.extend(self.aws_providers.read().keys().cloned());
        ids.into_iter().collect()
    }
}

/// Spawn a background task that calls [`CachingCredentials::refresh_due`] every
/// `interval`, using `clock` for the current time. Priming and rotation both flow through
/// it. The task lives for the process; it is dropped when the runtime shuts down.
pub fn spawn_refresher(
    creds: Arc<CachingCredentials>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    interval: std::time::Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let refreshed = creds.refresh_due(clock()).await;
            if !refreshed.is_empty() {
                tracing::debug!(?refreshed, "rotated credentials");
            }
        }
    });
}

// ---------------------------------------------------------------------------------------
// AWS EKS get-token provider
// ---------------------------------------------------------------------------------------

/// Mints an EKS `get-token` credential: a presigned STS `GetCallerIdentity` URL (SigV4
/// query auth, scoped to the cluster via the signed `x-k8s-aws-id` header), base64url-
/// encoded with the `k8s-aws-v1.` prefix — exactly what `aws eks get-token` produces and
/// what the kubelet/`kubectl` send as a bearer token. Fully local: no network, just the
/// account credential and the SigV4 primitives.
pub struct EksGetTokenProvider {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub region: String,
    pub cluster_name: String,
}

/// EKS tokens are valid for 15 minutes; mint with that window.
const EKS_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;
/// STS presign expiry (seconds) baked into the URL.
const EKS_PRESIGN_EXPIRES: u64 = 900;

impl EksGetTokenProvider {
    /// Build the `k8s-aws-v1.<base64url(presigned-url)>` token for `now_ms`.
    pub fn token(&self, now_ms: u64) -> String {
        let url = self.presigned_url(now_ms);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
        format!("k8s-aws-v1.{encoded}")
    }

    fn presigned_url(&self, now_ms: u64) -> String {
        let host = format!("sts.{}.amazonaws.com", self.region);
        let (amz_date, datestamp) = format_amz_datetime(now_ms);
        let scope = format!("{datestamp}/{}/sts/aws4_request", self.region);
        let signed_headers = "host;x-k8s-aws-id";
        // Query params that participate in the signature (everything but X-Amz-Signature),
        // already in sorted order (uppercase 'A' params sort before lowercase 'k'/'V').
        let credential = format!("{}/{scope}", self.access_key_id);
        let expires = EKS_PRESIGN_EXPIRES.to_string();
        let params = [
            ("Action", "GetCallerIdentity"),
            ("Version", "2011-06-15"),
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", credential.as_str()),
            ("X-Amz-Date", amz_date.as_str()),
            ("X-Amz-Expires", expires.as_str()),
            ("X-Amz-SignedHeaders", signed_headers),
        ];
        let canonical_query = canonical_query(&params);
        let canonical_headers = format!("host:{host}\nx-k8s-aws-id:{}\n", self.cluster_name);
        let payload_hash = sha256_hex(b"");
        let canonical_request = format!(
            "GET\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = derive_signing_key(
            self.secret_access_key.expose(),
            &datestamp,
            &self.region,
            "sts",
        );
        let signature = to_hex(&hmac256(&signing_key, string_to_sign.as_bytes()));
        format!("https://{host}/?{canonical_query}&X-Amz-Signature={signature}")
    }
}

impl CredentialProvider for EksGetTokenProvider {
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
        let token = self.token(now_ms);
        Box::pin(async move {
            Ok(MintedSecret {
                secret: Secret::new(token),
                expires_at_ms: now_ms.saturating_add(EKS_TOKEN_TTL_MS),
            })
        })
    }
}

// ---------------------------------------------------------------------------------------
// GitHub App installation-token provider
// ---------------------------------------------------------------------------------------

/// Mints a GitHub-App installation token: sign a short-lived RS256 JWT with the app's
/// private key, then exchange it at `POST /app/installations/{id}/access_tokens` for an
/// installation token (~1 h). The JWT signing is local; the exchange is one HTTP call.
pub struct GitHubAppProvider {
    pub app_id: String,
    pub installation_id: String,
    /// The app's RSA private key in PKCS#8 DER (parse from PEM with [`pkcs8_from_pem`]).
    pub private_key_pkcs8_der: Vec<u8>,
    /// API base, e.g. `https://api.github.com` (override for GHES or a test mock).
    pub api_base: String,
    pub client: reqwest::Client,
}

/// GitHub installation tokens last an hour; refresh well before then.
const GH_TOKEN_TTL_MS: u64 = 55 * 60 * 1000;

impl GitHubAppProvider {
    /// Build the signed app JWT for `now_ms` (valid 60 s in the past to 9 min ahead, per
    /// GitHub's guidance to tolerate clock skew). Public for testing.
    pub fn app_jwt(&self, now_ms: u64) -> Result<String, String> {
        let now_s = now_ms / 1000;
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64url(
            format!(
                r#"{{"iat":{},"exp":{},"iss":"{}"}}"#,
                now_s.saturating_sub(60),
                now_s + 540,
                self.app_id
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let key = signature::RsaKeyPair::from_pkcs8(&self.private_key_pkcs8_der)
            .map_err(|e| format!("invalid app private key: {e}"))?;
        let mut sig = vec![0u8; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .map_err(|e| format!("jwt signing failed: {e}"))?;
        Ok(format!("{signing_input}.{}", b64url(&sig)))
    }
}

impl CredentialProvider for GitHubAppProvider {
    fn mint(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
        Box::pin(async move {
            let jwt = self.app_jwt(now_ms)?;
            let url = format!(
                "{}/app/installations/{}/access_tokens",
                self.api_base.trim_end_matches('/'),
                self.installation_id
            );
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&jwt)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header(reqwest::header::USER_AGENT, "hackamore")
                .send()
                .await
                .map_err(|e| format!("installation-token request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("installation-token HTTP {}", resp.status()));
            }
            let body: InstallationToken = resp
                .json()
                .await
                .map_err(|e| format!("installation-token decode failed: {e}"))?;
            Ok(MintedSecret {
                secret: Secret::new(body.token),
                expires_at_ms: now_ms.saturating_add(GH_TOKEN_TTL_MS),
            })
        })
    }
}

#[derive(serde::Deserialize)]
struct InstallationToken {
    token: String,
}

/// Decode a PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----`) into DER bytes for
/// [`GitHubAppProvider::private_key_pkcs8_der`].
pub fn pkcs8_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN PRIVATE KEY-----";
    let end = "-----END PRIVATE KEY-----";
    let start = pem.find(begin).ok_or("no PKCS#8 PRIVATE KEY block")?;
    let after = &pem[start + begin.len()..];
    let stop = after.find(end).ok_or("unterminated PRIVATE KEY block")?;
    let body: String = after[..stop].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("base64 decode key: {e}"))
}

// ---------------------------------------------------------------------------------------
// STS AssumeRole provider
// ---------------------------------------------------------------------------------------

/// Mints an AWS credential bundle via STS `AssumeRole`, signed with a base credential. The
/// base may itself be a temporary credential (its session token is then signed into the
/// request). The minted bundle's `expires_at_ms` (parsed from the STS `Expiration`) drives
/// rotation in [`CachingCredentials`]. One HTTP call per mint.
pub struct AssumeRoleProvider {
    /// The base credential that signs the AssumeRole request (e.g. the instance/env chain).
    pub base: AwsCredential,
    pub role_arn: String,
    pub role_session_name: String,
    pub region: String,
    /// The STS endpoint host, e.g. `sts.amazonaws.com` or `sts.us-east-1.amazonaws.com`.
    pub sts_endpoint: String,
    pub client: reqwest::Client,
}

/// AssumeRole's default session duration is one hour; rotate ahead of the parsed expiry, and
/// fall back to this window if the response carries no parseable `Expiration`.
const ASSUME_ROLE_TTL_MS: u64 = 55 * 60 * 1000;

impl AssumeRoleProvider {
    /// Build the SigV4-signed STS `AssumeRole` request for `now_ms`: the URL, the headers to
    /// set, and the form-urlencoded body. Pure (no network) so it is unit-testable. The base
    /// credential's session token, if any, is signed in as `x-amz-security-token`.
    pub fn build_signed_request(&self, now_ms: u64) -> (String, Vec<(String, String)>, String) {
        let host = self.sts_endpoint.clone();
        let body = format!(
            "Action=AssumeRole&RoleArn={}&RoleSessionName={}&Version=2011-06-15",
            uri_encode(self.role_arn.as_bytes()),
            uri_encode(self.role_session_name.as_bytes()),
        );
        let (amz_date, datestamp) = format_amz_datetime(now_ms);
        let content_type = "application/x-www-form-urlencoded";
        let payload_hash = sha256_hex(body.as_bytes());

        // Canonical headers must be sorted by name. `content-type` < `host` < `x-amz-content-
        // sha256` < `x-amz-date` < `x-amz-security-token`.
        let mut canonical_headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        let mut signed_names = vec!["content-type", "host", "x-amz-content-sha256", "x-amz-date"];
        if let Some(token) = &self.base.session_token {
            canonical_headers.push((
                "x-amz-security-token".to_string(),
                token.expose().to_string(),
            ));
            signed_names.push("x-amz-security-token");
        }
        let signed_headers = signed_names.join(";");
        let canonical_headers_str: String = canonical_headers
            .iter()
            .map(|(n, v)| format!("{n}:{v}\n"))
            .collect();
        // STS is not S3 → double-encode the path; the path is `/`.
        let canonical_request =
            format!("POST\n/\n\n{canonical_headers_str}\n{signed_headers}\n{payload_hash}");
        let scope = format!("{datestamp}/{}/sts/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = derive_signing_key(
            self.base.secret_access_key.expose(),
            &datestamp,
            &self.region,
            "sts",
        );
        let signature = to_hex(&hmac256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.base.access_key_id
        );

        let mut headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("x-amz-date".to_string(), amz_date),
            ("authorization".to_string(), authorization),
        ];
        if let Some(token) = &self.base.session_token {
            headers.push((
                "x-amz-security-token".to_string(),
                token.expose().to_string(),
            ));
        }
        (format!("https://{host}/"), headers, body)
    }

    /// Parse an STS `AssumeRole` XML response into an [`AwsCredential`]. Minimal robust
    /// extraction of the four tagged values (`AccessKeyId`, `SecretAccessKey`, `SessionToken`,
    /// `Expiration`) — the response shape is fixed. A missing required field is an error
    /// (fail closed). The `Expiration` (ISO-8601) parses to epoch ms; an unparseable one
    /// leaves `expires_at_ms = None` (the cache then treats it as eagerly refreshable).
    pub fn parse_response(xml: &str) -> Result<AwsCredential, String> {
        let access_key_id =
            extract_tag(xml, "AccessKeyId").ok_or("STS response missing AccessKeyId")?;
        let secret_access_key =
            extract_tag(xml, "SecretAccessKey").ok_or("STS response missing SecretAccessKey")?;
        let session_token =
            extract_tag(xml, "SessionToken").ok_or("STS response missing SessionToken")?;
        let expires_at_ms = extract_tag(xml, "Expiration").and_then(|e| parse_iso8601_to_ms(&e));
        Ok(AwsCredential {
            access_key_id,
            secret_access_key: Secret::new(secret_access_key),
            session_token: Some(Secret::new(session_token)),
            expires_at_ms,
        })
    }
}

impl AwsCredentialProvider for AssumeRoleProvider {
    fn mint_aws(
        &self,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<AwsCredential, String>> + Send + '_>> {
        Box::pin(async move {
            let (url, headers, body) = self.build_signed_request(now_ms);
            let mut builder = self.client.post(&url).body(body);
            for (name, value) in headers {
                // `host` is set by reqwest from the URL; setting it again is harmless but
                // skip it to avoid a duplicate.
                if name == "host" {
                    continue;
                }
                builder = builder.header(name, value);
            }
            let resp = builder
                .send()
                .await
                .map_err(|e| format!("assume-role request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("assume-role HTTP {}", resp.status()));
            }
            let xml = resp
                .text()
                .await
                .map_err(|e| format!("assume-role read body: {e}"))?;
            let mut cred = Self::parse_response(&xml)?;
            // If STS gave no parseable expiry, fall back to the default TTL so rotation still
            // happens (rather than caching forever).
            if cred.expires_at_ms.is_none() {
                cred.expires_at_ms = Some(now_ms.saturating_add(ASSUME_ROLE_TTL_MS));
            }
            Ok(cred)
        })
    }
}

/// Extract the text content of the first `<tag>…</tag>` in `xml`. Returns `None` if the tag
/// is absent. Minimal — the STS response is well-formed and the four credential fields appear
/// once each, nested under `<Credentials>`.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Parse an ISO-8601 `YYYY-MM-DDTHH:MM:SSZ` (the STS `Expiration` format, optionally with a
/// fractional-second suffix before the `Z`) to epoch milliseconds (UTC). Returns `None` on a
/// shape it doesn't recognize.
fn parse_iso8601_to_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    // Strip an optional trailing `Z` and any fractional seconds.
    let core = s.strip_suffix('Z').unwrap_or(s);
    let core = core.split('.').next().unwrap_or(core);
    let bytes = core.as_bytes();
    // Expect YYYY-MM-DDTHH:MM:SS (19 chars).
    if bytes.len() != 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let num = |a: usize, z: usize| core.get(a..z).and_then(|v| v.parse::<i64>().ok());
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    u64::try_from(secs * 1000).ok()
}

/// Convert a civil (year, month, day) to days-since-Unix-epoch (Howard Hinnant). The inverse
/// of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------------------
// SigV4 / encoding primitives (kept local to avoid a control→gateway dependency)
// ---------------------------------------------------------------------------------------

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical SigV4 query string from already-sorted `(name, value)` params: URI-encode each
/// (slashes included) and join with `&`.
fn canonical_query(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k.as_bytes()), uri_encode(v.as_bytes())))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac256(&k_date, region.as_bytes());
    let k_service = hmac256(&k_region, service.as_bytes());
    hmac256(&k_service, b"aws4_request")
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

/// Format epoch ms as the SigV4 `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` strings (UTC).
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn eks_token_has_expected_shape_and_is_deterministic() {
        let p = EksGetTokenProvider {
            access_key_id: "AKIDTEST".into(),
            secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            region: "us-east-1".into(),
            cluster_name: "prod-cluster".into(),
        };
        let now = 1_700_000_000_000;
        let token = p.token(now);
        assert!(token.starts_with("k8s-aws-v1."));
        let url_b64 = token.strip_prefix("k8s-aws-v1.").unwrap();
        let url = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(url_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(url.starts_with("https://sts.us-east-1.amazonaws.com/?"));
        assert!(url.contains("Action=GetCallerIdentity"));
        assert!(url.contains("X-Amz-Credential=AKIDTEST%2F"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains("X-Amz-SignedHeaders=host%3Bx-k8s-aws-id"));
        assert!(url.contains("X-Amz-Signature="));
        // The cluster is bound via the signed header, never in the URL query.
        assert!(!url.contains("prod-cluster"));
        // Same inputs → identical token (no hidden randomness).
        assert_eq!(token, p.token(now));
        // A later timestamp produces a different signature/date.
        assert_ne!(token, p.token(now + 86_400_000));
    }

    #[test]
    fn github_app_jwt_is_well_formed_and_signs() {
        let pem = include_str!("../testdata/github_app_key.pem");
        let der = pkcs8_from_pem(pem).unwrap();
        let p = GitHubAppProvider {
            app_id: "123456".into(),
            installation_id: "789".into(),
            private_key_pkcs8_der: der,
            api_base: "https://api.github.com".into(),
            client: reqwest::Client::new(),
        };
        let now = 1_700_000_000_000;
        let jwt = p.app_jwt(now).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");
        let header = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .unwrap(),
        )
        .unwrap();
        assert!(header.contains("RS256"));
        let claims = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap(),
        )
        .unwrap();
        assert!(claims.contains(r#""iss":"123456""#));
        assert!(claims.contains(r#""iat":1699999940"#)); // now_s - 60
        assert!(claims.contains(r#""exp":1700000540"#)); // now_s + 540
        // RSA-2048 signature is 256 bytes → 342 base64url chars (no padding).
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap()
                .len(),
            256
        );
    }

    /// A trivial provider whose secret encodes its mint time + expiry window, for exercising
    /// the cache/refresh logic deterministically.
    struct StubProvider {
        ttl_ms: u64,
    }
    impl CredentialProvider for StubProvider {
        fn mint(
            &self,
            now_ms: u64,
        ) -> Pin<Box<dyn Future<Output = Result<MintedSecret, String>> + Send + '_>> {
            let ttl = self.ttl_ms;
            Box::pin(async move {
                Ok(MintedSecret {
                    secret: Secret::new(format!("minted@{now_ms}")),
                    expires_at_ms: now_ms + ttl,
                })
            })
        }
        fn refresh_skew_ms(&self) -> u64 {
            1_000
        }
    }

    #[tokio::test]
    async fn caching_store_fails_closed_then_serves_and_rotates() {
        let mut providers: HashMap<String, Arc<dyn CredentialProvider>> = HashMap::new();
        providers.insert("eks".into(), Arc::new(StubProvider { ttl_ms: 10_000 }));
        let mut statics = HashMap::new();
        statics.insert("ghs".to_string(), Secret::new("static-secret"));
        let store = CachingCredentials::new(statics, providers);

        // Static secret resolves immediately; provider-backed fails closed until minted.
        assert_eq!(store.resolve("ghs").unwrap().expose(), "static-secret");
        assert!(store.resolve("eks").is_none());

        // Prime at t=1000 → resolves the minted value.
        let refreshed = store.refresh_due(1_000).await;
        assert_eq!(refreshed, vec!["eks".to_string()]);
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@1000");

        // Well within TTL → no rotation.
        assert!(store.refresh_due(2_000).await.is_empty());
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@1000");

        // Within refresh skew of expiry (expires at 11_000, skew 1_000) → rotates.
        let refreshed = store.refresh_due(10_500).await;
        assert_eq!(refreshed, vec!["eks".to_string()]);
        assert_eq!(store.resolve("eks").unwrap().expose(), "minted@10500");
    }

    #[test]
    fn ids_union_static_and_provider_keys() {
        let mut providers: HashMap<String, Arc<dyn CredentialProvider>> = HashMap::new();
        providers.insert("eks".into(), Arc::new(StubProvider { ttl_ms: 10_000 }));
        let mut statics = HashMap::new();
        statics.insert("ghs".to_string(), Secret::new("static-secret"));
        let store = CachingCredentials::new(statics, providers);
        // Provider ids appear even before they are minted; ids are the union, secrets never.
        let mut ids = CredentialStore::ids(&store);
        ids.sort();
        assert_eq!(ids, vec!["eks".to_string(), "ghs".to_string()]);
        assert!(!ids.iter().any(|id| id == "static-secret"));
    }

    #[test]
    fn pkcs8_from_pem_round_trips() {
        let pem = include_str!("../testdata/github_app_key.pem");
        let der = pkcs8_from_pem(pem).unwrap();
        assert!(signature::RsaKeyPair::from_pkcs8(&der).is_ok());
        assert!(pkcs8_from_pem("not a key").is_err());
    }

    fn assume_role_provider() -> AssumeRoleProvider {
        AssumeRoleProvider {
            base: AwsCredential {
                access_key_id: "AKIDBASE".into(),
                secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
                session_token: None,
                expires_at_ms: None,
            },
            role_arn: "arn:aws:iam::123456789012:role/agent".into(),
            role_session_name: "hackamore".into(),
            region: "us-east-1".into(),
            sts_endpoint: "sts.amazonaws.com".into(),
            client: reqwest::Client::new(),
        }
    }

    #[test]
    fn assume_role_signed_request_is_well_formed() {
        let p = assume_role_provider();
        let now = 1_700_000_000_000;
        let (url, headers, body) = p.build_signed_request(now);
        assert_eq!(url, "https://sts.amazonaws.com/");
        // The body is the form-urlencoded AssumeRole action.
        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fagent"));
        assert!(body.contains("RoleSessionName=hackamore"));
        assert!(body.contains("Version=2011-06-15"));
        // The Authorization is a SigV4 header scoped to the `sts` service.
        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDBASE/"));
        assert!(auth.contains("/us-east-1/sts/aws4_request"));
        assert!(auth.contains("Signature="));
        // Deterministic for fixed inputs.
        let (_u2, h2, _b2) = p.build_signed_request(now);
        assert_eq!(headers, h2);
    }

    #[test]
    fn assume_role_signs_base_session_token_when_present() {
        let mut p = assume_role_provider();
        p.base.session_token = Some(Secret::new("base-session-token"));
        let (_, headers, _) = p.build_signed_request(1_700_000_000_000);
        // The base session token is set and signed.
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "x-amz-security-token" && v == "base-session-token")
        );
        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(auth.contains("x-amz-security-token"));
    }

    #[test]
    fn assume_role_parses_sts_xml_response() {
        let xml = r#"<?xml version="1.0"?>
        <AssumeRoleResponse>
          <AssumeRoleResult>
            <Credentials>
              <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
              <SecretAccessKey>secretkeyvalue</SecretAccessKey>
              <SessionToken>sessiontokenvalue</SessionToken>
              <Expiration>2026-06-27T13:00:00Z</Expiration>
            </Credentials>
          </AssumeRoleResult>
        </AssumeRoleResponse>"#;
        let cred = AssumeRoleProvider::parse_response(xml).unwrap();
        assert_eq!(cred.access_key_id, "ASIAEXAMPLE");
        assert_eq!(cred.secret_access_key.expose(), "secretkeyvalue");
        assert_eq!(cred.session_token.unwrap().expose(), "sessiontokenvalue");
        // 2026-06-27T13:00:00Z parses to a concrete epoch ms.
        assert_eq!(cred.expires_at_ms, Some(1_782_565_200_000));

        // A missing required field fails closed.
        assert!(AssumeRoleProvider::parse_response("<Credentials></Credentials>").is_err());
        // An unparseable expiry leaves expires_at_ms = None (not an error).
        let no_exp = r#"<Credentials><AccessKeyId>A</AccessKeyId>
          <SecretAccessKey>S</SecretAccessKey><SessionToken>T</SessionToken>
          <Expiration>not-a-date</Expiration></Credentials>"#;
        assert_eq!(
            AssumeRoleProvider::parse_response(no_exp)
                .unwrap()
                .expires_at_ms,
            None
        );
    }

    #[test]
    fn iso8601_parses_with_and_without_fractional_seconds() {
        assert_eq!(
            parse_iso8601_to_ms("2026-06-27T13:00:00Z"),
            Some(1_782_565_200_000)
        );
        assert_eq!(
            parse_iso8601_to_ms("2026-06-27T13:00:00.123Z"),
            Some(1_782_565_200_000)
        );
        assert_eq!(parse_iso8601_to_ms("garbage"), None);
    }

    /// A deterministic stub AWS provider whose bundle encodes its mint time + expiry window,
    /// mirroring `StubProvider` for the token cache.
    struct StubAwsProvider {
        ttl_ms: u64,
    }
    impl AwsCredentialProvider for StubAwsProvider {
        fn mint_aws(
            &self,
            now_ms: u64,
        ) -> Pin<Box<dyn Future<Output = Result<AwsCredential, String>> + Send + '_>> {
            let ttl = self.ttl_ms;
            Box::pin(async move {
                Ok(AwsCredential {
                    access_key_id: format!("AKID@{now_ms}"),
                    secret_access_key: Secret::new(format!("sak@{now_ms}")),
                    session_token: Some(Secret::new(format!("sess@{now_ms}"))),
                    expires_at_ms: Some(now_ms + ttl),
                })
            })
        }
        fn refresh_skew_ms(&self) -> u64 {
            1_000
        }
    }

    #[tokio::test]
    async fn caching_store_aws_fails_closed_then_serves_and_rotates() {
        let store = CachingCredentials::new(HashMap::new(), HashMap::new());
        // A static AWS bundle resolves immediately, no minting.
        store.insert_aws_runtime(
            "static-aws".into(),
            AwsCredential {
                access_key_id: "STATICAKID".into(),
                secret_access_key: Secret::new("static-sak"),
                session_token: None,
                expires_at_ms: None,
            },
        );
        assert_eq!(
            store.resolve_aws("static-aws").unwrap().access_key_id,
            "STATICAKID"
        );

        // A provider-backed bundle fails closed until minted.
        store.insert_aws_provider("role".into(), Arc::new(StubAwsProvider { ttl_ms: 10_000 }));
        assert!(store.resolve_aws("role").is_none());

        // Prime at t=1000 → resolves the minted bundle.
        let refreshed = store.refresh_due(1_000).await;
        assert_eq!(refreshed, vec!["role".to_string()]);
        assert_eq!(
            store.resolve_aws("role").unwrap().access_key_id,
            "AKID@1000"
        );

        // Well within TTL → no rotation.
        assert!(store.refresh_due(2_000).await.is_empty());
        assert_eq!(
            store.resolve_aws("role").unwrap().access_key_id,
            "AKID@1000"
        );

        // Within refresh skew of expiry (expires at 11_000, skew 1_000) → rotates.
        let refreshed = store.refresh_due(10_500).await;
        assert_eq!(refreshed, vec!["role".to_string()]);
        assert_eq!(
            store.resolve_aws("role").unwrap().access_key_id,
            "AKID@10500"
        );

        // ids unions token + AWS, static + provider.
        let ids = CredentialStore::ids(&store);
        assert!(ids.contains(&"static-aws".to_string()));
        assert!(ids.contains(&"role".to_string()));
    }
}
