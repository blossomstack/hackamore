//! CLI service presets — sugar over the generic `POST /admin/services`.
//!
//! A preset pins everything *intrinsic* to a well-known service: its host, upstream base,
//! wire protocol, bundled API model, and the injection mechanism that places the real
//! credential on the wire. The operator supplies only the *extrinsic* thing — the credential
//! source. Every preset **expands to the same generic admin JSON** the CLI already sends; the
//! gateway and policy engine never learn the words "github" or "aws". The expansion is pure
//! (preset + args → JSON), so it is unit-testable with no running server.
//!
//! Bundled specs are gzip-compressed and embedded with `include_bytes!`; [`inflate`] expands
//! them on use. `github-api` and `aws:<svc>` send their spec as `specInline` (the server
//! imports it); `github-git` carries no model (the server attaches the hardcoded git model).

use flate2::read::GzDecoder;
use std::io::Read;

/// The bundled, gzip-compressed GitHub OpenAPI description.
const GITHUB_API_GZ: &[u8] = include_bytes!("../assets/github-api.openapi.json.gz");

/// The bundled, gzip-compressed AWS Smithy (`service-2.json`) models, one per curated
/// service. Selected by [`aws_asset`].
const AWS_EC2_GZ: &[u8] = include_bytes!("../assets/aws-ec2.service-2.json.gz");
const AWS_S3_GZ: &[u8] = include_bytes!("../assets/aws-s3.service-2.json.gz");
const AWS_STS_GZ: &[u8] = include_bytes!("../assets/aws-sts.service-2.json.gz");
const AWS_IAM_GZ: &[u8] = include_bytes!("../assets/aws-iam.service-2.json.gz");
const AWS_LAMBDA_GZ: &[u8] = include_bytes!("../assets/aws-lambda.service-2.json.gz");
const AWS_DYNAMODB_GZ: &[u8] = include_bytes!("../assets/aws-dynamodb.service-2.json.gz");

/// The six curated AWS services with a bundled Smithy model. A service outside this set falls
/// back to the generic `services add … --smithy <file>`.
pub const AWS_SERVICES: [&str; 6] = ["ec2", "s3", "sts", "iam", "lambda", "dynamodb"];

/// The default AWS region a `aws:<svc>` preset pins (overridable with `--region`).
pub const DEFAULT_AWS_REGION: &str = "us-east-1";

/// Inflate gzip-compressed bytes to a UTF-8 string (the bundled specs are JSON).
pub fn inflate(gz: &[u8]) -> Result<String, String> {
    let mut decoder = GzDecoder::new(gz);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .map_err(|e| format!("inflate bundled spec: {e}"))?;
    Ok(out)
}

/// The compressed Smithy asset for a curated AWS service, or `None` if not bundled.
fn aws_asset(service: &str) -> Option<&'static [u8]> {
    match service {
        "ec2" => Some(AWS_EC2_GZ),
        "s3" => Some(AWS_S3_GZ),
        "sts" => Some(AWS_STS_GZ),
        "iam" => Some(AWS_IAM_GZ),
        "lambda" => Some(AWS_LAMBDA_GZ),
        "dynamodb" => Some(AWS_DYNAMODB_GZ),
        _ => None,
    }
}

/// How a preset places the real credential on the outbound request — the non-secret half of
/// the `outbound` object. The credential id is filled in by the caller at expansion time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Injection {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `Authorization: Basic base64(<username>:<secret>)`.
    Basic { username: String },
    /// Re-sign with AWS SigV4 for `service` in `region`.
    SigV4 { service: String, region: String },
}

impl Injection {
    /// The `outbound` JSON object for this injection, referencing `credential` by id.
    fn to_outbound_json(&self, credential: &str) -> serde_json::Value {
        match self {
            Injection::Bearer => serde_json::json!({ "kind": "bearer", "credential": credential }),
            Injection::Basic { username } => serde_json::json!({
                "kind": "basic", "username": username, "credential": credential
            }),
            Injection::SigV4 { service, region } => serde_json::json!({
                "kind": "sigv4", "credential": credential, "service": service, "region": region
            }),
        }
    }
}

/// A resolved preset: every field pinned but the credential. `model` is the model-source
/// branch — a spec to import inline, or none (the server supplies the model, e.g. git).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    /// The default service name (also the default credential id for `--auth-source`).
    pub name: String,
    /// Inbound `Host` routing pattern.
    pub host: String,
    /// Upstream base URL.
    pub upstream_base: String,
    /// The model source.
    pub model: ModelSource,
    /// The outbound injection mechanism.
    pub injection: Injection,
    /// The agent tool-config hint (`github` | `git` | `aws` | `kubernetes` | `generic`) the
    /// preset pins: which native tool config the sandbox agent writes for this service.
    pub tool_hint: &'static str,
    /// The friendly `--auth-source` kind this preset accepts as a convenience (`gh-token` for
    /// github, `aws-static` for aws); other `--auth-source` kinds still work via the generic
    /// source flags. `None` means no convenience mapping.
    pub auth_family: AuthFamily,
}

/// How a preset supplies its API vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelSource {
    /// Import this inline spec text on the server with the named `idl` (`openapi`/`smithy`).
    SpecInline { idl: &'static str, spec: String },
    /// Send no model; the server attaches one (git-http → the hardcoded git model). Carries the
    /// model-less `protocol` name.
    ServerProtocol { protocol: &'static str },
}

/// Which credential family a preset's `--auth-source` convenience belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFamily {
    /// GitHub: a friendly `gh-token` maps to the `command ["gh","auth","token"]` source.
    GitHub,
    /// AWS: expects an AWS-bundle source (`aws-static`/`assume-role`/`instance`).
    Aws,
}

/// Look up and resolve a preset by `name`, parameterizing `aws:<svc>` with `region`. Returns
/// `None` when `name` is not a known preset (the caller falls through to the generic
/// `services add`). Fails (Err) only when a known preset's bundled asset can't inflate.
pub fn resolve(name: &str, region: &str) -> Result<Option<Preset>, String> {
    match name {
        "github-api" => Ok(Some(Preset {
            name: "github-api".to_string(),
            host: "api.github.com".to_string(),
            upstream_base: "https://api.github.com".to_string(),
            model: ModelSource::SpecInline {
                idl: "openapi",
                spec: inflate(GITHUB_API_GZ)?,
            },
            injection: Injection::Bearer,
            // REST GitHub → configure `gh` (its hosts.yml carries the launch token).
            tool_hint: "github",
            auth_family: AuthFamily::GitHub,
        })),
        "github-git" => Ok(Some(Preset {
            name: "github-git".to_string(),
            host: "github.com".to_string(),
            upstream_base: "https://github.com".to_string(),
            // No model: the server attaches the hardcoded git model for a git-http service.
            model: ModelSource::ServerProtocol {
                protocol: "git-http",
            },
            injection: Injection::Basic {
                username: "x-access-token".to_string(),
            },
            // git-over-HTTPS → configure `git` (the .git-credentials + .gitconfig path).
            tool_hint: "git",
            auth_family: AuthFamily::GitHub,
        })),
        _ => match name.strip_prefix("aws:") {
            Some(service) => resolve_aws(service, region),
            None => Ok(None),
        },
    }
}

/// Resolve an `aws:<svc>` preset for a curated service, pinning host/upstream/region and
/// bundling the service's Smithy model. An uncurated service is not a preset (`Ok(None)` →
/// generic fallback with a helpful error from the caller).
fn resolve_aws(service: &str, region: &str) -> Result<Option<Preset>, String> {
    let Some(gz) = aws_asset(service) else {
        return Ok(None);
    };
    let host = format!("{service}.{region}.amazonaws.com");
    Ok(Some(Preset {
        name: format!("aws-{service}"),
        upstream_base: format!("https://{host}"),
        host,
        model: ModelSource::SpecInline {
            idl: "smithy",
            spec: inflate(gz)?,
        },
        injection: Injection::SigV4 {
            service: service.to_string(),
            region: region.to_string(),
        },
        // Any `aws:<svc>` → configure the `aws` CLI/SDK (dummy creds + endpoint).
        tool_hint: "aws",
        auth_family: AuthFamily::Aws,
    }))
}

/// How an operator supplies the credential a preset needs. Exactly one is required.
///
/// `Credential` references an already-registered vault id (no credential is created).
/// `AuthSource` is the convenience: it builds a `POST /admin/credentials` source so the CLI
/// registers the credential (id defaulting to the preset's name) then references it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialChoice {
    /// Reference an existing credential id.
    Credential(String),
    /// Register a credential from a source first, then reference its id.
    AuthSource {
        /// The credential id to register under (defaults to the preset name when absent).
        id: Option<String>,
        /// The `source` JSON for `POST /admin/credentials`.
        source: serde_json::Value,
    },
}

/// What a resolved [`CredentialChoice`] yields: the credential id the service references, and
/// optionally a credential to register first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    /// The credential id the service's outbound stance references.
    pub id: String,
    /// When `Some`, the CLI must `POST /admin/credentials` with this body first.
    pub register: Option<serde_json::Value>,
}

impl Preset {
    /// Resolve the credential a preset references, given the operator's choice. A
    /// `--credential` reference is used verbatim; an `--auth-source` builds a credential to
    /// register first (id defaulting to the preset name), then references it. The preset's
    /// auth family validates the friendly `--auth-source gh-token` shorthand. Pure — no I/O.
    pub fn resolve_credential(
        &self,
        choice: &CredentialChoice,
    ) -> Result<ResolvedCredential, String> {
        match choice {
            CredentialChoice::Credential(id) => {
                if id.trim().is_empty() {
                    return Err("--credential must not be empty".to_string());
                }
                Ok(ResolvedCredential {
                    id: id.clone(),
                    register: None,
                })
            }
            CredentialChoice::AuthSource { id, source } => {
                let id = id.clone().unwrap_or_else(|| self.name.clone());
                let source = self.normalize_auth_source(source)?;
                Ok(ResolvedCredential {
                    id: id.clone(),
                    register: Some(serde_json::json!({ "id": id, "source": source })),
                })
            }
        }
    }

    /// Apply a preset's friendly `--auth-source` shorthand. `github-*` map `gh-token` to the
    /// `command ["gh","auth","token"]` source; every other source kind passes through
    /// unchanged (so `--auth-source env MY_TOKEN` etc. still work). AWS presets accept any
    /// AWS-bundle source as-is.
    fn normalize_auth_source(
        &self,
        source: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let kind = source.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match (self.auth_family, kind) {
            (AuthFamily::GitHub, "gh-token") => Ok(serde_json::json!({
                "kind": "command", "argv": ["gh", "auth", "token"]
            })),
            // Anything else passes through; the server validates the source on registration.
            _ => Ok(source.clone()),
        }
    }

    /// Expand this preset into the generic `POST /admin/services` JSON body, referencing the
    /// resolved `credential` id. Pure — no I/O.
    pub fn to_service_json(&self, credential: &str) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert("name".into(), self.name.clone().into());
        body.insert("host".into(), self.host.clone().into());
        body.insert("upstreamBase".into(), self.upstream_base.clone().into());
        body.insert("toolHint".into(), self.tool_hint.into());
        body.insert(
            "outbound".into(),
            self.injection.to_outbound_json(credential),
        );
        match &self.model {
            ModelSource::SpecInline { idl, spec } => {
                body.insert("idl".into(), (*idl).into());
                body.insert("specInline".into(), spec.clone().into());
            }
            ModelSource::ServerProtocol { protocol } => {
                body.insert("protocol".into(), (*protocol).into());
            }
        }
        serde_json::Value::Object(body)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gzip_round_trips_through_inflate() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let original = r#"{"hello":"world","n":42}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original.as_bytes()).unwrap();
        let gz = encoder.finish().unwrap();
        assert_eq!(inflate(&gz).unwrap(), original);
    }

    #[test]
    fn unknown_name_is_not_a_preset() {
        assert!(resolve("my-api", DEFAULT_AWS_REGION).unwrap().is_none());
        // An uncurated AWS service is not a preset either.
        assert!(
            resolve("aws:route53", DEFAULT_AWS_REGION)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn github_api_pins_rest_bearer_and_inline_openapi() {
        let p = resolve("github-api", DEFAULT_AWS_REGION).unwrap().unwrap();
        assert_eq!(p.host, "api.github.com");
        assert_eq!(p.injection, Injection::Bearer);
        assert_eq!(p.tool_hint, "github");
        let json = p.to_service_json("gh-login");
        assert_eq!(json["host"], "api.github.com");
        assert_eq!(json["upstreamBase"], "https://api.github.com");
        // The REST GitHub preset hints `github` (configure `gh`), not its name.
        assert_eq!(json["toolHint"], "github");
        assert_eq!(json["idl"], "openapi");
        assert_eq!(json["outbound"]["kind"], "bearer");
        assert_eq!(json["outbound"]["credential"], "gh-login");
        // specInline is present and is the real GitHub OpenAPI (a known path appears).
        let spec = json["specInline"].as_str().unwrap();
        assert!(spec.contains("\"openapi\""));
        assert!(spec.contains("/repos/{owner}/{repo}/pulls"));
        assert!(json.get("protocol").is_none());
    }

    #[test]
    fn github_git_is_git_http_basic_with_no_model() {
        let p = resolve("github-git", DEFAULT_AWS_REGION).unwrap().unwrap();
        assert_eq!(p.host, "github.com");
        assert_eq!(
            p.injection,
            Injection::Basic {
                username: "x-access-token".to_string()
            }
        );
        assert_eq!(p.tool_hint, "git");
        let json = p.to_service_json("gh-login");
        assert_eq!(json["upstreamBase"], "https://github.com");
        // git-over-HTTPS preset hints `git` (configure `git`), distinct from `github-api`.
        assert_eq!(json["toolHint"], "git");
        // No model is sent — the server attaches the hardcoded git model.
        assert!(json.get("idl").is_none());
        assert!(json.get("specInline").is_none());
        assert!(json.get("modelInline").is_none());
        assert_eq!(json["protocol"], "git-http");
        assert_eq!(json["outbound"]["kind"], "basic");
        assert_eq!(json["outbound"]["username"], "x-access-token");
        assert_eq!(json["outbound"]["credential"], "gh-login");
    }

    #[test]
    fn aws_ec2_pins_host_region_sigv4_and_inline_smithy() {
        let p = resolve("aws:ec2", DEFAULT_AWS_REGION).unwrap().unwrap();
        assert_eq!(p.name, "aws-ec2");
        assert_eq!(p.host, "ec2.us-east-1.amazonaws.com");
        assert_eq!(
            p.injection,
            Injection::SigV4 {
                service: "ec2".to_string(),
                region: "us-east-1".to_string()
            }
        );
        assert_eq!(p.tool_hint, "aws");
        let json = p.to_service_json("aws-prod");
        assert_eq!(json["host"], "ec2.us-east-1.amazonaws.com");
        assert_eq!(json["upstreamBase"], "https://ec2.us-east-1.amazonaws.com");
        assert_eq!(json["idl"], "smithy");
        // The aws preset hints `aws` (configure the aws CLI/SDK).
        assert_eq!(json["toolHint"], "aws");
        assert_eq!(json["outbound"]["kind"], "sigv4");
        assert_eq!(json["outbound"]["credential"], "aws-prod");
        assert_eq!(json["outbound"]["service"], "ec2");
        assert_eq!(json["outbound"]["region"], "us-east-1");
        // The bundled Smithy model carries RunInstances.
        let spec = json["specInline"].as_str().unwrap();
        assert!(spec.contains("RunInstances"));
    }

    #[test]
    fn aws_region_override_is_threaded_into_host_and_signature() {
        let p = resolve("aws:s3", "eu-west-1").unwrap().unwrap();
        assert_eq!(p.host, "s3.eu-west-1.amazonaws.com");
        let json = p.to_service_json("aws-prod");
        assert_eq!(json["upstreamBase"], "https://s3.eu-west-1.amazonaws.com");
        assert_eq!(json["outbound"]["region"], "eu-west-1");
        assert_eq!(json["outbound"]["service"], "s3");
    }

    #[test]
    fn credential_reference_is_used_verbatim_and_registers_nothing() {
        let p = resolve("github-api", DEFAULT_AWS_REGION).unwrap().unwrap();
        let resolved = p
            .resolve_credential(&CredentialChoice::Credential("my-gh".to_string()))
            .unwrap();
        assert_eq!(resolved.id, "my-gh");
        assert!(resolved.register.is_none());
        // An empty reference fails closed.
        assert!(
            p.resolve_credential(&CredentialChoice::Credential("  ".to_string()))
                .is_err()
        );
    }

    #[test]
    fn github_gh_token_shorthand_maps_to_the_gh_command_source() {
        let p = resolve("github-git", DEFAULT_AWS_REGION).unwrap().unwrap();
        let resolved = p
            .resolve_credential(&CredentialChoice::AuthSource {
                id: None,
                source: serde_json::json!({ "kind": "gh-token" }),
            })
            .unwrap();
        // id defaults to the preset name.
        assert_eq!(resolved.id, "github-git");
        let register = resolved.register.unwrap();
        assert_eq!(register["id"], "github-git");
        assert_eq!(register["source"]["kind"], "command");
        assert_eq!(register["source"]["argv"][0], "gh");
        assert_eq!(register["source"]["argv"][1], "auth");
        assert_eq!(register["source"]["argv"][2], "token");
    }

    #[test]
    fn aws_auth_source_passes_through_and_id_can_be_overridden() {
        let p = resolve("aws:ec2", DEFAULT_AWS_REGION).unwrap().unwrap();
        let resolved = p
            .resolve_credential(&CredentialChoice::AuthSource {
                id: Some("aws-prod".to_string()),
                source: serde_json::json!({
                    "kind": "aws-static",
                    "access_key_id": "AKIA",
                    "secret_access_key": "sak"
                }),
            })
            .unwrap();
        assert_eq!(resolved.id, "aws-prod");
        let register = resolved.register.unwrap();
        assert_eq!(register["source"]["kind"], "aws-static");
        assert_eq!(register["source"]["access_key_id"], "AKIA");
        // The service references the same id.
        let svc = p.to_service_json(&resolved.id);
        assert_eq!(svc["outbound"]["credential"], "aws-prod");
    }

    #[test]
    fn all_six_aws_services_resolve_and_inflate() {
        for svc in AWS_SERVICES {
            let p = resolve(&format!("aws:{svc}"), DEFAULT_AWS_REGION)
                .unwrap()
                .unwrap_or_else(|| panic!("aws:{svc} should be a preset"));
            let json = p.to_service_json("aws-prod");
            // Each inflates to a non-empty Smithy spec with operations.
            let spec = json["specInline"].as_str().unwrap();
            assert!(spec.contains("operations"), "{svc} spec has operations");
        }
    }
}
