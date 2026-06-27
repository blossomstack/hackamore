//! Consumer-side provisioning: fetch the [`ProvisionDoc`] from the reserved
//! `/.hackamore/provision` path on hackamore's proxy listener — the only address a sandboxed
//! consumer can reach — and render it into native tool config. [`write_configs`]
//! writes everything **under a
//! caller-supplied home directory** — nothing outside it is touched, so a sandbox (or a
//! test) can configure stock tools without polluting the host's real `~/.kube`, `~/.aws`,
//! or git config.
//!
//! Every write is recorded in a manifest (`<home>/.hackamore/manifest`) so [`teardown`] can
//! remove exactly what hackamore wrote and nothing else. Line-oriented files (git
//! credentials) are merged idempotently rather than clobbered, so re-provisioning a second
//! service doesn't drop the first. When hackamore terminates TLS, the doc carries a CA bundle
//! ([`ProvisionDoc::hackamore_ca`]); it is written once and referenced by path from every
//! tool's config (kubeconfig, `~/.aws/config`, `.gitconfig`).

use hackamore_models::provision::{ProvisionAuth, ProvisionDoc, ProvisionMode, ProvisionService};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Relative path (under the home) of the manifest listing every file hackamore wrote.
const MANIFEST: &str = ".hackamore/manifest";
/// Relative path (under the home) of the CA bundle, when hackamore terminates TLS.
const CA_BUNDLE: &str = ".hackamore/hackamore-ca.pem";

/// Fetch the provision doc from the reserved `/.hackamore/provision` path on the proxy
/// listener at `proxy_url`, presenting the token via `X-Hackamore-Token`. The proxy
/// listener is the only address a sandboxed consumer can reach; the admin listener
/// (which also serves the unauthenticated `/mint`) stays operator-only.
pub async fn fetch_provision(proxy_url: &str, token: &str) -> Result<ProvisionDoc, String> {
    let url = format!("{}/.hackamore/provision", proxy_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Hackamore-Token", token)
        .send()
        .await
        .map_err(|e| format!("provision request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("provision failed: HTTP {}", resp.status()));
    }
    resp.json()
        .await
        .map_err(|e| format!("provision decode failed: {e}"))
}

/// Render shell `export` lines from a provision doc.
pub fn render_env(doc: &ProvisionDoc) -> String {
    let mut out = format!(
        "# hackamore-agent env (token expires at {} ms)\nexport HACKAMORE_TOKEN='{}'\n\
         export HACKAMORE_TOKEN_HEADER='X-Hackamore-Token'\n",
        doc.expires_at_ms, doc.hackamore_token
    );
    if !doc.hackamore_ca.is_empty() {
        // Point TLS-aware tools that read env (curl, some SDKs) at the bundle.
        out.push_str(&format!(
            "export HACKAMORE_CA_BUNDLE=\"$HOME/{CA_BUNDLE}\"\n\
             export AWS_CA_BUNDLE=\"$HOME/{CA_BUNDLE}\"\n\
             export GIT_SSL_CAINFO=\"$HOME/{CA_BUNDLE}\"\n"
        ));
    }
    for s in &doc.services {
        out.push_str(&format!(
            "# service '{}' [{}] {}\n",
            s.target,
            s.tool_hint,
            mode_hint(&s.mode)
        ));
        if !s.address.is_empty() {
            out.push_str(&format!("#   point your tool at: {}\n", s.address));
        }
    }
    out
}

/// Render a human-readable summary.
pub fn render_status(doc: &ProvisionDoc) -> String {
    let mut out = format!(
        "hackamore token valid until {} ms; {} service(s) reachable:\n",
        doc.expires_at_ms,
        doc.services.len()
    );
    for s in &doc.services {
        let addr = if s.address.is_empty() {
            "(via hackamore proxy)".to_string()
        } else {
            s.address.clone()
        };
        out.push_str(&format!(
            "  - {} [{}] {} → {}\n",
            s.target,
            s.tool_hint,
            mode_hint(&s.mode),
            addr
        ));
    }
    out
}

fn mode_hint(mode: &ProvisionMode) -> &'static str {
    match mode {
        ProvisionMode::Inject => "inject (hackamore supplies the credential)",
        ProvisionMode::Passthrough => "passthrough (bring your own credential)",
    }
}

/// Write native tool config for every service into `home` (an isolated directory). Returns
/// the files written and records them in the manifest. Always writes `hackamore.env` and (when
/// hackamore terminates TLS) the CA bundle; per service the `tool_hint` selects which native
/// config to write: `github` → `gh` hosts.yml, `git` → git credentials + `.gitconfig`,
/// `kubernetes` → a kubeconfig, `aws` → an AWS profile, `generic` (or unknown) → nothing
/// beyond the env. An AWS profile is *also* written whenever the auth is SigV4, regardless of
/// the hint, so a SigV4 service is robust even if its hint is missing.
pub fn write_configs(home: &Path, doc: &ProvisionDoc) -> std::io::Result<Vec<PathBuf>> {
    let mut written: Vec<PathBuf> = Vec::new();
    written.push(write(&home.join("hackamore.env"), &render_env(doc))?);

    // The CA bundle is written once and referenced by path from each tool's config.
    let ca_path = if doc.hackamore_ca.is_empty() {
        None
    } else {
        let p = home.join(CA_BUNDLE);
        written.push(write(&p, &doc.hackamore_ca)?);
        Some(p)
    };

    for s in &doc.services {
        match s.tool_hint.as_str() {
            // REST GitHub → only `gh` (its hosts.yml). git is a *separate* service/hint now.
            "github" => written.push(write_gh(home, s)?),
            // git-over-HTTPS → only the git credential store + `.gitconfig`.
            "git" => written.extend(write_git(home, s, ca_path.as_deref())?),
            "kubernetes" => written.push(write_kubeconfig(home, s, ca_path.as_deref())?),
            // `aws` is handled by the SigV4 branch below (keeps the AWS path robust whether or
            // not the hint is present); `generic`/anything else writes no tool files here.
            _ => {}
        }
        // Always write an AWS profile when the auth is SigV4 — robust against a missing hint.
        if let ProvisionAuth::SigV4(a) = &s.auth {
            written.extend(write_aws(home, s, a, ca_path.as_deref())?);
        }
    }

    write_manifest(home, &written)?;
    Ok(written)
}

/// Remove every file hackamore previously wrote under `home`, per its manifest, then the
/// manifest itself. Returns the files removed. Idempotent: a missing manifest or
/// already-removed file is not an error. Nothing outside the manifest is touched.
pub fn teardown(home: &Path) -> std::io::Result<Vec<PathBuf>> {
    let manifest = home.join(MANIFEST);
    let listing = match std::fs::read_to_string(&manifest) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut removed = Vec::new();
    for line in listing.lines().filter(|l| !l.trim().is_empty()) {
        let path = PathBuf::from(line);
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let _ = std::fs::remove_file(&manifest);
    Ok(removed)
}

/// The bearer (hackamore) token a service presents, if its auth is bearer.
fn bearer_token(s: &ProvisionService) -> Option<&str> {
    match &s.auth {
        ProvisionAuth::Bearer(b) => Some(&b.token),
        ProvisionAuth::SigV4(_) => None,
    }
}

fn endpoint(s: &ProvisionService) -> &str {
    if s.address.is_empty() {
        "https://hackamore.local"
    } else {
        &s.address
    }
}

/// The bare host[:port] of a service's consumer-facing endpoint.
fn endpoint_host(s: &ProvisionService) -> &str {
    endpoint(s)
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}

/// Write a kubeconfig with a static token (no `exec` plugin) pointing at hackamore. When
/// hackamore terminates TLS, the cluster references the CA bundle by path; otherwise the
/// endpoint is plaintext and no CA is needed.
fn write_kubeconfig(
    home: &Path,
    s: &ProvisionService,
    ca: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let token = bearer_token(s).unwrap_or_default();
    let name = &s.target;
    let cluster_tls = match ca {
        Some(p) => format!("    certificate-authority: {}\n", p.display()),
        None => String::new(),
    };
    let body = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: {name}\n\
         clusters:\n- name: {name}\n  cluster:\n    server: {server}\n{cluster_tls}\
         contexts:\n- name: {name}\n  context:\n    cluster: {name}\n    user: {name}\n\
         users:\n- name: {name}\n  user:\n    token: {token}\n",
        server = endpoint(s),
    );
    write(&home.join(".kube").join("config"), &body)
}

/// Configure **`gh`** (the GitHub CLI) only: write `~/.config/gh/hosts.yml` so `gh`
/// authenticates to the hackamore-fronted host with the launch token. This is the `github`
/// tool hint (the REST GitHub service). git config is a *separate* concern handled by
/// [`write_git`] under the `git` hint — splitting them keeps each tool's files scoped to the
/// service that actually needs it.
fn write_gh(home: &Path, s: &ProvisionService) -> std::io::Result<PathBuf> {
    let token = bearer_token(s).unwrap_or_default();
    let host = endpoint_host(s);
    // gh reads the oauth token for this host from hosts.yml.
    let hosts = format!(
        "{host}:\n    oauth_token: {token}\n    git_protocol: https\n    user: x-access-token\n"
    );
    write(&home.join(".config").join("gh").join("hosts.yml"), &hosts)
}

/// Configure **`git`** (over HTTPS) only: the store-helper credential line (merged, not
/// clobbered) carrying `https://x-access-token:<token>@<host>` — exactly the Basic-inbound
/// shape hackamore accepts (the launch token in the Basic password slot) — plus a `.gitconfig`
/// enabling the `store` helper (and trusting the CA, when hackamore terminates TLS). This is
/// the `git` tool hint (the git-over-HTTPS service); `gh` config lives in [`write_gh`].
fn write_git(
    home: &Path,
    s: &ProvisionService,
    ca: Option<&Path>,
) -> std::io::Result<Vec<PathBuf>> {
    let token = bearer_token(s).unwrap_or_default();
    let host = endpoint_host(s);

    // 1. git store-helper credential line — merged idempotently so multiple git services
    //    accumulate instead of overwriting one another.
    let cred_line = format!("https://x-access-token:{token}@{host}");
    let creds = home.join(".git-credentials");
    let merged = merge_lines(&creds, &cred_line)?;
    let creds = write(&creds, &merged)?;

    // 2. .gitconfig turning on the store helper (and trusting the CA, when TLS).
    let mut gitconfig = String::from("[credential]\n\thelper = store\n");
    if let Some(p) = ca {
        gitconfig.push_str(&format!("[http]\n\tsslCAInfo = {}\n", p.display()));
    }
    let gitconfig = write(&home.join(".gitconfig"), &gitconfig)?;

    Ok(vec![creds, gitconfig])
}

/// Write an AWS profile (dummy credential + hackamore endpoint) for the `aws` CLI / SDKs:
/// `~/.aws/credentials` (the dummy key pair) and `~/.aws/config` (region + endpoint, plus
/// the CA bundle when hackamore terminates TLS).
fn write_aws(
    home: &Path,
    s: &ProvisionService,
    a: &hackamore_models::provision::SigV4Auth,
    ca: Option<&Path>,
) -> std::io::Result<Vec<PathBuf>> {
    let creds = format!(
        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
        a.access_key_id, a.secret_access_key
    );
    let mut config = format!(
        "[default]\nregion = {}\nendpoint_url = {}\n",
        a.region,
        endpoint(s)
    );
    if let Some(p) = ca {
        config.push_str(&format!("ca_bundle = {}\n", p.display()));
    }
    Ok(vec![
        write(&home.join(".aws").join("credentials"), &creds)?,
        write(&home.join(".aws").join("config"), &config)?,
    ])
}

/// Merge `line` into the existing newline-separated file at `path` (if any), de-duplicating.
/// Existing lines are preserved and ordered before the new one; the result ends with a
/// trailing newline. Idempotent: merging an already-present line is a no-op.
fn merge_lines(path: &Path, line: &str) -> std::io::Result<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut ordered: Vec<String> = Vec::new();
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    for l in existing.lines().chain(std::iter::once(line)) {
        let l = l.trim();
        if !l.is_empty() && seen.insert(l.to_string()) {
            ordered.push(l.to_string());
        }
    }
    let mut out = ordered.join("\n");
    out.push('\n');
    Ok(out)
}

/// Record the absolute paths hackamore wrote into the manifest (one per line), so [`teardown`]
/// can later remove exactly them.
fn write_manifest(home: &Path, written: &[PathBuf]) -> std::io::Result<()> {
    let body = written
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    write(&home.join(MANIFEST), &format!("{body}\n"))?;
    Ok(())
}

/// Write `contents` to `path`, creating parent directories. Returns `path`.
fn write(path: &Path, contents: &str) -> std::io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hackamore_models::provision::{BearerAuth, SigV4Auth};

    fn svc(
        target: &str,
        tool_hint: &str,
        auth: ProvisionAuth,
        mode: ProvisionMode,
    ) -> ProvisionService {
        ProvisionService {
            target: target.into(),
            tool_hint: tool_hint.into(),
            address: String::new(),
            mode,
            auth,
        }
    }

    /// A bearer-auth service carrying the shared launch token.
    fn bearer_svc(target: &str, tool_hint: &str) -> ProvisionService {
        svc(
            target,
            tool_hint,
            ProvisionAuth::Bearer(BearerAuth {
                token: "tok-abc".into(),
            }),
            ProvisionMode::Inject,
        )
    }

    /// A doc covering every tool hint: a `github` (gh) service, a `git` service, a
    /// `kubernetes` service, an `aws` (SigV4) service, and a `generic` service (no tool
    /// files).
    fn doc_with_ca(ca: &str) -> ProvisionDoc {
        ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: ca.into(),
            expires_at_ms: 12345,
            services: vec![
                bearer_svc("github-api", "github"),
                bearer_svc("github-git", "git"),
                bearer_svc("eks-prod", "kubernetes"),
                svc(
                    "aws-acct-a",
                    "aws",
                    ProvisionAuth::SigV4(SigV4Auth {
                        access_key_id: "AKIADUMMY".into(),
                        secret_access_key: "dummy-secret".into(),
                        region: "us-east-1".into(),
                    }),
                    ProvisionMode::Inject,
                ),
                bearer_svc("plain-api", "generic"),
            ],
        }
    }

    fn doc() -> ProvisionDoc {
        doc_with_ca("")
    }

    fn temp_home(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hackamore-agent-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn env_exports_token_and_lists_services_with_tool_hints() {
        let env = render_env(&doc());
        assert!(env.contains("export HACKAMORE_TOKEN='tok-abc'"));
        assert!(env.contains("service 'github-api'"));
        assert!(env.contains("service 'aws-acct-a'"));
        // The tool hint (not the service name) is printed in the per-service comment.
        assert!(env.contains("[github]"));
        assert!(env.contains("[git]"));
        assert!(env.contains("[kubernetes]"));
        assert!(env.contains("[aws]"));
        // No CA → no CA-bundle exports.
        assert!(!env.contains("CA_BUNDLE"));
    }

    #[test]
    fn write_configs_writes_native_files_into_home() {
        let dir = temp_home("native");
        let written = write_configs(&dir, &doc()).unwrap();
        assert!(written.iter().any(|p| p.ends_with("hackamore.env")));

        let kube = std::fs::read_to_string(dir.join(".kube").join("config")).unwrap();
        assert!(kube.contains("token: tok-abc"));
        assert!(kube.contains("kind: Config"));
        // No TLS → no certificate-authority line.
        assert!(!kube.contains("certificate-authority"));

        let creds = std::fs::read_to_string(dir.join(".aws").join("credentials")).unwrap();
        assert!(creds.contains("aws_access_key_id = AKIADUMMY"));
        assert!(creds.contains("aws_secret_access_key = dummy-secret"));

        let git = std::fs::read_to_string(dir.join(".git-credentials")).unwrap();
        assert!(git.contains("x-access-token:tok-abc@"));

        // .gitconfig enables the store helper so git actually uses the credential.
        let gitconfig = std::fs::read_to_string(dir.join(".gitconfig")).unwrap();
        assert!(gitconfig.contains("helper = store"));

        // gh hosts.yml carries the oauth token for the hackamore host.
        let gh = std::fs::read_to_string(dir.join(".config").join("gh").join("hosts.yml")).unwrap();
        assert!(gh.contains("oauth_token: tok-abc"));
        assert!(gh.contains("git_protocol: https"));

        // Everything stayed under the isolated home.
        assert!(written.iter().all(|p| p.starts_with(&dir)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `github`-hint service writes the `gh` hosts.yml but NOT git-credentials/.gitconfig —
    /// those belong to the separate `git` hint.
    #[test]
    fn github_hint_writes_gh_hosts_but_not_git_files() {
        let dir = temp_home("gh-only");
        let doc = ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: String::new(),
            expires_at_ms: 1,
            services: vec![bearer_svc("github-api", "github")],
        };
        write_configs(&dir, &doc).unwrap();
        let gh = std::fs::read_to_string(dir.join(".config").join("gh").join("hosts.yml")).unwrap();
        assert!(gh.contains("oauth_token: tok-abc"));
        // No git credential store or .gitconfig from a github-hint service.
        assert!(!dir.join(".git-credentials").exists());
        assert!(!dir.join(".gitconfig").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `git`-hint service writes git-credentials + .gitconfig but NOT the `gh` hosts.yml.
    /// The credential line is exactly the Basic-inbound shape hackamore (P2) accepts:
    /// `https://x-access-token:<token>@<host>`.
    #[test]
    fn git_hint_writes_git_files_but_not_gh_hosts() {
        let dir = temp_home("git-only");
        let doc = ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: String::new(),
            expires_at_ms: 1,
            services: vec![bearer_svc("github-git", "git")],
        };
        write_configs(&dir, &doc).unwrap();
        let creds = std::fs::read_to_string(dir.join(".git-credentials")).unwrap();
        assert!(creds.contains("https://x-access-token:tok-abc@"));
        let gitconfig = std::fs::read_to_string(dir.join(".gitconfig")).unwrap();
        assert!(gitconfig.contains("helper = store"));
        // No gh hosts.yml from a git-hint service.
        assert!(!dir.join(".config").join("gh").join("hosts.yml").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `kubernetes`-hint service writes a kubeconfig (and no git/gh/aws files).
    #[test]
    fn kubernetes_hint_writes_kubeconfig_only() {
        let dir = temp_home("k8s-only");
        let doc = ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: String::new(),
            expires_at_ms: 1,
            services: vec![bearer_svc("eks-prod", "kubernetes")],
        };
        write_configs(&dir, &doc).unwrap();
        let kube = std::fs::read_to_string(dir.join(".kube").join("config")).unwrap();
        assert!(kube.contains("kind: Config"));
        assert!(kube.contains("token: tok-abc"));
        assert!(!dir.join(".git-credentials").exists());
        assert!(!dir.join(".config").join("gh").join("hosts.yml").exists());
        assert!(!dir.join(".aws").join("credentials").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An `aws`-hint SigV4 service writes the AWS profile (dummy creds + endpoint).
    #[test]
    fn aws_hint_writes_aws_profile() {
        let dir = temp_home("aws-only");
        let doc = ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: String::new(),
            expires_at_ms: 1,
            services: vec![svc(
                "aws-ec2",
                "aws",
                ProvisionAuth::SigV4(SigV4Auth {
                    access_key_id: "AKIADUMMY".into(),
                    secret_access_key: "dummy-secret".into(),
                    region: "us-east-1".into(),
                }),
                ProvisionMode::Inject,
            )],
        };
        write_configs(&dir, &doc).unwrap();
        let creds = std::fs::read_to_string(dir.join(".aws").join("credentials")).unwrap();
        assert!(creds.contains("aws_access_key_id = AKIADUMMY"));
        assert!(creds.contains("aws_secret_access_key = dummy-secret"));
        let config = std::fs::read_to_string(dir.join(".aws").join("config")).unwrap();
        assert!(config.contains("region = us-east-1"));
        // No git/gh/k8s files from an aws-hint service.
        assert!(!dir.join(".git-credentials").exists());
        assert!(!dir.join(".kube").join("config").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `generic`-hint service (bearer) writes no native tool files — only `hackamore.env`
    /// carries the token + endpoint.
    #[test]
    fn generic_hint_writes_no_tool_files() {
        let dir = temp_home("generic-only");
        let doc = ProvisionDoc {
            hackamore_token: "tok-abc".into(),
            hackamore_ca: String::new(),
            expires_at_ms: 1,
            services: vec![bearer_svc("plain-api", "generic")],
        };
        let written = write_configs(&dir, &doc).unwrap();
        // Only hackamore.env (+ the manifest) was written — no tool config.
        assert!(written.iter().any(|p| p.ends_with("hackamore.env")));
        assert!(!dir.join(".git-credentials").exists());
        assert!(!dir.join(".gitconfig").exists());
        assert!(!dir.join(".config").join("gh").join("hosts.yml").exists());
        assert!(!dir.join(".kube").join("config").exists());
        assert!(!dir.join(".aws").join("credentials").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_ca_is_written_and_referenced_by_every_tool() {
        let dir = temp_home("tls");
        let written = write_configs(
            &dir,
            &doc_with_ca("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
        )
        .unwrap();
        let ca_path = dir.join(CA_BUNDLE);
        assert!(written.contains(&ca_path));
        let ca = std::fs::read_to_string(&ca_path).unwrap();
        assert!(ca.contains("BEGIN CERTIFICATE"));

        let kube = std::fs::read_to_string(dir.join(".kube").join("config")).unwrap();
        assert!(kube.contains(&format!("certificate-authority: {}", ca_path.display())));

        let aws = std::fs::read_to_string(dir.join(".aws").join("config")).unwrap();
        assert!(aws.contains(&format!("ca_bundle = {}", ca_path.display())));

        let gitconfig = std::fs::read_to_string(dir.join(".gitconfig")).unwrap();
        assert!(gitconfig.contains(&format!("sslCAInfo = {}", ca_path.display())));

        let env = render_env(&doc_with_ca("x"));
        assert!(env.contains("AWS_CA_BUNDLE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_credentials_merge_idempotently() {
        let dir = temp_home("merge");
        std::fs::create_dir_all(&dir).unwrap();
        let creds = dir.join(".git-credentials");
        // A pre-existing, unrelated credential must survive a hackamore write.
        std::fs::write(&creds, "https://x-access-token:other@github.example\n").unwrap();
        write_configs(&dir, &doc()).unwrap();
        let body = std::fs::read_to_string(&creds).unwrap();
        assert!(
            body.contains("other@github.example"),
            "pre-existing line preserved"
        );
        assert!(body.contains("tok-abc@"), "hackamore line added");
        // Writing again does not duplicate.
        write_configs(&dir, &doc()).unwrap();
        let body2 = std::fs::read_to_string(&creds).unwrap();
        assert_eq!(body2.matches("tok-abc@").count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn teardown_removes_exactly_what_was_written() {
        let dir = temp_home("teardown");
        let written = write_configs(&dir, &doc()).unwrap();
        for p in &written {
            assert!(p.exists());
        }
        let removed = teardown(&dir).unwrap();
        // Every written file is gone.
        for p in &written {
            assert!(!p.exists(), "{} should be removed", p.display());
        }
        assert_eq!(removed.len(), written.len());
        // The manifest itself is gone, and a second teardown is a no-op.
        assert!(!dir.join(MANIFEST).exists());
        assert_eq!(teardown(&dir).unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
