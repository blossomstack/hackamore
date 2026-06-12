//! Consumer-side provisioning: fetch the [`ProvisionDoc`] from the reserved
//! `/.halter/provision` path on halter's proxy listener — the only address a sandboxed
//! consumer can reach — and render it into native tool config. [`write_configs`]
//! writes everything **under a
//! caller-supplied home directory** — nothing outside it is touched, so a sandbox (or a
//! test) can configure stock tools without polluting the host's real `~/.kube`, `~/.aws`,
//! or git config.
//!
//! Every write is recorded in a manifest (`<home>/.halter/manifest`) so [`teardown`] can
//! remove exactly what halter wrote and nothing else. Line-oriented files (git
//! credentials) are merged idempotently rather than clobbered, so re-provisioning a second
//! service doesn't drop the first. When halter terminates TLS, the doc carries a CA bundle
//! ([`ProvisionDoc::halter_ca`]); it is written once and referenced by path from every
//! tool's config (kubeconfig, `~/.aws/config`, `.gitconfig`).

use models::provision::{ProvisionAuth, ProvisionDoc, ProvisionMode, ProvisionService};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Relative path (under the home) of the manifest listing every file halter wrote.
const MANIFEST: &str = ".halter/manifest";
/// Relative path (under the home) of the CA bundle, when halter terminates TLS.
const CA_BUNDLE: &str = ".halter/halter-ca.pem";

/// Fetch the provision doc from the reserved `/.halter/provision` path on the proxy
/// listener at `proxy_url`, presenting the token via `X-Halter-Token`. The proxy
/// listener is the only address a sandboxed consumer can reach; the admin listener
/// (which also serves the unauthenticated `/mint`) stays operator-only.
pub async fn fetch_provision(proxy_url: &str, token: &str) -> Result<ProvisionDoc, String> {
    let url = format!("{}/.halter/provision", proxy_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Halter-Token", token)
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
        "# halter-agent env (token expires at {} ms)\nexport HALTER_TOKEN='{}'\n\
         export HALTER_TOKEN_HEADER='X-Halter-Token'\n",
        doc.expires_at_ms, doc.halter_token
    );
    if !doc.halter_ca.is_empty() {
        // Point TLS-aware tools that read env (curl, some SDKs) at the bundle.
        out.push_str(&format!(
            "export HALTER_CA_BUNDLE=\"$HOME/{CA_BUNDLE}\"\n\
             export AWS_CA_BUNDLE=\"$HOME/{CA_BUNDLE}\"\n\
             export GIT_SSL_CAINFO=\"$HOME/{CA_BUNDLE}\"\n"
        ));
    }
    for s in &doc.services {
        out.push_str(&format!(
            "# service '{}' [{}] {}\n",
            s.target,
            s.flavor,
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
        "halter token valid until {} ms; {} service(s) reachable:\n",
        doc.expires_at_ms,
        doc.services.len()
    );
    for s in &doc.services {
        let addr = if s.address.is_empty() {
            "(via halter proxy)".to_string()
        } else {
            s.address.clone()
        };
        out.push_str(&format!(
            "  - {} [{}] {} → {}\n",
            s.target,
            s.flavor,
            mode_hint(&s.mode),
            addr
        ));
    }
    out
}

fn mode_hint(mode: &ProvisionMode) -> &'static str {
    match mode {
        ProvisionMode::Inject => "inject (halter supplies the credential)",
        ProvisionMode::Passthrough => "passthrough (bring your own credential)",
    }
}

/// Write native tool config for every service into `home` (an isolated directory). Returns
/// the files written and records them in the manifest. Always writes `halter.env` and (when
/// halter terminates TLS) the CA bundle; per service it writes git config (github), a
/// kubeconfig (k8s), and/or an AWS profile (SigV4).
pub fn write_configs(home: &Path, doc: &ProvisionDoc) -> std::io::Result<Vec<PathBuf>> {
    let mut written: Vec<PathBuf> = Vec::new();
    written.push(write(&home.join("halter.env"), &render_env(doc))?);

    // The CA bundle is written once and referenced by path from each tool's config.
    let ca_path = if doc.halter_ca.is_empty() {
        None
    } else {
        let p = home.join(CA_BUNDLE);
        written.push(write(&p, &doc.halter_ca)?);
        Some(p)
    };

    for s in &doc.services {
        match s.flavor.as_str() {
            "github" => written.extend(write_github(home, s, ca_path.as_deref())?),
            "k8s" => written.push(write_kubeconfig(home, s, ca_path.as_deref())?),
            _ => {}
        }
        if let ProvisionAuth::SigV4(a) = &s.auth {
            written.extend(write_aws(home, s, a, ca_path.as_deref())?);
        }
    }

    write_manifest(home, &written)?;
    Ok(written)
}

/// Remove every file halter previously wrote under `home`, per its manifest, then the
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

/// The bearer (halter) token a service presents, if its auth is bearer.
fn bearer_token(s: &ProvisionService) -> Option<&str> {
    match &s.auth {
        ProvisionAuth::Bearer(b) => Some(&b.token),
        ProvisionAuth::SigV4(_) => None,
    }
}

fn endpoint(s: &ProvisionService) -> &str {
    if s.address.is_empty() {
        "https://halter.local"
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

/// Write a kubeconfig with a static token (no `exec` plugin) pointing at halter. When
/// halter terminates TLS, the cluster references the CA bundle by path; otherwise the
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

/// Configure `git` and `gh` to use the halter token: the store-helper credential line
/// (merged, not clobbered), a `.gitconfig` enabling that helper (+ CA when TLS), and a `gh`
/// `hosts.yml` so `gh` authenticates to the halter-fronted host.
fn write_github(
    home: &Path,
    s: &ProvisionService,
    ca: Option<&Path>,
) -> std::io::Result<Vec<PathBuf>> {
    let token = bearer_token(s).unwrap_or_default();
    let host = endpoint_host(s);

    // 1. git store-helper credential line — merged idempotently so multiple github-flavored
    //    services accumulate instead of overwriting one another.
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

    // 3. gh hosts.yml — gh reads the oauth token for this host from here.
    let hosts = format!(
        "{host}:\n    oauth_token: {token}\n    git_protocol: https\n    user: x-access-token\n"
    );
    let gh = write(&home.join(".config").join("gh").join("hosts.yml"), &hosts)?;

    Ok(vec![creds, gitconfig, gh])
}

/// Write an AWS profile (dummy credential + halter endpoint) for the `aws` CLI / SDKs:
/// `~/.aws/credentials` (the dummy key pair) and `~/.aws/config` (region + endpoint, plus
/// the CA bundle when halter terminates TLS).
fn write_aws(
    home: &Path,
    s: &ProvisionService,
    a: &models::provision::SigV4Auth,
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

/// Record the absolute paths halter wrote into the manifest (one per line), so [`teardown`]
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
    use models::provision::{BearerAuth, SigV4Auth};

    fn svc(
        target: &str,
        flavor: &str,
        auth: ProvisionAuth,
        mode: ProvisionMode,
    ) -> ProvisionService {
        ProvisionService {
            target: target.into(),
            flavor: flavor.into(),
            address: String::new(),
            mode,
            auth,
        }
    }

    fn doc_with_ca(ca: &str) -> ProvisionDoc {
        ProvisionDoc {
            halter_token: "tok-abc".into(),
            halter_ca: ca.into(),
            expires_at_ms: 12345,
            services: vec![
                svc(
                    "github",
                    "github",
                    ProvisionAuth::Bearer(BearerAuth {
                        token: "tok-abc".into(),
                    }),
                    ProvisionMode::Inject,
                ),
                svc(
                    "eks-prod",
                    "k8s",
                    ProvisionAuth::Bearer(BearerAuth {
                        token: "tok-abc".into(),
                    }),
                    ProvisionMode::Inject,
                ),
                svc(
                    "aws-acct-a",
                    "generic",
                    ProvisionAuth::SigV4(SigV4Auth {
                        access_key_id: "AKIADUMMY".into(),
                        secret_access_key: "dummy-secret".into(),
                        region: "us-east-1".into(),
                    }),
                    ProvisionMode::Inject,
                ),
            ],
        }
    }

    fn doc() -> ProvisionDoc {
        doc_with_ca("")
    }

    fn temp_home(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("halter-agent-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn env_exports_token_and_lists_services() {
        let env = render_env(&doc());
        assert!(env.contains("export HALTER_TOKEN='tok-abc'"));
        assert!(env.contains("service 'github'"));
        assert!(env.contains("service 'aws-acct-a'"));
        // No CA → no CA-bundle exports.
        assert!(!env.contains("CA_BUNDLE"));
    }

    #[test]
    fn write_configs_writes_native_files_into_home() {
        let dir = temp_home("native");
        let written = write_configs(&dir, &doc()).unwrap();
        assert!(written.iter().any(|p| p.ends_with("halter.env")));

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

        // gh hosts.yml carries the oauth token for the halter host.
        let gh = std::fs::read_to_string(dir.join(".config").join("gh").join("hosts.yml")).unwrap();
        assert!(gh.contains("oauth_token: tok-abc"));
        assert!(gh.contains("git_protocol: https"));

        // Everything stayed under the isolated home.
        assert!(written.iter().all(|p| p.starts_with(&dir)));
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
        // A pre-existing, unrelated credential must survive a halter write.
        std::fs::write(&creds, "https://x-access-token:other@github.example\n").unwrap();
        write_configs(&dir, &doc()).unwrap();
        let body = std::fs::read_to_string(&creds).unwrap();
        assert!(
            body.contains("other@github.example"),
            "pre-existing line preserved"
        );
        assert!(body.contains("tok-abc@"), "halter line added");
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
