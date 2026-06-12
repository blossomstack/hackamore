//! Optional TLS termination for the agent-facing proxy listener.
//!
//! hackamore's baseline model is a reverse proxy reached over plaintext inside a sandbox whose
//! only egress is hackamore (see [`crate::server`]). When instead the consumer is configured to
//! *terminate TLS at hackamore and trust hackamore's certificate*, the operator supplies a serving
//! cert + key here; the provision doc then carries the CA the consumer must trust
//! (`ProvisionDoc.hackamore_ca`), which `hackamore-agent` writes into each tool's config.
//!
//! The crypto provider is `ring` (matching reqwest's rustls stack), selected explicitly so
//! this works without rustls's default-provider feature.

use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The PEM material an operator configures for TLS termination: the serving certificate
/// chain, its private key, and the CA bundle consumers must trust (often the self-signed
/// cert itself). Storage/config type — not a wire type.
#[derive(Clone, Debug)]
pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    /// What a consumer adds to its trust store to validate hackamore — surfaced verbatim in
    /// the provision doc as `hackamore_ca`.
    pub ca_pem: String,
}

impl TlsMaterial {
    /// Build a rustls [`ServerConfig`] (no client auth) from the configured cert + key.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, String> {
        let certs = parse_certificates(&self.cert_pem)?;
        if certs.is_empty() {
            return Err("no certificates found in cert PEM".to_string());
        }
        let key = parse_private_key(&self.key_pem)?;
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls protocol versions: {e}"))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("tls cert/key: {e}"))?;
        Ok(Arc::new(config))
    }
}

/// Parse every `CERTIFICATE` block from a PEM bundle into DER.
fn parse_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    Ok(pem_blocks(pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect())
}

/// Parse the first private-key block (PKCS#8 `PRIVATE KEY`, PKCS#1 `RSA PRIVATE KEY`, or
/// SEC1 `EC PRIVATE KEY`) into a rustls key.
fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    if let Some(der) = pem_blocks(pem, "PRIVATE KEY")?.into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("pkcs8 key: {e}"));
    }
    if let Some(der) = pem_blocks(pem, "RSA PRIVATE KEY")?.into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("pkcs1 key: {e}"));
    }
    if let Some(der) = pem_blocks(pem, "EC PRIVATE KEY")?.into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("sec1 key: {e}"));
    }
    Err("no private key found in key PEM".to_string())
}

/// Extract and base64-decode every `-----BEGIN <label>-----`…`-----END <label>-----` block.
fn pem_blocks(pem: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else {
            return Err(format!("unterminated PEM block for {label}"));
        };
        let body: String = after[..stop].split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|e| format!("base64 decode {label}: {e}"))?;
        blocks.push(der);
        rest = &after[stop + end.len()..];
    }
    Ok(blocks)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // A throwaway `localhost` server leaf (RSA-2048, PKCS#8) signed by a throwaway CA,
    // generated with openssl. Used only to exercise PEM parsing + ServerConfig assembly.
    const TEST_CERT: &str = include_str!("../testdata/tls_cert.pem");
    const TEST_KEY: &str = include_str!("../testdata/tls_key.pem");
    const TEST_CA: &str = include_str!("../testdata/tls_ca.pem");

    #[test]
    fn parses_cert_and_key_and_builds_server_config() {
        let mat = TlsMaterial {
            cert_pem: TEST_CERT.to_string(),
            key_pem: TEST_KEY.to_string(),
            ca_pem: TEST_CA.to_string(),
        };
        assert_eq!(parse_certificates(&mat.cert_pem).unwrap().len(), 1);
        assert!(parse_private_key(&mat.key_pem).is_ok());
        assert!(mat.server_config().is_ok());
    }

    #[test]
    fn rejects_empty_and_malformed_material() {
        let empty = TlsMaterial {
            cert_pem: String::new(),
            key_pem: TEST_KEY.to_string(),
            ca_pem: String::new(),
        };
        assert!(empty.server_config().is_err());
        assert!(pem_blocks("-----BEGIN CERTIFICATE-----\nnotb64!!", "CERTIFICATE").is_err());
    }
}
