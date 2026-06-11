//! Fail-closed request-path canonicalization. Policy resource globs and field conditions
//! are segment- and value-oriented, so a request whose path is *spelled differently* from
//! its canonical form could otherwise slip past them: `repos/octocat/../evil`,
//! `repos//octocat`, a trailing slash, or percent-encoded separators (`repos/%2e%2e/evil`,
//! `repos/%65vil`). This module folds every such request into one canonical form **before**
//! any policy decision, so the engine and the upstream see the same path the operator
//! reasoned about.
//!
//! Two views come out, both with a leading `/`:
//! - [`CanonicalPath::decoded`] — segments percent-decoded and dot-resolved, for matching
//!   and field extraction (what a human wrote a glob against).
//! - [`CanonicalPath::encoded`] — the same segments re-encoded canonically, safe to forward
//!   upstream and to feed the SigV4 signer.
//!
//! A `..` that would escape above the root is rejected (`Err`), not clamped — there is no
//! legitimate request it denies, and it removes any doubt about what "above root" forwards
//! to.

use crate::sigv4::{percent_decode, uri_encode};

/// The canonical forms of a request path. See the module docs.
#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalPath {
    /// Percent-decoded, dot-resolved path (leading `/`). Used for policy matching and
    /// `fields` extraction.
    pub decoded: String,
    /// Re-encoded canonical path (leading `/`). Used to forward upstream and to sign.
    pub encoded: String,
}

/// Why a path could not be canonicalized. The data plane maps this to a fail-closed deny.
#[derive(Debug, PartialEq, Eq)]
pub enum CanonError {
    /// A `..` segment popped above the root — a traversal attempt.
    Escape,
}

/// Canonicalize a request path, or fail closed. Percent-decodes each segment (so encoded
/// dots/letters can't disguise a segment), resolves `.`/`..`, and collapses empty segments
/// (duplicate and trailing slashes). An encoded slash (`%2F`) decodes to a byte *inside* a
/// segment and is re-encoded — it never becomes a separator, so it can neither split a
/// segment for the glob nor smuggle a path traversal.
pub fn path(raw: &str) -> Result<CanonicalPath, CanonError> {
    let mut stack: Vec<String> = Vec::new();
    for seg in raw.trim_start_matches('/').split('/') {
        let decoded = String::from_utf8_lossy(&percent_decode(seg)).into_owned();
        match decoded.as_str() {
            "" | "." => {}
            ".." => {
                stack.pop().ok_or(CanonError::Escape)?;
            }
            _ => stack.push(decoded),
        }
    }
    let decoded = format!("/{}", stack.join("/"));
    let encoded = format!(
        "/{}",
        stack
            .iter()
            .map(|s| uri_encode(s.as_bytes(), true))
            .collect::<Vec<_>>()
            .join("/")
    );
    Ok(CanonicalPath { decoded, encoded })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn decoded(raw: &str) -> String {
        path(raw).unwrap().decoded
    }

    #[test]
    fn resolves_dot_segments() {
        assert_eq!(decoded("/repos/octocat/../evil"), "/repos/evil");
        assert_eq!(decoded("/repos/./octocat"), "/repos/octocat");
    }

    #[test]
    fn collapses_empty_and_trailing_slashes() {
        assert_eq!(decoded("/repos//octocat"), "/repos/octocat");
        assert_eq!(decoded("/repos/octocat/"), "/repos/octocat");
        assert_eq!(decoded("/"), "/");
        assert_eq!(decoded(""), "/");
    }

    #[test]
    fn decodes_percent_escapes_so_they_cannot_disguise_a_segment() {
        // %2e%2e == ".." → resolved; %65 == 'e'.
        assert_eq!(decoded("/repos/octocat/%2e%2e/evil"), "/repos/evil");
        assert_eq!(decoded("/repos/%65vil"), "/repos/evil");
    }

    #[test]
    fn root_escape_is_rejected() {
        assert_eq!(path("/.."), Err(CanonError::Escape));
        assert_eq!(path("/repos/../../etc"), Err(CanonError::Escape));
    }

    #[test]
    fn encoded_slash_decodes_for_matching_but_re_encodes_for_the_wire() {
        // The matching view decodes %2F to '/' (so a smuggled separator is *more* visible to
        // deny/allow globs — fail-closed), while the wire view re-encodes it to %2F so the
        // upstream receives exactly the resource the consumer addressed.
        let c = path("/repos/a%2Fb").unwrap();
        assert_eq!(c.decoded, "/repos/a/b");
        assert_eq!(c.encoded, "/repos/a%2Fb");
    }

    #[test]
    fn plain_paths_are_unchanged() {
        let c = path("/api/v1/namespaces/dev/pods").unwrap();
        assert_eq!(c.decoded, "/api/v1/namespaces/dev/pods");
        assert_eq!(c.encoded, "/api/v1/namespaces/dev/pods");
    }
}
