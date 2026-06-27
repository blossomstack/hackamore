//! The hardcoded git Smart-HTTP [`ApiModel`]. Git's verb depends on the `?service=` query
//! value under the same method+path, which no OpenAPI/Smithy selector can express, so the
//! request→`Action` mapping is the custom `git-http` normalizer regardless. The model exists
//! only to advertise vocabulary (its two operations and a `repo` resource) for lint /
//! discovery / the studio's verb list — it is never imported from a spec, so it is built in
//! code. Generic over the git host (works for GitHub, GitLab, Gitea, …); a preset adds the
//! concrete host.

use hackamore_models::apimodel::{ApiModel, ApiOperation, Field, FieldOrigin, Protocol, Selector};

/// The two git Smart-HTTP operations as named verbs, each exposing the `repo` resource
/// (`{owner}/{repo}`) the normalizer derives. `git-upload-pack` is fetch/clone;
/// `git-receive-pack` is push.
pub fn git_model() -> ApiModel {
    let op = |id: &str, summary: &str| ApiOperation {
        id: id.to_string(),
        selector: Selector::named(id),
        fields: vec![Field {
            name: "repo".to_string(),
            source: FieldOrigin::Path,
            summary: "The {owner}/{repo} the operation addresses.".to_string(),
        }],
        summary: summary.to_string(),
    };
    ApiModel {
        protocol: Protocol::git(),
        operations: vec![
            op(
                "git-upload-pack",
                "Fetch/clone refs and objects from a repository.",
            ),
            op("git-receive-pack", "Push refs and objects to a repository."),
        ],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn git_model_has_the_two_smart_http_operations_and_git_protocol() {
        let model = git_model();
        assert_eq!(model.protocol, Protocol::git());
        let ids: Vec<&str> = model.operations.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["git-upload-pack", "git-receive-pack"]);
        // Every op exposes the `repo` resource for lint/discovery.
        for op in &model.operations {
            assert!(op.fields.iter().any(|f| f.name == "repo"));
        }
    }
}
