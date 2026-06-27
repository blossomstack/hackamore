//! Generated protocol/contract types for hackamore (see `fluorite/*.fl`).
//!
//! Each module is generated from the like-named schema package. Hand-written
//! convenience constructors live here, never in the schemas.

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod action {
    include!(concat!(env!("OUT_DIR"), "/action/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod policy {
    include!(concat!(env!("OUT_DIR"), "/policy/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod verdict {
    include!(concat!(env!("OUT_DIR"), "/verdict/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod audit {
    include!(concat!(env!("OUT_DIR"), "/audit/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod control {
    include!(concat!(env!("OUT_DIR"), "/control/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod provision {
    include!(concat!(env!("OUT_DIR"), "/provision/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod lint {
    include!(concat!(env!("OUT_DIR"), "/lint/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod dryrun {
    include!(concat!(env!("OUT_DIR"), "/dryrun/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod apimodel {
    include!(concat!(env!("OUT_DIR"), "/apimodel/mod.rs"));
}

/// An empty `fields` JSON object — the default when a request carries no query or body
/// attributes relevant to conditional rules.
pub fn empty_fields() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl action::Action {
    /// Ergonomic constructor with an empty `fields` object (the generated `new` requires
    /// every field, including `fields`, positionally). `target` is the service instance
    /// name.
    pub fn of(target: impl Into<String>, verb: action::Verb, resource: action::Resource) -> Self {
        Self {
            target: target.into(),
            verb,
            resource,
            fields: empty_fields(),
        }
    }

    /// Set the request `fields` (merged query + body) used by conditional rules.
    #[must_use]
    pub fn with_fields(mut self, fields: serde_json::Value) -> Self {
        self.fields = fields;
        self
    }
}

impl action::Verb {
    /// A REST verb: the literal HTTP method the request states (e.g. "GET", "PATCH").
    pub fn method(m: impl Into<String>) -> Self {
        action::Verb::Method(action::MethodVerb { method: m.into() })
    }

    /// A named, service-defined action (e.g. "s3:PutObject").
    pub fn action(id: impl Into<String>) -> Self {
        action::Verb::Action(action::NamedVerb { id: id.into() })
    }
}

impl action::Resource {
    /// Ergonomic constructor accepting anything `Into<String>` (the generated `new`
    /// takes `String` positionally).
    pub fn of(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl verdict::Verdict {
    /// Whether this verdict permits the action.
    pub fn is_allow(&self) -> bool {
        matches!(self, verdict::Verdict::Allow(_))
    }

    /// Allow with explicit obligations. The data plane builds these from the matched
    /// service instance (inject its credential, or pass the consumer's through).
    pub fn allow(obligations: Vec<verdict::Obligation>) -> Self {
        verdict::Verdict::Allow(verdict::AllowVerdict { obligations })
    }

    /// An obligation to inject the named credential upstream.
    pub fn inject(id: impl Into<String>) -> verdict::Obligation {
        verdict::Obligation::InjectCredential(verdict::InjectCredentialObligation {
            credential: verdict::CredentialRef { id: id.into() },
        })
    }

    /// An obligation to forward the consumer's own credential unchanged.
    pub fn passthrough() -> verdict::Obligation {
        verdict::Obligation::Passthrough(verdict::PassthroughObligation {})
    }

    /// Deny with the given reason.
    pub fn deny(reason: verdict::DenyReason) -> Self {
        verdict::Verdict::Deny(verdict::DenyVerdict { reason })
    }
}

impl apimodel::Protocol {
    /// The REST protocol (operation = method + path).
    pub fn rest() -> Self {
        apimodel::Protocol::Rest(apimodel::RestProtocol {})
    }

    /// The git Smart-HTTP protocol (verb + resource derived by the git-http normalizer).
    pub fn git() -> Self {
        apimodel::Protocol::Git(apimodel::GitProtocol {})
    }

    /// Operation name read from a body/query parameter (e.g. `"Action"`).
    pub fn parameter(name: impl Into<String>) -> Self {
        apimodel::Protocol::Parameter(apimodel::NamedInParameter { name: name.into() })
    }

    /// Operation name read from a header, keeping the suffix after `suffix_after` (empty =
    /// whole value), e.g. `header("x-amz-target", ".")`.
    pub fn header(name: impl Into<String>, suffix_after: impl Into<String>) -> Self {
        apimodel::Protocol::Header(apimodel::NamedInHeader {
            name: name.into(),
            suffix_after: suffix_after.into(),
        })
    }
}

impl apimodel::Selector {
    /// A REST route selector (literal method + path template).
    pub fn route(method: impl Into<String>, path_template: impl Into<String>) -> Self {
        apimodel::Selector::Route(apimodel::RestSelector {
            method: method.into(),
            path_template: path_template.into(),
        })
    }

    /// A named-operation selector (the operation-name value under the service protocol).
    pub fn named(name: impl Into<String>) -> Self {
        apimodel::Selector::Named(apimodel::NamedSelector { name: name.into() })
    }
}

impl dryrun::MatchedRule {
    /// Build from the engine trace's `Option<usize>`.
    pub fn of(matched_rule: Option<usize>) -> Self {
        match matched_rule {
            Some(index) => dryrun::MatchedRule::Rule(dryrun::RuleIndex {
                index: index as u64,
            }),
            None => dryrun::MatchedRule::NoMatch(dryrun::NoMatch {}),
        }
    }
}

impl lint::Finding {
    /// An `Error` finding: the rule can never do what its author meant; rejects a mint.
    pub fn error(rule_index: usize, message: impl Into<String>) -> Self {
        Self {
            severity: lint::Severity::Error,
            rule_index: rule_index as u64,
            message: message.into(),
        }
    }

    /// A `Warning` finding: passes lint but deserves a look.
    pub fn warning(rule_index: usize, message: impl Into<String>) -> Self {
        Self {
            severity: lint::Severity::Warning,
            rule_index: rule_index as u64,
            message: message.into(),
        }
    }

    /// Whether this finding rejects a mint.
    pub fn is_error(&self) -> bool {
        self.severity == lint::Severity::Error
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::action::{Action, Resource, Verb};
    use super::verdict::{DenyReason, Verdict};

    #[test]
    fn action_round_trips_through_json() {
        let action = Action::of(
            "github",
            Verb::method("POST"),
            Resource::of("repos/octocat/hello/pulls"),
        )
        .with_fields(serde_json::json!({ "base": "main" }));
        let json = serde_json::to_string(&action).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn verb_union_supports_method_and_named_action() {
        let get = Verb::method("GET");
        let terminate = Verb::action("ec2:TerminateInstances");
        assert_ne!(get, terminate);
        for v in [get, terminate] {
            let json = serde_json::to_string(&v).unwrap();
            let back: Verb = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn api_model_round_trips_with_tagged_protocol_and_selector() {
        use super::apimodel::{ApiModel, ApiOperation, Field, FieldOrigin, Protocol, Selector};
        let rest_op = ApiOperation {
            id: "pulls.create".into(),
            selector: Selector::route("POST", "repos/{owner}/{repo}/pulls"),
            fields: vec![Field {
                name: "base".into(),
                source: FieldOrigin::Body,
                summary: "target branch".into(),
            }],
            summary: "Open a pull request".into(),
        };
        let model = ApiModel {
            protocol: Protocol::rest(),
            operations: vec![rest_op],
        };
        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["protocol"]["type"], "Rest");
        assert_eq!(json["operations"][0]["selector"]["type"], "Route");
        assert_eq!(json["operations"][0]["selector"]["value"]["method"], "POST");
        assert_eq!(
            json["operations"][0]["selector"]["value"]["pathTemplate"],
            "repos/{owner}/{repo}/pulls"
        );
        assert_eq!(json["operations"][0]["fields"][0]["source"], "Body");
        let back: ApiModel = serde_json::from_value(json).unwrap();
        assert_eq!(model, back);

        // A Parameter-protocol (RPC) model round-trips too — "AWS" is just config.
        let rpc = ApiModel {
            protocol: Protocol::parameter("Action"),
            operations: vec![ApiOperation {
                id: "DescribeInstances".into(),
                selector: Selector::named("DescribeInstances"),
                fields: vec![],
                summary: "List instances".into(),
            }],
        };
        let j = serde_json::to_value(&rpc).unwrap();
        assert_eq!(j["protocol"]["type"], "Parameter");
        assert_eq!(j["protocol"]["value"]["name"], "Action");
        assert_eq!(j["operations"][0]["selector"]["type"], "Named");
        assert_eq!(serde_json::from_value::<ApiModel>(j).unwrap(), rpc);
    }

    #[test]
    fn finding_constructors_and_json_shape() {
        let f = super::lint::Finding::error(2, "rule 2 can never match");
        assert!(f.is_error());
        assert!(!super::lint::Finding::warning(0, "looks odd").is_error());
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["severity"], "Error");
        // Fluorite structs serialize camelCase on the wire.
        assert_eq!(json["ruleIndex"], 2);
        let back: super::lint::Finding = serde_json::from_value(json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn verdict_helpers_build_expected_variants() {
        let allow = Verdict::allow(vec![Verdict::inject("gh")]);
        assert!(allow.is_allow());

        let passthrough = Verdict::allow(vec![Verdict::passthrough()]);
        assert!(passthrough.is_allow());

        let deny = Verdict::deny(DenyReason::NotAllowed);
        assert!(!deny.is_allow());
    }
}
