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
    /// A coarse CRUD verb (RESTful method mapping).
    pub fn crud(kind: action::CrudKind) -> Self {
        action::Verb::Crud(action::CrudVerb { kind })
    }

    /// A named, service-defined action (e.g. "s3:PutObject").
    pub fn action(id: impl Into<String>) -> Self {
        action::Verb::Action(action::NamedVerb { id: id.into() })
    }

    /// Parse a compact verb shorthand: the case-insensitive CRUD words `read`/`create`/
    /// `update`/`delete` map to the closed [`action::CrudVerb`] arm; anything else is a
    /// named action verb. This is the terse spelling a policy-authoring layer expands into
    /// the verbose tagged-union JSON the wire format requires
    /// (`{"type":"Crud","value":{"kind":"Read"}}`), so operators and call sites can write
    /// `"read"` or `"ec2:DescribeInstances"` instead.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "read" => Self::crud(action::CrudKind::Read),
            "create" => Self::crud(action::CrudKind::Create),
            "update" => Self::crud(action::CrudKind::Update),
            "delete" => Self::crud(action::CrudKind::Delete),
            _ => Self::action(s),
        }
    }
}

impl action::Resource {
    /// Ergonomic constructor accepting anything `Into<String>` (the generated `new`
    /// takes `String` positionally).
    pub fn of(path: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::action::{Action, CrudKind, Resource, Verb};
    use super::verdict::{DenyReason, Verdict};

    #[test]
    fn action_round_trips_through_json() {
        let action = Action::of(
            "github",
            Verb::crud(CrudKind::Create),
            Resource::of("repos/octocat/hello/pulls", "pull_request"),
        )
        .with_fields(serde_json::json!({ "base": "main" }));
        let json = serde_json::to_string(&action).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn verb_parse_shorthand_maps_crud_words_and_named_actions() {
        assert_eq!(Verb::parse("read"), Verb::crud(CrudKind::Read));
        assert_eq!(Verb::parse("DELETE"), Verb::crud(CrudKind::Delete));
        assert_eq!(
            Verb::parse("ec2:DescribeInstances"),
            Verb::action("ec2:DescribeInstances")
        );
    }

    #[test]
    fn verb_union_supports_crud_and_named_action() {
        let read = Verb::crud(CrudKind::Read);
        let terminate = Verb::action("ec2:TerminateInstances");
        assert_ne!(read, terminate);
        let json = serde_json::to_string(&terminate).unwrap();
        let back: Verb = serde_json::from_str(&json).unwrap();
        assert_eq!(terminate, back);
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
