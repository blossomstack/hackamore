//! The halter policy engine — the reusable decision core.
//!
//! Its entire public surface is one pure function, [`decide`]: given a normalized
//! [`Action`] and an agent's [`Policy`], it returns a [`Verdict`]. No I/O, no HTTP, no
//! async, no awareness that a proxy exists. That narrowness is the point: any data
//! plane (the bundled reverse proxy today, an Envoy `ext_authz` adapter tomorrow) can
//! reuse it by translating its request into an `Action` and enforcing the `Verdict`.
//!
//! Semantics: rules are evaluated top-to-bottom, **first match wins**, and if no rule
//! matches the action is **denied** (fail closed). An `Allow` is **bare**: the engine
//! names no credentials — the matched service instance owns its credential, and the data
//! plane attaches the inject/passthrough obligation.

use models::action::{Action, Verb};
use models::policy::{Condition, Effect, Match, Policy, Rule};
use models::verdict::{DenyReason, Verdict};
use serde_json::Value;

/// Decide whether `action` is permitted under `policy`.
///
/// Pure and total: every action yields either `Allow` (with obligations) or `Deny`
/// (with a reason). The default, when no rule matches, is `Deny(NotAllowed)`.
pub fn decide(action: &Action, policy: &Policy) -> Verdict {
    for rule in &policy.rules {
        if rule_matches(rule, action) {
            return verdict_for(rule);
        }
    }
    Verdict::deny(DenyReason::NotAllowed)
}

/// Build the verdict a matched rule produces. An `Allow` is **bare** — the engine no
/// longer names credentials (the matched service instance owns them); the data plane
/// attaches the inject/passthrough obligation from the routed target.
fn verdict_for(rule: &Rule) -> Verdict {
    match rule.effect {
        Effect::Allow => Verdict::allow(vec![]),
        Effect::Deny => Verdict::deny(DenyReason::ExplicitDeny),
    }
}

/// Whether every facet of a rule's `matches` holds for the action. Empty lists mean
/// "any", so an all-empty `Match` matches every action.
fn rule_matches(rule: &Rule, action: &Action) -> bool {
    let m: &Match = &rule.matches;
    target_matches(&m.targets, &action.target)
        && verb_matches(&m.verbs, &action.verb)
        && resource_matches(&m.resources, &action.resource.path)
        && m.conditions
            .iter()
            .all(|c| condition_holds(c, &action.fields))
}

fn target_matches(targets: &[String], target: &str) -> bool {
    targets.is_empty() || targets.iter().any(|t| t == target)
}

fn verb_matches(verbs: &[Verb], verb: &Verb) -> bool {
    verbs.is_empty() || verbs.contains(verb)
}

fn resource_matches(patterns: &[String], path: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_matches(p, path))
}

/// Segment-wise glob over a slash-joined resource path. `*` matches exactly one
/// segment; `**` matches any number of segments (including zero) and is normally the
/// trailing segment. Both pattern and path are compared by their `/`-split segments.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    segments_match(&pat, &seg)
}

fn segments_match(pat: &[&str], seg: &[&str]) -> bool {
    match pat.split_first() {
        None => seg.is_empty(),
        Some((&"**", rest)) => {
            // `**` consumes zero-or-more segments: succeed if `rest` matches any suffix.
            (0..=seg.len()).any(|i| segments_match(rest, &seg[i..]))
        }
        Some((&head, rest)) => match seg.split_first() {
            None => false,
            Some((&shead, srest)) => (head == "*" || head == shead) && segments_match(rest, srest),
        },
    }
}

/// Whether a single field condition holds against the action's `fields` JSON object.
fn condition_holds(condition: &Condition, fields: &Value) -> bool {
    match condition {
        Condition::Equals(c) => lookup(fields, &c.field) == Some(&c.value),
        Condition::OneOf(c) => lookup(fields, &c.field).is_some_and(|v| c.values.contains(v)),
        Condition::Exists(c) => lookup(fields, &c.field).is_some_and(|v| !v.is_null()),
    }
}

/// Resolve a dotted path (e.g. `"head.ref"`) into a JSON object. Returns `None` if any
/// segment is missing or a non-object is traversed.
fn lookup<'a>(fields: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = fields;
    for seg in path.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::action::{Action, CrudKind, Resource, Verb};
    use models::policy::{
        Condition, Effect, EqualsCondition, ExistsCondition, Match, OneOfCondition, Policy, Rule,
    };
    use models::verdict::{DenyReason, Verdict};

    fn empty_match() -> Match {
        Match {
            targets: vec![],
            verbs: vec![],
            resources: vec![],
            conditions: vec![],
        }
    }

    fn allow(matches: Match) -> Rule {
        Rule {
            effect: Effect::Allow,
            matches,
        }
    }

    fn deny(matches: Match) -> Rule {
        Rule {
            effect: Effect::Deny,
            matches,
        }
    }

    fn pr_create() -> Action {
        Action::of(
            "github",
            Verb::crud(CrudKind::Create),
            Resource::of("repos/octocat/hello/pulls", "pull_request"),
        )
    }

    #[test]
    fn empty_policy_denies_default() {
        let v = decide(&pr_create(), &Policy { rules: vec![] });
        assert!(matches!(
            v,
            Verdict::Deny(d) if d.reason == DenyReason::NotAllowed
        ));
    }

    #[test]
    fn matching_allow_rule_yields_bare_allow() {
        let policy = Policy {
            rules: vec![allow(Match {
                verbs: vec![Verb::crud(CrudKind::Create)],
                resources: vec!["repos/octocat/*/pulls".into()],
                ..empty_match()
            })],
        };
        match decide(&pr_create(), &policy) {
            // The engine no longer names credentials; allow is bare, the data plane
            // attaches the target's inject/passthrough obligation.
            Verdict::Allow(a) => assert!(a.obligations.is_empty()),
            Verdict::Deny(_) => panic!("expected allow"),
        }
    }

    #[test]
    fn named_verb_matches_named_rule() {
        let describe = Action::of(
            "aws-acct-a",
            Verb::action("ec2:DescribeInstances"),
            Resource::of("", "root"),
        );
        let policy = Policy {
            rules: vec![allow(Match {
                verbs: vec![Verb::action("ec2:DescribeInstances")],
                ..empty_match()
            })],
        };
        assert!(decide(&describe, &policy).is_allow());
        // A different named action falls through to default-deny.
        let terminate = Action::of(
            "aws-acct-a",
            Verb::action("ec2:TerminateInstances"),
            Resource::of("", "root"),
        );
        assert!(!decide(&terminate, &policy).is_allow());
    }

    #[test]
    fn first_match_wins_deny_before_allow() {
        let policy = Policy {
            rules: vec![
                deny(Match {
                    verbs: vec![Verb::crud(CrudKind::Create)],
                    ..empty_match()
                }),
                allow(empty_match()),
            ],
        };
        let v = decide(&pr_create(), &policy);
        assert!(matches!(
            v,
            Verdict::Deny(d) if d.reason == DenyReason::ExplicitDeny
        ));
    }

    #[test]
    fn read_only_agent_denied_create() {
        // Allow only reads; a create falls through to default-deny.
        let policy = Policy {
            rules: vec![allow(Match {
                verbs: vec![Verb::crud(CrudKind::Read)],
                ..empty_match()
            })],
        };
        let read = Action::of(
            "github",
            Verb::crud(CrudKind::Read),
            Resource::of("repos/octocat/hello", "repo"),
        );
        assert!(decide(&read, &policy).is_allow());
        assert!(!decide(&pr_create(), &policy).is_allow());
    }

    #[test]
    fn condition_gates_on_field_value() {
        // May open PRs, but only against base "develop".
        let policy = Policy {
            rules: vec![allow(Match {
                verbs: vec![Verb::crud(CrudKind::Create)],
                resources: vec!["repos/*/*/pulls".into()],
                conditions: vec![Condition::Equals(EqualsCondition {
                    field: "base".into(),
                    value: serde_json::json!("develop"),
                })],
                ..empty_match()
            })],
        };
        let to_develop = pr_create().with_fields(serde_json::json!({ "base": "develop" }));
        let to_main = pr_create().with_fields(serde_json::json!({ "base": "main" }));
        assert!(decide(&to_develop, &policy).is_allow());
        assert!(!decide(&to_main, &policy).is_allow());
    }

    #[test]
    fn one_of_and_exists_conditions() {
        let policy = Policy {
            rules: vec![allow(Match {
                conditions: vec![
                    Condition::OneOf(OneOfCondition {
                        field: "base".into(),
                        values: vec![serde_json::json!("develop"), serde_json::json!("staging")],
                    }),
                    Condition::Exists(ExistsCondition {
                        field: "title".into(),
                    }),
                ],
                ..empty_match()
            })],
        };
        let ok = pr_create().with_fields(serde_json::json!({ "base": "staging", "title": "x" }));
        let no_title = pr_create().with_fields(serde_json::json!({ "base": "staging" }));
        let bad_base = pr_create().with_fields(serde_json::json!({ "base": "main", "title": "x" }));
        assert!(decide(&ok, &policy).is_allow());
        assert!(!decide(&no_title, &policy).is_allow());
        assert!(!decide(&bad_base, &policy).is_allow());
    }

    #[test]
    fn glob_double_star_matches_remainder() {
        assert!(glob_matches(
            "repos/octocat/**",
            "repos/octocat/hello/pulls/1"
        ));
        assert!(glob_matches("repos/*/*/pulls", "repos/a/b/pulls"));
        assert!(!glob_matches("repos/*/*/pulls", "repos/a/b/issues"));
        assert!(!glob_matches("repos/*/pulls", "repos/a/b/pulls"));
        assert!(glob_matches("repos/octocat/**", "repos/octocat"));
    }

    #[test]
    fn dotted_field_lookup() {
        let fields = serde_json::json!({ "head": { "ref": "feature" } });
        assert_eq!(
            lookup(&fields, "head.ref"),
            Some(&serde_json::json!("feature"))
        );
        assert_eq!(lookup(&fields, "head.sha"), None);
        assert_eq!(lookup(&fields, "missing"), None);
    }
}
