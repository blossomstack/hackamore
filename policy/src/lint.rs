//! Policy lint — pure, model-aware validation of a policy document, sitting beside
//! [`crate::decide`]. Catches what the type system can't: rules that can never match,
//! rules shadowed by earlier rules, and rules that disagree with a service's imported
//! vocabulary ([`ApiModel`]).
//!
//! Severity model: **Error** = the rule cannot do what its author meant (unmatchable
//! glob, a rule unreachable behind an opposite-effect rule) — mints reject these.
//! **Warning** = model-derived advice; an imported model is a curated subset of each
//! service's API, so absence from it is a smell, not proof.
//!
//! The `models` map is keyed by **target name** (what `Match.targets` contains). The
//! gateway maps each configured service name to its imported `ApiModel`. Targets without
//! an entry (or with an empty model) skip model-derived checks — structural checks
//! always run.

use hackamore_models::action::Verb;
use hackamore_models::apimodel::{ApiModel, ApiOperation, Selector};
use hackamore_models::lint::Finding;
use hackamore_models::policy::{Policy, Rule};
use std::collections::BTreeMap;

/// Lint `policy` against the per-target `models`. Findings are ordered by rule index.
pub fn lint(policy: &Policy, models: &BTreeMap<String, &ApiModel>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, rule) in policy.rules.iter().enumerate() {
        findings.extend(unmatchable_globs(index, rule));
        findings.extend(shadowed_by_earlier(index, rule, &policy.rules));
        findings.extend(catalog_checks(index, rule, models));
    }
    findings.sort_by_key(|f| f.rule_index);
    findings
}

/// The operation's verb, derived from its selector: a REST route's literal method, or a
/// named/RPC operation's literal action name.
fn op_verb(op: &ApiOperation) -> Verb {
    match &op.selector {
        Selector::Route(r) => Verb::method(&r.method),
        Selector::Named(n) => Verb::action(&n.name),
    }
}

/// The route path template of an operation, or `None` for a named/RPC operation (which
/// has no path, so glob checks skip it).
fn op_path(op: &ApiOperation) -> Option<&str> {
    match &op.selector {
        Selector::Route(r) => Some(&r.path_template),
        Selector::Named(_) => None,
    }
}

/// E1: a resource glob that no normalized action path can ever match. Action paths are
/// slash-joined with no leading slash and no empty segments, so a pattern with a leading
/// `/`, an empty segment (`//`), or nothing at all is dead weight — and almost certainly
/// an authoring mistake.
fn unmatchable_globs(index: usize, rule: &Rule) -> Vec<Finding> {
    rule.matches
        .resources
        .iter()
        .filter_map(|glob| {
            let problem = if glob.is_empty() {
                Some("is empty (matches only the bare service root)")
            } else if glob.starts_with('/') {
                Some("has a leading '/' — action paths never do, so it can never match")
            } else if glob.split('/').any(str::is_empty) {
                Some("has an empty segment ('//') — action paths never do")
            } else {
                None
            };
            problem.map(|p| Finding::error(index, format!("resource glob '{glob}' {p}")))
        })
        .collect()
}

/// E2/W1: rule `index` never fires because an earlier rule matches everything it would.
/// Opposite effects = Error (the policy silently does the opposite of what the author
/// wrote); same effect = Warning (redundant).
fn shadowed_by_earlier(index: usize, rule: &Rule, rules: &[Rule]) -> Vec<Finding> {
    rules[..index]
        .iter()
        .enumerate()
        .find(|(_, earlier)| subsumes(earlier, rule))
        .map(|(j, earlier)| {
            if earlier.effect == rule.effect {
                vec![Finding::warning(
                    index,
                    format!("redundant: rule {j} already matches everything this rule does"),
                )]
            } else {
                vec![Finding::error(
                    index,
                    format!(
                        "unreachable: rule {j} matches everything this rule does but with \
                         effect {:?} — this rule never fires",
                        earlier.effect
                    ),
                )]
            }
        })
        .unwrap_or_default()
}

/// Whether `general`'s match-set is a superset of `specific`'s — every facet of
/// `general` is at-least-as-broad. Conservative: false negatives are fine (we miss a
/// shadow), false positives are not.
fn subsumes(general: &Rule, specific: &Rule) -> bool {
    let g = &general.matches;
    let s = &specific.matches;
    let targets_ok = g.targets.is_empty()
        || (!s.targets.is_empty() && s.targets.iter().all(|t| g.targets.contains(t)));
    let verbs_ok =
        g.verbs.is_empty() || (!s.verbs.is_empty() && s.verbs.iter().all(|v| g.verbs.contains(v)));
    let resources_ok = g.resources.is_empty()
        || (!s.resources.is_empty()
            && s.resources
                .iter()
                .all(|sg| g.resources.iter().any(|gg| glob_subsumes(gg, sg))));
    // Fewer conditions = broader: everything `general` requires, `specific` requires too.
    let conditions_ok = g.conditions.iter().all(|c| s.conditions.contains(c));
    targets_ok && verbs_ok && resources_ok && conditions_ok
}

/// Whether glob `general` matches every path glob `specific` matches. Segment-wise over
/// the same syntax [`crate::decide`] uses: `*` = one segment, `**` = zero or more.
fn glob_subsumes(general: &str, specific: &str) -> bool {
    let g: Vec<&str> = general.split('/').collect();
    let s: Vec<&str> = specific.split('/').collect();
    pattern_covers(&g, &s)
}

fn pattern_covers(g: &[&str], s: &[&str]) -> bool {
    match g.split_first() {
        None => s.is_empty(),
        Some((&"**", rest)) => (0..=s.len()).any(|i| {
            // `**` may absorb any prefix of `specific` — including its wildcards.
            pattern_covers(rest, &s[i..])
        }),
        Some((&head, rest)) => match s.split_first() {
            None => false,
            // `**` in `specific` can only be covered by `**` in `general` (handled above).
            Some((&"**", _)) => false,
            Some((&shead, srest)) => {
                (head == "*" || (head == shead && shead != "*")) && pattern_covers(rest, srest)
            }
        },
    }
}

/// W2 + W3: model-aware checks for one rule. Applicable models: the rule's named targets
/// (empty targets = all provided). Raw/unknown targets are skipped. Glob checks only
/// consider operations that have a path (named/RPC ops are skipped).
fn catalog_checks(index: usize, rule: &Rule, models: &BTreeMap<String, &ApiModel>) -> Vec<Finding> {
    let applicable: Vec<(&str, &ApiModel)> = if rule.matches.targets.is_empty() {
        models.iter().map(|(k, m)| (k.as_str(), *m)).collect()
    } else {
        rule.matches
            .targets
            .iter()
            .filter_map(|t| models.get_key_value(t).map(|(k, m)| (k.as_str(), *m)))
            .collect()
    };
    let applicable: Vec<(&str, &ApiModel)> = applicable
        .into_iter()
        .filter(|(_, m)| !m.operations.is_empty())
        .collect();
    if applicable.is_empty() {
        return vec![];
    }

    let mut findings = Vec::new();
    let verb_ok = |op: &ApiOperation| {
        rule.matches.verbs.is_empty() || rule.matches.verbs.contains(&op_verb(op))
    };

    // W2: every resource glob should reach at least one catalogued (path-bearing) operation.
    for glob in &rule.matches.resources {
        let reaches_any = applicable.iter().any(|(_, m)| {
            m.operations.iter().any(|op| {
                verb_ok(op) && op_path(op).is_some_and(|path| glob_intersects_route(glob, path))
            })
        });
        if !reaches_any {
            let names: Vec<&str> = applicable.iter().map(|(name, _)| *name).collect();
            findings.push(Finding::warning(
                index,
                format!(
                    "resource glob '{glob}' matches no catalogued operation of {} \
                     (catalogs are curated, not exhaustive — double-check the path shape)",
                    names.join("/")
                ),
            ));
        }
    }

    // W3: condition fields should appear on some operation the rule can match.
    let matched_ops: Vec<&ApiOperation> = applicable
        .iter()
        .flat_map(|(_, m)| m.operations.iter())
        .filter(|op| {
            verb_ok(op)
                && (rule.matches.resources.is_empty()
                    || op_path(op).is_some_and(|path| {
                        rule.matches
                            .resources
                            .iter()
                            .any(|g| glob_intersects_route(g, path))
                    }))
        })
        .collect();
    let documented: Vec<&str> = matched_ops
        .iter()
        .flat_map(|op| op.fields.iter().map(|f| f.name.as_str()))
        .collect();
    if !documented.is_empty() {
        for condition in &rule.matches.conditions {
            let field = condition_field(condition);
            let head = field.split('.').next().unwrap_or(field);
            if !documented.contains(&head) {
                findings.push(Finding::warning(
                    index,
                    format!(
                        "condition field '{field}' is not documented on any operation this \
                         rule matches (known fields: {})",
                        documented.join(", ")
                    ),
                ));
            }
        }
    }
    findings
}

fn condition_field(condition: &hackamore_models::policy::Condition) -> &str {
    use hackamore_models::policy::Condition;
    match condition {
        Condition::Equals(c) => &c.field,
        Condition::OneOf(c) => &c.field,
        Condition::Exists(c) => &c.field,
    }
}

/// Whether a policy glob and a catalog route template can match a common concrete path.
/// Glob segments: literal / `*` (one) / `**` (zero or more). Template segments: literal
/// / `{name}` (one) / trailing `{name+}` (one or more).
fn glob_intersects_route(glob: &str, template: &str) -> bool {
    let g: Vec<&str> = glob.split('/').collect();
    let t: Vec<&str> = template.split('/').collect();
    intersects(&g, &t)
}

fn intersects(g: &[&str], t: &[&str]) -> bool {
    match (g.split_first(), t.split_first()) {
        (None, None) => true,
        // Glob exhausted: only an (impossible) empty-remainder template matches; a
        // trailing `{x+}` needs at least one more segment, so no.
        (None, Some(_)) => false,
        (Some((&"**", grest)), _) => {
            // `**` absorbs zero or more template segments.
            (0..=t.len()).any(|i| intersects(grest, &t[i..]))
        }
        (Some(_), None) => false,
        (Some((&ghead, grest)), Some((&thead, trest))) => {
            if is_rest_capture(thead) {
                // `{x+}`: one-or-more segments. The current glob segment must be able to
                // match *a* segment (any non-`**` can); then either the capture is done
                // or it absorbs more glob segments.
                return intersects(grest, t) || intersects(grest, trest);
            }
            let seg_compatible = ghead == "*" || is_capture(thead) || ghead == thead;
            seg_compatible && intersects(grest, trest)
        }
    }
}

fn is_capture(seg: &str) -> bool {
    seg.starts_with('{') && seg.ends_with('}')
}

fn is_rest_capture(seg: &str) -> bool {
    is_capture(seg) && seg.ends_with("+}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hackamore_models::action::Verb;
    use hackamore_models::apimodel::{
        ApiModel, ApiOperation, Field, FieldOrigin, Protocol, Selector,
    };
    use hackamore_models::lint::Severity;
    use hackamore_models::policy::{Condition, Effect, EqualsCondition, Match, Rule};

    fn rule(effect: Effect, m: Match) -> Rule {
        Rule { effect, matches: m }
    }

    fn m() -> Match {
        Match {
            targets: vec![],
            verbs: vec![],
            resources: vec![],
            conditions: vec![],
        }
    }

    fn body_field(name: &str) -> Field {
        Field {
            name: name.into(),
            source: FieldOrigin::Body,
            summary: String::new(),
        }
    }

    fn github() -> ApiModel {
        ApiModel {
            protocol: Protocol::rest(),
            operations: vec![
                ApiOperation {
                    id: "pulls.create".into(),
                    selector: Selector::route("POST", "repos/{owner}/{repo}/pulls"),
                    fields: vec![body_field("base"), body_field("title")],
                    summary: "Open a pull request".into(),
                },
                ApiOperation {
                    id: "contents.get".into(),
                    selector: Selector::route("GET", "repos/{owner}/{repo}/contents/{path+}"),
                    fields: vec![],
                    summary: "Read a file".into(),
                },
            ],
        }
    }

    fn catalogs(c: &ApiModel) -> BTreeMap<String, &ApiModel> {
        BTreeMap::from([("github".to_string(), c)])
    }

    fn lint_one(rule_: Rule, c: &ApiModel) -> Vec<Finding> {
        lint(&Policy { rules: vec![rule_] }, &catalogs(c))
    }

    #[test]
    fn unmatchable_globs_are_errors() {
        let c = github();
        let bad = |glob: &str| {
            rule(
                Effect::Allow,
                Match {
                    resources: vec![glob.into()],
                    ..m()
                },
            )
        };
        for glob in ["/repos/octocat/**", "repos//pulls", ""] {
            let findings = lint_one(bad(glob), &c);
            assert!(
                findings.iter().any(|f| f.severity == Severity::Error),
                "expected error for {glob:?}, got {findings:?}"
            );
        }
        // A healthy glob produces no error.
        let ok = lint_one(bad("repos/octocat/*/pulls"), &c);
        assert!(ok.iter().all(|f| f.severity != Severity::Error), "{ok:?}");
    }

    #[test]
    fn shadowed_rule_with_opposite_effect_is_an_error() {
        let allow_all = rule(Effect::Allow, m());
        let deny_create = rule(
            Effect::Deny,
            Match {
                verbs: vec![Verb::method("POST")],
                ..m()
            },
        );
        let findings = lint(
            &Policy {
                rules: vec![allow_all, deny_create],
            },
            &BTreeMap::new(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_index, 1);
        assert!(findings[0].is_error());
        assert!(findings[0].message.contains("unreachable"));
    }

    #[test]
    fn shadowed_rule_with_same_effect_is_a_warning() {
        let broad = rule(
            Effect::Allow,
            Match {
                resources: vec!["repos/octocat/**".into()],
                ..m()
            },
        );
        let narrow = rule(
            Effect::Allow,
            Match {
                resources: vec!["repos/octocat/hello/pulls".into()],
                ..m()
            },
        );
        let findings = lint(
            &Policy {
                rules: vec![broad, narrow],
            },
            &BTreeMap::new(),
        );
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].is_error());
        assert!(findings[0].message.contains("redundant"));
    }

    #[test]
    fn narrower_earlier_rule_does_not_shadow() {
        // Earlier deny is narrower than the later allow: no shadow (this is the normal
        // carve-out ordering).
        let deny_one = rule(
            Effect::Deny,
            Match {
                resources: vec!["repos/octocat/secret/**".into()],
                ..m()
            },
        );
        let allow_all = rule(
            Effect::Allow,
            Match {
                resources: vec!["repos/octocat/**".into()],
                ..m()
            },
        );
        let findings = lint(
            &Policy {
                rules: vec![deny_one, allow_all],
            },
            &BTreeMap::new(),
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn glob_subsumption_is_conservative() {
        assert!(glob_subsumes("repos/**", "repos/a/b"));
        assert!(glob_subsumes("repos/*/x", "repos/a/x"));
        assert!(glob_subsumes("**", "anything/at/all"));
        assert!(glob_subsumes("repos/**", "repos/*/pulls"));
        assert!(!glob_subsumes("repos/*/x", "repos/**"));
        assert!(!glob_subsumes("repos/a/x", "repos/*/x"));
        assert!(!glob_subsumes("repos/*", "repos/a/b"));
    }

    #[test]
    fn glob_reaching_no_catalogued_operation_warns() {
        let c = github();
        let findings = lint_one(
            rule(
                Effect::Allow,
                Match {
                    targets: vec!["github".into()],
                    resources: vec!["orgs/octocat/teams".into()],
                    ..m()
                },
            ),
            &c,
        );
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].is_error());
        assert!(findings[0].message.contains("no catalogued operation"));

        // Globs that do reach catalogued routes are quiet, wildcards included.
        for glob in [
            "repos/octocat/*/pulls",
            "repos/**",
            "repos/octocat/hello/contents/docs/README.md",
        ] {
            let findings = lint_one(
                rule(
                    Effect::Allow,
                    Match {
                        resources: vec![glob.into()],
                        ..m()
                    },
                ),
                &c,
            );
            assert!(findings.is_empty(), "{glob}: {findings:?}");
        }
    }

    #[test]
    fn verb_filter_narrows_reachable_operations() {
        let c = github();
        // Delete reaches nothing in this catalog (only Create pulls + Read contents).
        let findings = lint_one(
            rule(
                Effect::Allow,
                Match {
                    verbs: vec![Verb::method("DELETE")],
                    resources: vec!["repos/octocat/*/pulls".into()],
                    ..m()
                },
            ),
            &c,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("no catalogued operation"));
    }

    #[test]
    fn unknown_condition_field_warns_with_known_fields() {
        let c = github();
        let findings = lint_one(
            rule(
                Effect::Allow,
                Match {
                    verbs: vec![Verb::method("POST")],
                    resources: vec!["repos/octocat/*/pulls".into()],
                    conditions: vec![Condition::Equals(EqualsCondition {
                        field: "bsae".into(),
                        value: serde_json::json!("develop"),
                    })],
                    ..m()
                },
            ),
            &c,
        );
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].is_error());
        assert!(findings[0].message.contains("'bsae'"));
        assert!(findings[0].message.contains("base"));

        // The correctly spelled field is quiet.
        let ok = lint_one(
            rule(
                Effect::Allow,
                Match {
                    verbs: vec![Verb::method("POST")],
                    resources: vec!["repos/octocat/*/pulls".into()],
                    conditions: vec![Condition::Equals(EqualsCondition {
                        field: "base".into(),
                        value: serde_json::json!("develop"),
                    })],
                    ..m()
                },
            ),
            &c,
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn raw_targets_skip_catalog_checks() {
        let c = github();
        // Target not in the map: structural checks only.
        let findings = lint_one(
            rule(
                Effect::Allow,
                Match {
                    targets: vec!["openai".into()],
                    resources: vec!["v1/chat/completions".into()],
                    ..m()
                },
            ),
            &c,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn glob_route_intersection_handles_captures_and_rest() {
        let t = "repos/{owner}/{repo}/pulls";
        assert!(glob_intersects_route("repos/octocat/*/pulls", t));
        assert!(glob_intersects_route("repos/**", t));
        assert!(glob_intersects_route("**", t));
        assert!(!glob_intersects_route("repos/octocat/pulls", t)); // too short
        assert!(!glob_intersects_route("orgs/**", t));

        let rest = "repos/{owner}/{repo}/contents/{path+}";
        assert!(glob_intersects_route("repos/o/r/contents/a/b/c", rest));
        assert!(glob_intersects_route("repos/o/r/contents/*", rest));
        assert!(glob_intersects_route("repos/o/r/**", rest));
        // `{path+}` needs at least one segment.
        assert!(!glob_intersects_route("repos/o/r/contents", rest));
    }
}
