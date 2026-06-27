//! Human/JSON rendering for the validation commands (`hackamore policy lint`, `hackamore
//! policy test`). Pure string-building so it unit-tests without a terminal.

use hackamore_models::action::Action;
use hackamore_models::lint::Finding;
use hackamore_models::verdict::Verdict;
use hackamore_policy::Trace;

/// Render lint findings, one line each (`error rule 1: …` / `warning rule 0: …`), with
/// a one-line tally. Empty findings render the all-clear line.
pub fn findings_human(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "ok: no findings\n".to_string();
    }
    let mut out = String::new();
    for f in findings {
        let severity = if f.is_error() { "error" } else { "warning" };
        out.push_str(&format!(
            "{severity} rule {}: {}\n",
            f.rule_index, f.message
        ));
    }
    let errors = findings.iter().filter(|f| f.is_error()).count();
    out.push_str(&format!(
        "{} error(s), {} warning(s)\n",
        errors,
        findings.len() - errors
    ));
    out
}

/// Render a `policy test` result: the normalized action, then the traced decision.
pub fn trace_human(action: &Action, trace: &Trace) -> Result<String, serde_json::Error> {
    let decision = match (&trace.verdict, trace.matched_rule) {
        (Verdict::Allow(_), Some(rule)) => format!("Allow (rule {rule})"),
        // The engine only allows via a matched rule; this arm is unreachable but total.
        (Verdict::Allow(_), None) => "Allow".to_string(),
        (Verdict::Deny(d), Some(rule)) => format!("Deny {:?} (rule {rule})", d.reason),
        (Verdict::Deny(d), None) => format!("Deny {:?} (no rule matched)", d.reason),
    };
    Ok(format!(
        "action: {}\ndecision: {decision}\n",
        serde_json::to_string_pretty(action)?
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hackamore_models::action::Verb;

    #[test]
    fn findings_render_with_tally_and_all_clear() {
        assert_eq!(findings_human(&[]), "ok: no findings\n");
        let text = findings_human(&[
            Finding::error(1, "glob '/x' can never match"),
            Finding::warning(2, "field 'bsae' is not documented"),
        ]);
        assert_eq!(
            text,
            "error rule 1: glob '/x' can never match\n\
             warning rule 2: field 'bsae' is not documented\n\
             1 error(s), 1 warning(s)\n"
        );
    }

    #[test]
    fn trace_renders_decision_lines() {
        use hackamore_models::action::Resource;
        use hackamore_models::verdict::DenyReason;
        let action = Action::of(
            "github",
            Verb::method("POST"),
            Resource::of("repos/o/r/pulls"),
        );
        let allowed = Trace {
            verdict: Verdict::allow(vec![]),
            matched_rule: Some(0),
        };
        let text = trace_human(&action, &allowed).unwrap();
        assert!(text.starts_with("action: {"));
        assert!(text.ends_with("decision: Allow (rule 0)\n"));

        let fallthrough = Trace {
            verdict: Verdict::deny(DenyReason::NotAllowed),
            matched_rule: None,
        };
        let text = trace_human(&action, &fallthrough).unwrap();
        assert!(text.ends_with("decision: Deny NotAllowed (no rule matched)\n"));
    }
}
