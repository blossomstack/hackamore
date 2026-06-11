//! The audit sink. Every decision halter makes — allow or deny — is recorded. The
//! trait lets the data plane stay oblivious to where records go; v1 ships an in-memory
//! sink (used by tests and introspection) and a `tracing` sink for operations.

use models::audit::AuditEvent;
use parking_lot::{Mutex, RwLock};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Receives one immutable [`AuditEvent`] per decision. Implementations must be cheap
/// and non-blocking; the data plane records on the request path.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Collects events in memory. Used by tests and for local introspection.
#[derive(Default)]
pub struct InMemoryAudit {
    events: RwLock<Vec<AuditEvent>>,
}

impl InMemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot copy of all recorded events, oldest first.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }
}

impl AuditSink for InMemoryAudit {
    fn record(&self, event: AuditEvent) {
        self.events.write().push(event);
    }
}

/// Emits each event as a structured `tracing` record.
#[derive(Default)]
pub struct TracingAudit;

impl AuditSink for TracingAudit {
    fn record(&self, event: AuditEvent) {
        tracing::info!(
            target = %event.action.target,
            decision = ?event.decision,
            resource = %event.action.resource.path,
            verb = ?event.action.verb,
            detail = %event.detail,
            "halter decision"
        );
    }
}

/// A durable, queryable audit sink: appends each event as one JSON line (JSONL) to a file,
/// flushed per record so a crash loses at most the in-flight event. The file is a stable
/// append-only log a SIEM or `jq` can tail and query, unlike the ephemeral `tracing`
/// stream. A write failure is logged (the request path must not fail because audit I/O
/// did) — operators should alarm on the `audit write failed` event.
pub struct FileAudit {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl FileAudit {
    /// Open (creating, else appending to) the JSONL audit log at `path`.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Read every recorded event back from the JSONL log (introspection / tests). Blank and
    /// unparseable lines are skipped.
    pub fn read(path: impl AsRef<Path>) -> std::io::Result<Vec<AuditEvent>> {
        let text = std::fs::read_to_string(path)?;
        Ok(text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }
}

impl AuditSink for FileAudit {
    fn record(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                tracing::error!(error = %e, "audit serialize failed");
                return;
            }
        };
        let mut file = self.file.lock();
        if let Err(e) = writeln!(file, "{line}").and_then(|()| file.flush()) {
            tracing::error!(error = %e, path = %self.path.display(), "audit write failed");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::action::{Action, CrudKind, Resource, Verb};
    use models::audit::Decision;

    fn event(at: u64, decision: Decision, detail: &str) -> AuditEvent {
        AuditEvent {
            at_ms: at,
            action: Action::of(
                "github",
                Verb::crud(CrudKind::Read),
                Resource::of("repos/o/r", "repo"),
            ),
            decision,
            detail: detail.to_string(),
        }
    }

    #[test]
    fn file_audit_appends_jsonl_and_reads_back() {
        let path = std::env::temp_dir().join(format!("halter-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let sink = FileAudit::open(&path).unwrap();
            sink.record(event(1, Decision::Allow, "allowed"));
            sink.record(event(2, Decision::Deny, "denied"));
        }
        // Reopening appends rather than truncating — the log is durable across restarts.
        {
            let sink = FileAudit::open(&path).unwrap();
            sink.record(event(3, Decision::Allow, "again"));
        }
        let events = FileAudit::read(&path).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].decision, Decision::Allow);
        assert_eq!(events[1].decision, Decision::Deny);
        assert_eq!(events[2].at_ms, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn in_memory_audit_collects_in_order() {
        let sink = InMemoryAudit::new();
        for (i, decision) in [Decision::Allow, Decision::Deny].into_iter().enumerate() {
            sink.record(AuditEvent {
                at_ms: i as u64,
                action: Action::of(
                    "github",
                    Verb::crud(CrudKind::Read),
                    Resource::of("repos/o/r", "repo"),
                ),
                decision,
                detail: String::new(),
            });
        }
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision, Decision::Allow);
        assert_eq!(events[1].decision, Decision::Deny);
    }
}
