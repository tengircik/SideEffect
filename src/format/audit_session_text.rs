use std::io::{self, Write};

use serde::Serialize;

use crate::audit_session::{
    AppliedLimit, AuditSessionManifest, SessionStatus, SourceRole, SourceStatus,
};

/// Render verified session metadata without copying inventory rows into terminal output.
///
/// The caller must provide a bounded writer. User-influenced scope text is quoted as ASCII.
pub fn write_audit_session_text<W: Write>(
    manifest: &AuditSessionManifest,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(b"SideEffect audit session review\n")?;
    writeln!(writer, "Session ID: {}", manifest.session_id)?;
    writeln!(
        writer,
        "Platform: {} ({})",
        manifest.platform,
        escape_ascii(&manifest.architecture)
    )?;
    writeln!(writer, "Status: {}", session_status_name(manifest.status))?;
    writeln!(
        writer,
        "Session interval (Unix milliseconds): {}..={}",
        manifest.started_at_unix_ms, manifest.ended_at_unix_ms
    )?;
    writer.write_all(b"Interval semantics: best_effort_non_atomic\n")?;
    writer.write_all(b"Intervals are best effort; no atomic system snapshot is claimed.\n")?;
    writer.write_all(b"Coverage: complete means selected collectors produced their declared artifacts; it does not establish exhaustive system coverage.\n")?;
    writer.write_all(b"Integrity: listed artifact lengths and SHA-256 values matched the local bytes; hashes do not authenticate the source.\n")?;
    writeln!(writer, "Sources: {}", manifest.sources.len())?;

    for (index, source) in manifest.sources.iter().enumerate() {
        writeln!(writer, "\nSource {}", index + 1)?;
        writeln!(writer, "  Role: {}", source_role_name(source.role))?;
        writeln!(writer, "  Status: {}", source_status_name(source.status))?;
        writeln!(writer, "  Platform: {}", source.platform)?;
        writer.write_all(b"  Scope: ")?;
        write_quoted_ascii(writer, &source.scope)?;
        writer.write_all(b"\n")?;
        writeln!(
            writer,
            "  Source interval (Unix milliseconds): {}..={}",
            source.started_at_unix_ms, source.ended_at_unix_ms
        )?;
        if source.applied_limits.is_empty() {
            writer.write_all(b"  Selected key limits: none recorded\n")?;
        } else {
            writer.write_all(b"  Selected key limits:\n")?;
            for limit in &source.applied_limits {
                writeln!(writer, "    {} = {}", limit.code, limit.value)?;
            }
        }
        if source.diagnostic_codes.is_empty() {
            writer.write_all(b"  Diagnostic codes: none recorded\n")?;
        } else {
            writer.write_all(b"  Diagnostic codes:\n")?;
            for code in &source.diagnostic_codes {
                writeln!(writer, "    {code}")?;
            }
        }
        if source.artifacts.is_empty() {
            writer.write_all(b"  Artifacts: none declared for this source\n")?;
        } else {
            writer.write_all(b"  Verified artifacts:\n")?;
            for artifact in &source.artifacts {
                writeln!(
                    writer,
                    "    {}: {} v{}; {} bytes; SHA-256 {}",
                    artifact.path,
                    artifact.schema,
                    artifact.schema_version,
                    artifact.byte_length,
                    artifact.sha256
                )?;
            }
        }
    }
    Ok(())
}

/// Serialize a bounded review document with user-influenced scope strings made ASCII-safe.
pub fn write_audit_session_json<W: Write>(
    manifest: &AuditSessionManifest,
    writer: &mut W,
) -> serde_json::Result<()> {
    let sources = manifest
        .sources
        .iter()
        .map(|source| SessionSourceReview {
            role: source_role_name(source.role),
            platform: &source.platform,
            status: source_status_name(source.status),
            scope: escape_ascii(&source.scope),
            scope_encoding: "non_ascii_and_controls_escaped_as_ascii",
            started_at_unix_ms: source.started_at_unix_ms,
            ended_at_unix_ms: source.ended_at_unix_ms,
            applied_limits: &source.applied_limits,
            diagnostic_codes: &source.diagnostic_codes,
            artifacts: source
                .artifacts
                .iter()
                .map(|artifact| SessionArtifactReview {
                    kind: artifact_kind_name(artifact.kind),
                    path: &artifact.path,
                    schema: &artifact.schema,
                    schema_version: artifact.schema_version,
                    byte_length: artifact.byte_length,
                    sha256: &artifact.sha256,
                    integrity: "length_and_sha256_match_local_bytes",
                })
                .collect(),
        })
        .collect();
    let review = SessionReview {
        schema: "sideeffect.audit_session_review",
        schema_version: 1,
        session_id: &manifest.session_id,
        platform: &manifest.platform,
        architecture: escape_ascii(&manifest.architecture),
        architecture_encoding: "non_ascii_and_controls_escaped_as_ascii",
        status: session_status_name(manifest.status),
        interval_semantics: "best_effort_non_atomic",
        started_at_unix_ms: manifest.started_at_unix_ms,
        ended_at_unix_ms: manifest.ended_at_unix_ms,
        coverage_note: "complete means selected collectors produced their declared artifacts; it does not establish exhaustive system coverage",
        authenticity: "not_established",
        sources,
    };
    serde_json::to_writer_pretty(writer, &review)
}

#[derive(Serialize)]
struct SessionReview<'a> {
    schema: &'static str,
    schema_version: u32,
    session_id: &'a str,
    platform: &'a str,
    architecture: String,
    architecture_encoding: &'static str,
    status: &'static str,
    interval_semantics: &'static str,
    started_at_unix_ms: u128,
    ended_at_unix_ms: u128,
    coverage_note: &'static str,
    authenticity: &'static str,
    sources: Vec<SessionSourceReview<'a>>,
}

#[derive(Serialize)]
struct SessionSourceReview<'a> {
    role: &'static str,
    platform: &'a str,
    status: &'static str,
    scope: String,
    scope_encoding: &'static str,
    started_at_unix_ms: u128,
    ended_at_unix_ms: u128,
    applied_limits: &'a [AppliedLimit],
    diagnostic_codes: &'a [String],
    artifacts: Vec<SessionArtifactReview<'a>>,
}

#[derive(Serialize)]
struct SessionArtifactReview<'a> {
    kind: &'static str,
    path: &'a str,
    schema: &'a str,
    schema_version: u32,
    byte_length: u64,
    sha256: &'a str,
    integrity: &'static str,
}

fn escape_ascii(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ' '..='~' => escaped.push(character),
            _ => {
                let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
            }
        }
    }
    escaped
}

fn write_quoted_ascii<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    writer.write_all(b"\"")?;
    for character in value.chars() {
        match character {
            '"' => writer.write_all(b"\\\"")?,
            '\\' => writer.write_all(b"\\\\")?,
            '\n' => writer.write_all(b"\\n")?,
            '\r' => writer.write_all(b"\\r")?,
            '\t' => writer.write_all(b"\\t")?,
            ' '..='~' => write!(writer, "{character}")?,
            _ => write!(writer, "\\u{{{:x}}}", character as u32)?,
        }
    }
    writer.write_all(b"\"")
}

fn session_status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Complete => "complete",
        SessionStatus::Partial => "partial",
    }
}

fn source_status_name(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Complete => "complete",
        SourceStatus::Partial => "partial",
        SourceStatus::Unknown => "unknown",
        SourceStatus::NotChecked => "not_checked",
        SourceStatus::Unsupported => "unsupported",
        SourceStatus::NotApplicable => "not_applicable",
        SourceStatus::Unavailable => "unavailable",
        SourceStatus::AccessDenied => "access_denied",
        SourceStatus::Failed => "failed",
        SourceStatus::TimedOut => "timed_out",
        SourceStatus::OutputLimitExceeded => "output_limit_exceeded",
    }
}

fn source_role_name(role: SourceRole) -> &'static str {
    match role {
        crate::audit_session::SourceRole::Packages => "packages",
        crate::audit_session::SourceRole::Processes => "processes",
        crate::audit_session::SourceRole::Permissions => "permissions",
        crate::audit_session::SourceRole::Startup => "startup",
        crate::audit_session::SourceRole::Runtime => "runtime",
    }
}

fn artifact_kind_name(kind: crate::audit_session::ArtifactKind) -> &'static str {
    match kind {
        crate::audit_session::ArtifactKind::Packages => "packages",
        crate::audit_session::ArtifactKind::Processes => "processes",
        crate::audit_session::ArtifactKind::Permissions => "permissions",
        crate::audit_session::ArtifactKind::Startup => "startup",
        crate::audit_session::ArtifactKind::RuntimeManifest => "runtime_manifest",
        crate::audit_session::ArtifactKind::RuntimeTrace => "runtime_trace",
    }
}

#[cfg(test)]
mod tests {
    use super::{write_audit_session_json, write_audit_session_text};
    use crate::audit_session::{
        AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AuditSessionManifest,
        AuditSessionSource, IntervalSemantics, SessionStatus, SourceRole, SourceStatus,
    };

    fn manifest(scope: &str, status: SourceStatus) -> AuditSessionManifest {
        AuditSessionManifest {
            schema: AUDIT_SESSION_SCHEMA.to_owned(),
            schema_version: AUDIT_SESSION_SCHEMA_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            interval_semantics: IntervalSemantics::BestEffortNonAtomic,
            status: if status == SourceStatus::Complete {
                SessionStatus::Complete
            } else {
                SessionStatus::Partial
            },
            sources: vec![AuditSessionSource {
                role: SourceRole::Packages,
                platform: "linux".to_owned(),
                scope: scope.to_owned(),
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
                status,
                applied_limits: Vec::new(),
                diagnostic_codes: Vec::new(),
                artifacts: Vec::new(),
            }],
        }
    }

    #[test]
    fn escapes_non_ascii_controls_and_bidi_scope_as_terminal_safe_ascii() {
        let mut fixture = manifest("safe\n\u{202e}path", SourceStatus::Partial);
        fixture.architecture = "x86\u{202e}_64".to_owned();
        let mut output = Vec::new();
        write_audit_session_text(&fixture, &mut output).unwrap();
        assert!(output.is_ascii());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Platform: linux (x86\\u{202e}_64)"));
        assert!(output.contains("Scope: \"safe\\n\\u{202e}path\""));
        assert!(output.contains("Status: partial"));
        assert!(output.contains("Artifacts: none declared for this source"));
        assert!(output.contains("hashes do not authenticate the source"));
    }

    #[test]
    fn json_review_uses_an_ascii_escaped_scope_and_disclaims_authenticity() {
        let mut fixture = manifest("safe\n\u{202e}path", SourceStatus::Partial);
        fixture.architecture = "x86\u{202e}_64".to_owned();
        let mut output = Vec::new();
        write_audit_session_json(&fixture, &mut output).unwrap();
        assert!(output.is_ascii());
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["schema"], "sideeffect.audit_session_review");
        assert_eq!(value["authenticity"], "not_established");
        assert_eq!(value["architecture"], "x86\\u{202e}_64");
        assert_eq!(
            value["architecture_encoding"],
            "non_ascii_and_controls_escaped_as_ascii"
        );
        assert_eq!(value["sources"][0]["scope"], "safe\\n\\u{202e}path");
        assert_eq!(value["sources"][0]["status"], "partial");
    }
}
