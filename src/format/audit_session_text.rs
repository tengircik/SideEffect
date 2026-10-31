use std::io::{self, Write};

use serde::Serialize;

use crate::audit_session::{
    AppliedLimit, AuditSessionManifest, CoverageStatus, HostContext, SessionStatus, SourceRole,
    SourceStatus,
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
    write_host_context(writer, manifest.host_context.as_ref())?;
    writeln!(
        writer,
        "Session interval (Unix milliseconds): {}..={}",
        manifest.started_at_unix_ms, manifest.ended_at_unix_ms
    )?;
    writer.write_all(b"Interval semantics: best_effort_non_atomic\n")?;
    writer.write_all(b"Intervals are best effort; no atomic system snapshot is claimed.\n")?;
    writer.write_all(
        b"Coverage note: selected collector results do not establish exhaustive system coverage.\n",
    )?;
    writer.write_all(b"Integrity: listed artifact lengths and SHA-256 values matched the local bytes; hashes do not authenticate the source.\n")?;
    writeln!(writer, "Sources: {}", manifest.sources.len())?;

    for (index, source) in manifest.sources.iter().enumerate() {
        writeln!(writer, "\nSource {}", index + 1)?;
        writeln!(writer, "  Role: {}", source_role_name(source.role))?;
        writeln!(writer, "  Status: {}", source_status_name(source.status))?;
        writeln!(
            writer,
            "  Coverage: {}",
            coverage_status_name(
                manifest
                    .coverage_manifest
                    .as_ref()
                    .and_then(|coverage| coverage
                        .sources
                        .iter()
                        .find(|entry| entry.role == source.role)
                        .map(|entry| entry.status))
                    .unwrap_or(CoverageStatus::Unknown)
            )
        )?;
        writeln!(writer, "  Platform: {}", source.platform)?;
        if let Some(collector) = &source.collector {
            writeln!(
                writer,
                "  Collector: {} v{}",
                escape_ascii(&collector.id),
                escape_ascii(&collector.version)
            )?;
            writeln!(
                writer,
                "  Provider: {}",
                collector.provider_id.as_deref().unwrap_or("not applicable")
            )?;
        } else {
            writer.write_all(b"  Collector identity: not recorded (legacy session)\n")?;
        }
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
        write_settings(writer, "Requested settings", &source.requested_settings)?;
        write_settings(
            writer,
            "Source-reported effective settings",
            &source.effective_settings,
        )?;
        if let Some(loss) = &source.loss {
            writeln!(
                writer,
                "  Runtime loss status: {}",
                loss_status_name(loss.status)
            )?;
            writeln!(
                writer,
                "  Loss statistics available: {}",
                loss.statistics_available
            )?;
            writeln!(
                writer,
                "  Final loss snapshot available: {}",
                loss.final_snapshot_available
            )?;
            writeln!(
                writer,
                "  Events lost: {}",
                optional_count(loss.events_lost)
            )?;
            writeln!(
                writer,
                "  Log buffers lost: {}",
                optional_count(loss.log_buffers_lost)
            )?;
            writeln!(
                writer,
                "  Real-time buffers lost: {}",
                optional_count(loss.real_time_buffers_lost)
            )?;
        } else {
            writer.write_all(b"  Runtime loss metadata: not applicable to this source\n")?;
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
            writer
                .write_all(b"  Artifact provenance (verified local bytes; not authenticated):\n")?;
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

fn write_host_context<W: Write>(writer: &mut W, context: Option<&HostContext>) -> io::Result<()> {
    let Some(context) = context else {
        return writer
            .write_all(b"Host OS/version and privilege context: not recorded (legacy session)\n");
    };
    writer.write_all(b"Host context:\n")?;
    for (label, fact) in [
        ("OS", &context.os_name),
        ("OS version", &context.os_version),
    ] {
        write!(writer, "  {label}: ")?;
        match (&fact.status, fact.value.as_deref()) {
            (crate::audit_session::ContextFactStatus::Observed, Some(value)) => {
                write_quoted_ascii(writer, value)?
            }
            (crate::audit_session::ContextFactStatus::Unknown, _) => {
                writer.write_all(b"unknown")?
            }
            (crate::audit_session::ContextFactStatus::NotChecked, _) => {
                writer.write_all(b"not_checked")?
            }
            _ => writer.write_all(b"unknown")?,
        }
        writer.write_all(b"\n")?;
    }
    let privilege = match context.privilege {
        crate::audit_session::PrivilegeContext::Elevated => "elevated",
        crate::audit_session::PrivilegeContext::NotElevated => "not_elevated",
        crate::audit_session::PrivilegeContext::Unknown => "unknown",
        crate::audit_session::PrivilegeContext::NotChecked => "not_checked",
    };
    writeln!(writer, "  Process privilege context: {privilege}")
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
            collector: &source.collector,
            coverage_status: coverage_status_name(
                manifest
                    .coverage_manifest
                    .as_ref()
                    .and_then(|coverage| {
                        coverage
                            .sources
                            .iter()
                            .find(|entry| entry.role == source.role)
                            .map(|entry| entry.status)
                    })
                    .unwrap_or(CoverageStatus::Unknown),
            ),
            scope: escape_ascii(&source.scope),
            scope_encoding: "non_ascii_and_controls_escaped_as_ascii",
            started_at_unix_ms: source.started_at_unix_ms,
            ended_at_unix_ms: source.ended_at_unix_ms,
            applied_limits: &source.applied_limits,
            requested_settings: &source.requested_settings,
            effective_settings: &source.effective_settings,
            loss: &source.loss,
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
                    provenance: "manifest_reference_verified_against_local_bytes",
                    integrity: "length_and_sha256_match_local_bytes",
                })
                .collect(),
        })
        .collect();
    let review = SessionReview {
        schema: "sideeffect.audit_session_review",
        schema_version: 6,
        session_id: &manifest.session_id,
        platform: &manifest.platform,
        architecture: escape_ascii(&manifest.architecture),
        architecture_encoding: "non_ascii_and_controls_escaped_as_ascii",
        host_context: &manifest.host_context,
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
    host_context: &'a Option<HostContext>,
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
    collector: &'a Option<crate::audit_session::CollectorIdentity>,
    coverage_status: &'static str,
    scope: String,
    scope_encoding: &'static str,
    started_at_unix_ms: u128,
    ended_at_unix_ms: u128,
    applied_limits: &'a [AppliedLimit],
    requested_settings: &'a [crate::audit_session::Setting],
    effective_settings: &'a [crate::audit_session::Setting],
    loss: &'a Option<crate::audit_session::LossMetadata>,
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
    provenance: &'static str,
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

fn write_settings<W: Write>(
    writer: &mut W,
    label: &str,
    settings: &[crate::audit_session::Setting],
) -> io::Result<()> {
    if settings.is_empty() {
        writeln!(writer, "  {label}: none reported")
    } else {
        writeln!(writer, "  {label}:")?;
        for setting in settings {
            writeln!(writer, "    {} = {}", setting.code, setting.value)?;
        }
        Ok(())
    }
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |count| count.to_string())
}

fn loss_status_name(status: crate::audit_session::LossStatus) -> &'static str {
    match status {
        crate::audit_session::LossStatus::Reported => "reported",
        crate::audit_session::LossStatus::NoneReported => "none_reported",
        crate::audit_session::LossStatus::Unknown => "unknown",
    }
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

fn coverage_status_name(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Observed => "observed",
        CoverageStatus::Configured => "configured",
        CoverageStatus::NotObserved => "not_observed",
        CoverageStatus::NotChecked => "not_checked",
        CoverageStatus::Unsupported => "unsupported",
        CoverageStatus::Inaccessible => "inaccessible",
        CoverageStatus::Partial => "partial",
        CoverageStatus::Unknown => "unknown",
    }
}

fn source_role_name(role: SourceRole) -> &'static str {
    match role {
        crate::audit_session::SourceRole::Packages => "packages",
        crate::audit_session::SourceRole::Processes => "processes",
        crate::audit_session::SourceRole::Permissions => "permissions",
        crate::audit_session::SourceRole::Startup => "startup",
        crate::audit_session::SourceRole::PathExecutables => "path_executables",
        crate::audit_session::SourceRole::Runtime => "runtime",
    }
}

fn artifact_kind_name(kind: crate::audit_session::ArtifactKind) -> &'static str {
    match kind {
        crate::audit_session::ArtifactKind::Packages => "packages",
        crate::audit_session::ArtifactKind::Processes => "processes",
        crate::audit_session::ArtifactKind::Permissions => "permissions",
        crate::audit_session::ArtifactKind::Startup => "startup",
        crate::audit_session::ArtifactKind::PathExecutables => "path_executables",
        crate::audit_session::ArtifactKind::WindowsSoftware => "windows_software",
        crate::audit_session::ArtifactKind::WindowsProcesses => "windows_processes",
        crate::audit_session::ArtifactKind::WindowsPermissions => "windows_permissions",
        crate::audit_session::ArtifactKind::WindowsStartup => "windows_startup",
        crate::audit_session::ArtifactKind::RuntimeManifest => "runtime_manifest",
        crate::audit_session::ArtifactKind::RuntimeTrace => "runtime_trace",
        crate::audit_session::ArtifactKind::WindowsRuntimeCapture => "windows_runtime_capture",
    }
}

#[cfg(test)]
mod tests {
    use super::{write_audit_session_json, write_audit_session_text};
    use crate::audit_session::{
        AUDIT_SESSION_SCHEMA, AUDIT_SESSION_SCHEMA_VERSION, AuditSessionManifest,
        AuditSessionSource, COVERAGE_MANIFEST_VERSION, CoverageManifest, CoverageStatus,
        IntervalSemantics, SessionStatus, SourceCoverage, SourceRole, SourceStatus,
    };

    fn manifest(scope: &str, status: SourceStatus) -> AuditSessionManifest {
        AuditSessionManifest {
            schema: AUDIT_SESSION_SCHEMA.to_owned(),
            schema_version: AUDIT_SESSION_SCHEMA_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            host_context: Some(crate::audit_session::HostContext {
                os_name: crate::audit_session::ContextFact {
                    status: crate::audit_session::ContextFactStatus::Observed,
                    value: Some("Linux".to_owned()),
                },
                os_version: crate::audit_session::ContextFact {
                    status: crate::audit_session::ContextFactStatus::Observed,
                    value: Some("6.1".to_owned()),
                },
                privilege: crate::audit_session::PrivilegeContext::NotElevated,
            }),
            started_at_unix_ms: 1,
            ended_at_unix_ms: 2,
            interval_semantics: IntervalSemantics::BestEffortNonAtomic,
            status: if status == SourceStatus::Complete {
                SessionStatus::Complete
            } else {
                SessionStatus::Partial
            },
            coverage_manifest: Some(CoverageManifest {
                version: COVERAGE_MANIFEST_VERSION,
                sources: vec![SourceCoverage {
                    role: SourceRole::Packages,
                    status: if status == SourceStatus::Complete {
                        CoverageStatus::Observed
                    } else {
                        CoverageStatus::Partial
                    },
                }],
            }),
            sources: vec![AuditSessionSource {
                role: SourceRole::Packages,
                collector: Some(crate::audit_session::collector_identity(
                    "linux",
                    SourceRole::Packages,
                )),
                platform: "linux".to_owned(),
                scope: scope.to_owned(),
                started_at_unix_ms: 1,
                ended_at_unix_ms: 2,
                status,
                applied_limits: Vec::new(),
                requested_settings: Vec::new(),
                effective_settings: Vec::new(),
                loss: None,
                diagnostic_codes: Vec::new(),
                artifacts: Vec::new(),
            }],
        }
    }

    #[test]
    fn escapes_non_ascii_controls_and_bidi_scope_as_terminal_safe_ascii() {
        let mut fixture = manifest("safe\n\u{202e}path", SourceStatus::Partial);
        fixture.architecture = "x86\u{202e}_64".to_owned();
        fixture.sources[0].collector.as_mut().unwrap().version = "1.0\u{202e}txt.exe".to_owned();
        let mut output = Vec::new();
        write_audit_session_text(&fixture, &mut output).unwrap();
        assert!(output.is_ascii());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Platform: linux (x86\\u{202e}_64)"));
        assert!(output.contains("v1.0\\u{202e}txt.exe"));
        assert!(output.contains("Scope: \"safe\\n\\u{202e}path\""));
        assert!(output.contains("Status: partial"));
        assert!(output.contains("Session interval (Unix milliseconds): 1..=2"));
        assert!(output.contains("Interval semantics: best_effort_non_atomic"));
        assert!(output.contains("Source interval (Unix milliseconds): 1..=2"));
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
        assert_eq!(value["schema_version"], 6);
        assert_eq!(value["authenticity"], "not_established");
        assert_eq!(value["architecture"], "x86\\u{202e}_64");
        assert_eq!(
            value["architecture_encoding"],
            "non_ascii_and_controls_escaped_as_ascii"
        );
        assert_eq!(value["host_context"]["os_name"]["value"], "Linux");
        assert_eq!(value["sources"][0]["scope"], "safe\\n\\u{202e}path");
        assert_eq!(value["sources"][0]["status"], "partial");
        assert_eq!(value["sources"][0]["coverage_status"], "partial");
    }

    #[test]
    fn text_review_renders_unknown_and_not_checked_host_facts_explicitly() {
        let mut fixture = manifest("bounded context fixture", SourceStatus::Complete);
        fixture.host_context.as_mut().unwrap().os_name = crate::audit_session::ContextFact {
            status: crate::audit_session::ContextFactStatus::Unknown,
            value: None,
        };
        fixture.host_context.as_mut().unwrap().os_version = crate::audit_session::ContextFact {
            status: crate::audit_session::ContextFactStatus::NotChecked,
            value: None,
        };
        let mut output = Vec::new();
        write_audit_session_text(&fixture, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("OS: unknown"));
        assert!(output.contains("OS version: not_checked"));
    }

    #[test]
    fn v1_review_keeps_missing_coverage_unknown() {
        let mut fixture = manifest("legacy v1", SourceStatus::Complete);
        fixture.schema_version = crate::audit_session::AUDIT_SESSION_V1_SCHEMA_VERSION;
        fixture.coverage_manifest = None;
        fixture.host_context = None;
        let mut output = Vec::new();
        write_audit_session_json(&fixture, &mut output).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["sources"][0]["coverage_status"], "unknown");
    }
}
