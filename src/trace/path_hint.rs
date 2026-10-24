use crate::limits::MAX_RECORD_BYTES;
use serde::Serialize;

/// The limited syntactic source used to form a lexical path hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LexicalPathBasis {
    AbsoluteArgument,
    AtFdcwdAnnotation,
    DirectoryFdAnnotation,
}

/// A path string derived from syscall argument spelling, without filesystem resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LexicalPathHint {
    pub path: String,
    pub basis: LexicalPathBasis,
}

/// Derive a narrowly scoped lexical path hint from `openat` or `openat2` arguments.
///
/// This does not resolve `.` or `..`, inspect filesystem state, follow symlinks,
/// or establish a descriptor's identity. Quoted strings and `-yy` bases that
/// require decoding are rejected rather than guessed.
pub fn derive_lexical_path_hint(syscall: &str, raw_arguments: &str) -> Option<LexicalPathHint> {
    let (minimum_arguments, maximum_arguments) = match syscall {
        "openat" => (3, 4),
        "openat2" => (4, 4),
        _ => return None,
    };
    if raw_arguments.len() > MAX_RECORD_BYTES {
        return None;
    }
    let arguments = split_top_level_arguments(raw_arguments, maximum_arguments)?;
    if arguments.len() < minimum_arguments {
        return None;
    }

    let path = decode_plain_quoted_path(arguments[1].trim())?;
    if path.is_empty() {
        return None;
    }
    if path.starts_with('/') {
        return Some(LexicalPathHint {
            path: path.to_owned(),
            basis: LexicalPathBasis::AbsoluteArgument,
        });
    }

    let (base, basis) = parse_directory_base(arguments[0].trim())?;
    let mut joined = String::with_capacity(base.len().saturating_add(path.len()).saturating_add(1));
    joined.push_str(base);
    if !joined.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(path);
    Some(LexicalPathHint {
        path: joined,
        basis,
    })
}

fn split_top_level_arguments(raw: &str, expected_arguments: usize) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut stack = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;

    for (index, character) in raw.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }

        match character {
            '"' => quoted = true,
            '(' | '[' | '{' => stack.push(character),
            ')' | ']' | '}' => {
                let expected_open = match character {
                    ')' => '(',
                    ']' => '[',
                    '}' => '{',
                    _ => unreachable!(),
                };
                if stack.pop() != Some(expected_open) {
                    return None;
                }
            }
            ',' if stack.is_empty() => {
                if parts.len() + 1 >= expected_arguments {
                    return None;
                }
                parts.push(raw.get(start..index)?);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }

    if quoted || escaped || !stack.is_empty() {
        return None;
    }
    parts.push(raw.get(start..)?);
    if parts.iter().any(|part| part.trim().is_empty()) {
        return None;
    }
    Some(parts)
}

fn decode_plain_quoted_path(argument: &str) -> Option<&str> {
    let inner = argument.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"')
        || inner.contains('\\')
        || inner.contains("...")
        || !inner.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return None;
    }
    Some(inner)
}

fn parse_directory_base(argument: &str) -> Option<(&str, LexicalPathBasis)> {
    let (descriptor, annotated_path) = argument.split_once('<')?;
    let base = annotated_path.strip_suffix('>')?;
    if !base.starts_with('/')
        || base.contains(['<', '>'])
        || base.contains('\\')
        || base.contains('"')
        || base.contains("...")
        || base.ends_with(" (deleted)")
        || !base.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return None;
    }

    let basis = if descriptor == "AT_FDCWD" {
        LexicalPathBasis::AtFdcwdAnnotation
    } else if !descriptor.is_empty() && descriptor.bytes().all(|byte| byte.is_ascii_digit()) {
        LexicalPathBasis::DirectoryFdAnnotation
    } else {
        return None;
    };
    Some((base, basis))
}

#[cfg(test)]
mod tests {
    use super::{LexicalPathBasis as Basis, derive_lexical_path_hint};

    #[test]
    fn absolute_paths_are_emitted_as_spelled_for_openat_and_openat2() {
        let expected = ("/var/tmp/../config.ini", Basis::AbsoluteArgument);
        for (syscall, args) in [
            ("openat", "AT_FDCWD, \"/var/tmp/../config.ini\", O_RDONLY"),
            (
                "openat2",
                "7</work>, \"/var/tmp/../config.ini\", {flags=O_RDONLY}, 24",
            ),
        ] {
            let hint = derive_lexical_path_hint(syscall, args).unwrap();
            assert_eq!((hint.path.as_str(), hint.basis), expected);
        }
    }

    #[test]
    fn openat_with_creation_mode_still_uses_its_path_operand() {
        let hint = derive_lexical_path_hint(
            "openat",
            "AT_FDCWD</tmp>, \"created.bin\", O_WRONLY|O_CREAT, 0600",
        )
        .unwrap();
        assert_eq!(hint.path, "/tmp/created.bin");
        assert_eq!(hint.basis, Basis::AtFdcwdAnnotation);
    }

    #[test]
    fn relative_path_joins_only_supported_absolute_fd_annotations() {
        let at_cwd = derive_lexical_path_hint(
            "openat",
            "AT_FDCWD</home/alice/project>, \"assets/../icon.svg\", O_RDONLY",
        )
        .unwrap();
        assert_eq!(at_cwd.path, "/home/alice/project/assets/../icon.svg");
        assert_eq!(at_cwd.basis, Basis::AtFdcwdAnnotation);

        let directory_fd = derive_lexical_path_hint(
            "openat2",
            "12</srv/work>, \"./result.bin\", {flags=O_CREAT|O_WRONLY}, 24",
        )
        .unwrap();
        assert_eq!(directory_fd.path, "/srv/work/./result.bin");
        assert_eq!(directory_fd.basis, Basis::DirectoryFdAnnotation);
    }

    #[test]
    fn preserves_dot_segments_without_lexical_normalization() {
        let hint = derive_lexical_path_hint(
            "openat",
            "AT_FDCWD</home/alice>, \"one/../two/./file\", O_RDONLY",
        )
        .unwrap();
        assert_eq!(hint.path, "/home/alice/one/../two/./file");
    }

    #[test]
    fn rejects_unknown_bases_escaped_or_truncated_paths_and_deleted_bases() {
        for args in [
            "AT_FDCWD, \"relative\", O_RDONLY",
            "9<relative/base>, \"file\", O_RDONLY",
            "9</home/user (deleted)>, \"file\", O_RDONLY",
            "9</home/user...>, \"file\", O_RDONLY",
            "AT_FDCWD</home/user>, \"file\\nname\", O_RDONLY",
            "AT_FDCWD</home/user>, \"long...\", O_RDONLY",
            "AT_FDCWD</home/user>, \"\", O_RDONLY",
            "AT_FDCWD</home/user>, \"café\", O_RDONLY",
            "AT_FDCWD</home/café>, \"file\", O_RDONLY",
            "AT_FDCWD</home/user>, \"unterminated, O_RDONLY",
        ] {
            assert_eq!(derive_lexical_path_hint("openat", args), None, "{args}");
        }
    }

    #[test]
    fn rejects_malformed_delimiters_arity_and_unsupported_syscalls() {
        for args in [
            "AT_FDCWD, \"file\", {flags=O_RDONLY]",
            "AT_FDCWD, \"file\", O_RDONLY, extra",
            "AT_FDCWD, \"file\" O_RDONLY",
            "AT_FDCWD, \"file\",",
            "AT_FDCWD, \"file\", {flags=O_RDONLY",
        ] {
            assert_eq!(derive_lexical_path_hint("openat", args), None, "{args}");
        }
        assert_eq!(
            derive_lexical_path_hint("open", "\"/tmp/file\", O_RDONLY"),
            None
        );
        assert_eq!(
            derive_lexical_path_hint("openat2", "AT_FDCWD, \"file\", {flags=O_RDONLY}"),
            None
        );
    }

    #[test]
    fn rejects_excess_top_level_arguments_without_collecting_all_parts() {
        let args = format!("AT_FDCWD, \"file\", {}", "extra,".repeat(10_000));
        assert_eq!(derive_lexical_path_hint("openat", &args), None);
    }

    #[test]
    fn basis_serializes_with_stable_snake_case_name() {
        let hint =
            derive_lexical_path_hint("openat", "AT_FDCWD</home/alice>, \"file.txt\", O_RDONLY")
                .unwrap();
        assert_eq!(
            serde_json::to_string(&hint).unwrap(),
            r#"{"path":"/home/alice/file.txt","basis":"at_fdcwd_annotation"}"#
        );
    }
}
