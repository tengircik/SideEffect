use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn help_command_and_flag_show_command_list() {
    for arguments in [&["help"][..], &["--help"][..]] {
        let output = run(arguments);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("sideeffect help [command [subcommand]]"));
        assert!(text.contains("sideeffect model-preview"));
        assert!(text.contains(
            "sideeffect associated-behavior <startup-inventory.json> <runtime-evidence-file>"
        ));
        assert!(text.contains("sideeffect attribute --windows-runtime <capture.json>"));
        assert!(text.contains("--session <audit-session-directory>"));
    }
}

#[test]
fn focused_help_covers_command_and_nested_inventory_topics() {
    let record = run(&["record", "--help"]);
    assert!(record.status.success());
    let record_help = String::from_utf8_lossy(&record.stdout);
    #[cfg(target_os = "linux")]
    assert!(record_help.contains("current user's permissions"));
    #[cfg(windows)]
    assert!(record_help.contains("system-wide events"));
    assert!(record_help.contains("not isolation") || record_help.contains("not a safety check"));

    let inspect = run(&["inspect", "--help"]);
    assert!(inspect.status.success());
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("--session DIR"));

    let diff = run(&["help", "diff"]);
    assert!(diff.status.success());
    let diff_help = String::from_utf8_lossy(&diff.stdout);
    assert!(diff_help.contains("diff --windows-runtime"));
    assert!(diff_help.contains("Windows summary v2"));
    assert!(diff_help.contains("unique supported changed identities as candidates"));

    let associated = run(&["help", "associated-behavior"]);
    assert!(associated.status.success());
    let associated_help = String::from_utf8_lossy(&associated.stdout);
    assert!(
        associated_help.contains("Candidate matches do not prove startup execution or causation")
    );
    assert!(associated_help.contains("No match is insufficient evidence"));

    let startup = run(&["help", "inventory", "startup"]);
    assert!(startup.status.success());
    let startup_help = String::from_utf8_lossy(&startup.stdout);
    assert!(startup_help.contains("configured entry ran"));
    #[cfg(target_os = "linux")]
    assert!(startup_help.contains("supported Linux"));
    #[cfg(windows)]
    assert!(startup_help.contains("boot/logon triggers in tasks visible to the current token"));
    #[cfg(windows)]
    assert!(
        startup_help
            .contains("bounded Exec-action executable paths, arguments, and working directories")
    );
    #[cfg(windows)]
    assert!(startup_help.contains("unsupported action types remain labeled unsupported"));

    let packages = run(&["help", "inventory", "packages"]);
    assert!(packages.status.success());
    let packages_help = String::from_utf8_lossy(&packages.stdout);
    #[cfg(target_os = "linux")]
    assert!(packages_help.contains("dpkg, RPM"));
    #[cfg(windows)]
    assert!(packages_help.contains("Uninstall registry entries"));
}

#[test]
fn version_subcommand_matches_version_flag() {
    let command = run(&["version"]);
    let flag = run(&["--version"]);
    assert!(command.status.success());
    assert!(flag.status.success());
    assert_eq!(command.stdout, flag.stdout);
}
